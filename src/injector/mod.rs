mod dex;
mod dlopen;
mod linker;
mod memfd;

use crate::hider::{HideTarget, Hider};
use crate::ptrace_ex::{find_remote_lib_base, remote_close, remote_dlsym};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Result, bail};
use log::{debug, info, warn};
use std::path::Path;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// 注入结果
#[derive(Debug)]
pub struct InjectedInfo {
    pub dl_handle: usize,
    pub base_addr: usize,
    pub hider_results: Vec<(String, bool)>,
    pub jni_onload: Option<usize>,
    /// 自带 linker 装载的 so 没有系统 dlopen 句柄，不能拿基址去 `dlsym`。
    pub custom_link: bool,
}

impl InjectedInfo {
    pub fn is_valid(&self) -> bool {
        self.dl_handle != 0 && self.base_addr != 0
    }
}

/// 加载结果（dlopen 返回的信息）
pub struct LoadResult {
    pub handle: usize,
    pub base_addr: usize,
    pub maps_search_name: String,
    pub memfd_fd: Option<i32>,
    /// 自带 linker 已经从动态符号表里找到的 `JNI_OnLoad`。系统 dlopen 的结果是 `None`。
    pub jni_onload: Option<usize>,
    pub prot_hide: bool,
}

/// 注入器 trait：不同的加载方式（dlopen / memfd）
pub trait Injector {
    fn load(&self, proc: &RemoteProcess, lib_path: &str) -> Result<LoadResult>;
}

#[derive(Clone, Debug)]
pub enum InjectKind {
    So { use_memfd: bool },
    Linker,
    Dex { entry: String },
}

/// 注入 payload 到目标进程
pub fn inject(
    pid: i32,
    lib_path: &str,
    kind: InjectKind,
    hiders: &[Box<dyn Hider>],
    jni_key: Option<usize>,
) -> Result<InjectedInfo> {
    info!("Injecting {} into pid {}", lib_path, pid);

    if !Path::new(lib_path).exists() {
        bail!("Payload not found: {lib_path}");
    }

    match kind {
        InjectKind::Dex { .. } => {
            if !dex::is_dex_payload(lib_path) {
                bail!("dex subcommand requires a .dex file: {lib_path}");
            }
            if !hiders.is_empty() {
                warn!("hiders apply to injected SOs only and will be skipped for DEX");
            }
        }
        InjectKind::So { .. } | InjectKind::Linker => {
            if dex::is_dex_payload(lib_path) {
                bail!("DEX payload requires the dex subcommand");
            }
        }
    }

    let stop_result = kill(Pid::from_raw(pid), Signal::SIGSTOP);
    let stopped = stop_result.is_ok();
    if stopped {
        debug!("Stopped target process");
    } else {
        warn!("Failed to stop target process, continuing anyway");
    }

    let mut proc = RemoteProcess::attach(pid)?;
    info!("Attached to pid {}", pid);

    let caller = find_remote_lib_base(pid, "libRS.so")?
        .unwrap_or(0);
    if caller != 0 {
        debug!("default_caller set to {:#x}", caller);
        proc.set_default_caller(caller);
    } else {
        warn!("Could not find a suitable default_caller, remote calls may fail");
    }

    let result = match kind {
        InjectKind::Dex { ref entry } => dex::inject_dex(&proc, lib_path, entry),
        InjectKind::Linker => {
            let info = do_linker_inject(&proc, lib_path, hiders);
            if let Ok(ref injected) = info {
                if injected.is_valid() {
                    call_jni_onload(&proc, injected, jni_key);
                }
            }
            info
        }
        InjectKind::So { use_memfd } => {
            let info = do_inject(&proc, pid, lib_path, use_memfd, hiders);
            if let Ok(ref injected) = info {
                if injected.is_valid() {
                    call_jni_onload(&proc, injected, jni_key);
                }
            }
            info
        }
    };

    proc.detach()?;
    info!("Detached from pid {}", pid);

    if stopped {
        let _ = kill(Pid::from_raw(pid), Signal::SIGCONT);
        debug!("Resumed target process");
    }

    result
}

fn call_jni_onload(proc: &RemoteProcess, injected: &InjectedInfo, jni_key: Option<usize>) {
    let ep = if let Some(ep) = injected.jni_onload {
        ep
    } else if injected.custom_link {
        debug!("No JNI_OnLoad symbol found, skipping");
        return;
    } else {
        match remote_dlsym(proc, injected.dl_handle, "JNI_OnLoad") {
            Ok(ep) if ep != 0 => ep,
            _ => {
                debug!("No JNI_OnLoad symbol found, skipping");
                return;
            }
        }
    };
    let key = jni_key.unwrap_or(0);
    info!("Calling JNI_OnLoad at {ep:#x} (key={key:#x})");
    if let Err(e) = proc.call_function(ep, &[0, key]) {
        warn!("JNI_OnLoad call failed: {e:#}");
    }
}

fn do_inject(
    proc: &RemoteProcess,
    pid: i32,
    lib_path: &str,
    use_memfd: bool,
    hiders: &[Box<dyn Hider>],
) -> Result<InjectedInfo> {
    let injector: Box<dyn Injector> = if use_memfd {
        info!("Using memfd injection");
        Box::new(memfd::MemfdInjector)
    } else {
        info!("Using dlopen injection");
        Box::new(dlopen::DlopenInjector)
    };

    let load = injector.load(proc, lib_path)?;
    info!("dlopen returned handle: {:#x}", load.handle);

    if load.base_addr != 0 {
        info!("Library loaded at base: {:#x}", load.base_addr);
    } else {
        warn!("Could not find library base address in maps");
    }

    let mut hider_results = Vec::new();
    if load.base_addr != 0 {
        let target = HideTarget::new(proc, pid, load.base_addr, &load.maps_search_name)?;
        for hider in hiders {
            let name = hider.name().to_string();
            match hider.apply(&target) {
                Ok(true) => {
                    info!("{name}: succeeded");
                    hider_results.push((name, true));
                }
                Ok(false) => {
                    warn!("{name}: failed");
                    hider_results.push((name, false));
                }
                Err(e) => {
                    warn!("{name} error: {e:#}");
                    hider_results.push((name, false));
                }
            }
        }
    }

    if let Some(fd) = load.memfd_fd {
        if let Err(e) = remote_close(proc, fd) {
            warn!("Failed to close memfd fd: {e:#}");
        }
    }

    Ok(InjectedInfo {
        dl_handle: load.handle,
        base_addr: load.base_addr,
        hider_results,
        jni_onload: load.jni_onload,
        custom_link: false,
    })
}

fn do_linker_inject(proc: &RemoteProcess, lib_path: &str, hiders: &[Box<dyn Hider>]) -> Result<InjectedInfo> {
    if !hiders.is_empty() {
        warn!("linker load is absent from the system soinfo; maps/solist hiders are skipped");
    }
    info!("Using custom linker");
    let load = linker::LinkerInjector.load(proc, lib_path)?;
    info!("custom linker base {:#x}", load.base_addr);
    Ok(InjectedInfo {
        dl_handle: load.handle,
        base_addr: load.base_addr,
        hider_results: vec![("prot_hide".to_string(), load.prot_hide)],
        jni_onload: load.jni_onload,
        custom_link: true,
    })
}
