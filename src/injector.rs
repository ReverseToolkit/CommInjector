use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
use proc_maps::get_process_maps;
use std::process;

use crate::ptrace_ext::RemoteProcess;

/// 注入结果
#[derive(Debug)]
pub struct InjectedInfo {
    pub dl_handle: usize,
    pub base_addr: usize,
}

impl InjectedInfo {
    pub fn is_valid(&self) -> bool {
        self.dl_handle != 0 && self.base_addr != 0
    }
}

/// 在远程进程中查找某个 so 的基址
fn find_remote_lib_base(pid: i32, lib_name: &str) -> Result<Option<usize>> {
    let maps = get_process_maps(pid).context("Failed to read remote maps")?;
    for map in &maps {
        if let Some(path) = map.filename() {
            let path_str = path.to_string_lossy();
            if path_str.contains(lib_name) {
                return Ok(Some(map.start()));
            }
        }
    }
    Ok(None)
}

/// 在本地进程中查找某个 so 的基址
fn find_local_lib_base(lib_name: &str) -> Result<Option<usize>> {
    let pid = process::id() as i32;
    find_remote_lib_base(pid, lib_name)
}

/// 计算远程进程中某个函数的地址
/// 原理：local_func_addr - local_lib_base + remote_lib_base
fn find_remote_symbol(pid: i32, lib_name: &str, local_func_addr: usize) -> Result<usize> {
    let local_base = find_local_lib_base(lib_name)?.context(format!("Local lib {lib_name} not found"))?;
    let remote_base =
        find_remote_lib_base(pid, lib_name)?.context(format!("Remote lib {lib_name} not found in pid {pid}"))?;

    let offset = local_func_addr - local_base;
    Ok(remote_base + offset)
}

/// 在远程进程中分配内存（通过远程调用 mmap）
fn remote_mmap(proc: &RemoteProcess, size: usize) -> Result<usize> {
    let local_mmap = libc::mmap as usize;
    let remote_mmap = find_remote_symbol(proc.pid.as_raw(), "libc.so", local_mmap)?;

    debug!("remote mmap: {:#x}", remote_mmap);

    let addr = proc.call_remote_fn(
        remote_mmap,
        &[
            0,                                                  // addr = NULL
            size,                                               // length
            (libc::PROT_READ | libc::PROT_WRITE) as usize,      // prot
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize, // flags
            0, // fd = 0 (with MAP_ANONYMOUS, some kernels want -1 but 0 works on Android)
            0, // offset
        ],
    )?;

    if addr == usize::MAX || addr == 0 {
        bail!("Remote mmap failed, returned {:#x}", addr);
    }

    debug!("remote mmap allocated {size} bytes at {:#x}", addr);
    Ok(addr)
}

/// 在远程进程中释放内存
fn remote_munmap(proc: &RemoteProcess, addr: usize, size: usize) -> Result<()> {
    let local_munmap = libc::munmap as usize;
    let remote_munmap = find_remote_symbol(proc.pid.as_raw(), "libc.so", local_munmap)?;

    proc.call_remote_fn(remote_munmap, &[addr, size])?;
    Ok(())
}

/// 在远程进程中调用 dlopen
fn remote_dlopen(proc: &RemoteProcess, lib_path: &str, flags: i32) -> Result<usize> {
    let local_dlopen = libc::dlopen as usize;
    let remote_dlopen = find_remote_symbol(proc.pid.as_raw(), "libdl.so", local_dlopen)?;

    debug!("remote dlopen: {:#x}", remote_dlopen);

    // 在远程进程中写入 lib 路径字符串
    let path_bytes = lib_path.as_bytes();
    let path_len = path_bytes.len() + 1; // +1 for null terminator
    let remote_path = remote_mmap(proc, path_len)?;

    let mut buf = path_bytes.to_vec();
    buf.push(0); // null terminator
    proc.write_mem(remote_path, &buf)?;

    // 调用 dlopen
    let handle = proc.call_remote_fn(remote_dlopen, &[remote_path, flags as usize])?;

    // 清理路径内存
    let _ = remote_munmap(proc, remote_path, path_len);

    if handle == 0 {
        // 尝试获取 dlerror
        let local_dlerror = libc::dlerror as usize;
        if let Ok(remote_dlerror) = find_remote_symbol(proc.pid.as_raw(), "libdl.so", local_dlerror) {
            if let Ok(err_ptr) = proc.call_remote_fn(remote_dlerror, &[]) {
                if err_ptr != 0 {
                    if let Ok(err_str) = proc.read_cstring(err_ptr, 256) {
                        bail!("dlopen failed: {err_str}");
                    }
                }
            }
        }
        bail!("dlopen returned NULL");
    }

    Ok(handle)
}

/// 注入 so 到目标进程
///
/// 流程：
/// 1. SIGSTOP 暂停目标进程
/// 2. ptrace attach
/// 3. 远程调用 dlopen 加载 so
/// 4. SIGCONT 恢复目标进程
/// 5. ptrace detach
pub fn inject(pid: i32, lib_path: &str) -> Result<InjectedInfo> {
    info!("Injecting {} into pid {}", lib_path, pid);

    // 验证 so 文件存在
    if !std::path::Path::new(lib_path).exists() {
        bail!("Library not found: {lib_path}");
    }

    // 暂停目标进程
    let stop_result = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGSTOP);
    let stopped = stop_result.is_ok();
    if stopped {
        debug!("Stopped target process");
    } else {
        warn!("Failed to stop target process, continuing anyway");
    }

    // ptrace attach（会自动备份寄存器，drop 时自动 detach 恢复）
    let mut proc = RemoteProcess::attach(pid)?;
    info!("Attached to pid {}", pid);

    // 远程 dlopen
    let handle = remote_dlopen(&proc, lib_path, libc::RTLD_NOW)?;
    info!("dlopen returned handle: {:#x}", handle);

    // 查找注入后的 so 基址
    let base_addr = find_remote_lib_base(pid, lib_path)?
        .or_else(|| {
            // 尝试用文件名查找
            std::path::Path::new(lib_path)
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| find_remote_lib_base(pid, name).ok().flatten())
        })
        .unwrap_or(0);

    if base_addr != 0 {
        info!("Library loaded at base: {:#x}", base_addr);
    } else {
        warn!("Could not find library base address in maps");
    }

    // 恢复目标进程
    if stopped {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGCONT);
        debug!("Resumed target process");
    }

    // detach（恢复寄存器）
    proc.detach()?;
    info!("Detached from pid {}", pid);

    Ok(InjectedInfo {
        dl_handle: handle,
        base_addr,
    })
}
