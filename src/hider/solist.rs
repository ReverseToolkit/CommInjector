use crate::linker_sym;
use crate::ptrace_ex::{remote_mmap, remote_munmap};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
use proc_maps::get_process_maps;

use super::{HideTarget, Hider};

const SOINFO_SIZE_OFFSET: usize = 0x18;

/// 通过 linker 内部 `soinfo_unload` 清理 solist / namespace 痕迹
///
/// 参考 NeoZygisk `dropSoPath(unload=true)`：
/// 1. 将 soinfo.size 置 0，避免 `soinfo_free` munmap 注入库内存
/// 2. 临时清除 constructors_called，避免触发析构 / JNI_OnUnload
/// 3. 在 ProtectedDataGuard 保护下调用 `soinfo_unload`
pub struct SolistHider;

impl Hider for SolistHider {
    fn name(&self) -> &'static str {
        "solist"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        let maps = get_process_maps(target.pid).context("Failed to read maps")?;
        let linker_info = maps
            .iter()
            .find(|m| {
                m.filename()
                    .map(|p| p.to_string_lossy().contains("/linker"))
                    .unwrap_or(false)
            })
            .context("linker not found in remote maps")?;

        let remote_linker_base = linker_info.start();
        let linker_path = linker_info
            .filename()
            .context("linker has no path")?
            .to_string_lossy()
            .to_string();

        debug!(
            "hide_solist: linker base={:#x} path={}",
            remote_linker_base, linker_path
        );

        let syms = linker_sym::resolve(&linker_path).context("Failed to resolve linker symbols")?;
        let find_containing = remote_linker_base + syms.find_containing_library;
        let soinfo_unload = remote_linker_base + syms.soinfo_unload;
        let pdg_ctor = remote_linker_base + syms.pdg_ctor;
        let pdg_dtor = remote_linker_base + syms.pdg_dtor;

        debug!(
            "hide_solist: find_containing={:#x} soinfo_unload={:#x}",
            find_containing, soinfo_unload
        );

        let soinfo = target
            .proc
            .call_function(find_containing, &[target.base_addr])?;
        if soinfo == 0 {
            warn!(
                "hide_solist: find_containing_library returned null for base {:#x}",
                target.base_addr
            );
            return Ok(false);
        }

        info!("hide_solist: target soinfo at {:#x}", soinfo);

        let saved_size = read_usize(target.proc, soinfo + SOINFO_SIZE_OFFSET)?;
        let ctor_off = probe_constructors_called_offset(target.proc, soinfo)?;
        let saved_ctor = target.proc.read_mem(soinfo + ctor_off, 1)?[0];

        target
            .proc
            .write_mem_io(soinfo + SOINFO_SIZE_OFFSET, &0usize.to_ne_bytes())?;
        target.proc.write_mem_io(soinfo + ctor_off, &[0u8])?;

        let guard = remote_mmap(target.proc, 64).context("Failed to allocate ProtectedDataGuard")?;
        let unload_result = (|| {
            target.proc.call_function(pdg_ctor, &[guard])?;
            let ret = target.proc.call_function(soinfo_unload, &[soinfo]);
            target.proc.call_function(pdg_dtor, &[guard])?;
            ret
        })();
        let _ = remote_munmap(target.proc, guard, 64);

        target
            .proc
            .write_mem_io(soinfo + ctor_off, &[saved_ctor])?;

        match unload_result {
            Ok(_) => {
                info!(
                    "hide_solist: soinfo_unload ok (saved_size={:#x}, size zeroed to skip munmap)",
                    saved_size
                );
                Ok(true)
            }
            Err(e) => {
                warn!("hide_solist: soinfo_unload failed: {e:#}");
                let _ = target
                    .proc
                    .write_mem_io(soinfo + SOINFO_SIZE_OFFSET, &saved_size.to_ne_bytes());
                Ok(false)
            }
        }
    }
}

fn read_usize(proc: &RemoteProcess, addr: usize) -> Result<usize> {
    let buf = proc.read_mem(addr, 8)?;
    Ok(usize::from_ne_bytes(buf.try_into().unwrap()))
}

/// 在 soinfo 结构体中定位 constructors_called（注入后应为 true）
fn probe_constructors_called_offset(proc: &RemoteProcess, soinfo: usize) -> Result<usize> {
    let buf = proc.read_mem(soinfo, 0x100).context("Failed to read soinfo header")?;
    let mut candidates = Vec::new();
    for off in 0x48..0xc0 {
        if buf[off] == 1 {
            candidates.push(off);
        }
    }
    if candidates.is_empty() {
        bail!("constructors_called not found in soinfo {:#x}", soinfo);
    }
    // LP64 上 bool 通常在 link_map 之后，取第一个合理候选
    Ok(candidates[0])
}
