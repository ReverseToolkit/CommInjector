use crate::ptrace_ex::{find_remote_symbol, remote_mmap_fixed, remote_munmap};
use anyhow::Result;
use log::{debug, info, warn};

use super::{HideTarget, Hider};

/// 通过 remap 匿名映射隐藏库在 /proc/pid/maps 中的痕迹
///
/// 原理（来自 Riru）：
/// 对每个 segment：备份内存 → munmap → mmap anonymous 到同一地址 → 恢复内存
/// 结果：内存内容不变，但 maps 中显示为匿名映射而非库文件路径
pub struct MapsHider;

impl Hider for MapsHider {
    fn name(&self) -> &'static str {
        "maps"
    }

    fn apply(&self, target: &HideTarget) -> Result<bool> {
        if target.segments.is_empty() {
            warn!("hide_maps: no segments found for {}", target.maps_search_name);
            return Ok(false);
        }

        for seg in &target.segments {
            debug!(
                "hide_maps: hiding segment {:#x} - {:#x} (size={})",
                seg.start,
                seg.start + seg.size,
                seg.size
            );

            let backup = target.proc.read_mem(seg.start, seg.size)?;
            remote_munmap(target.proc, seg.start, seg.size)?;

            let new_addr = remote_mmap_fixed(target.proc, seg.start, seg.size, libc::PROT_READ | libc::PROT_WRITE)?;
            if new_addr != seg.start {
                warn!("hide_maps: mmap returned {:#x}, expected {:#x}", new_addr, seg.start);
            }

            target.proc.write_mem(seg.start, &backup)?;

            if seg.prot != (libc::PROT_READ | libc::PROT_WRITE) {
                let pid_raw = target.proc.pid.as_raw();
                let local_syscall = libc::syscall as *const () as usize;
                let remote_syscall = find_remote_symbol(pid_raw, "libc.so", local_syscall)?;
                target.proc.call_function(
                    remote_syscall,
                    &[libc::SYS_mprotect as usize, seg.start, seg.size, seg.prot as usize],
                )?;
            }
        }

        info!("hide_maps: hidden {} segments", target.segments.len());
        Ok(true)
    }
}
