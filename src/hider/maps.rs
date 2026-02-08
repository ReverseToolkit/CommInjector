use crate::ptrace_ex::{find_remote_symbol, remote_mmap_fixed, remote_munmap};
use anyhow::{Context, Result};
use log::{debug, info, warn};
use proc_maps::get_process_maps;

use super::{HideTarget, Hider};

struct LibSegment {
    start: usize,
    size: usize,
    prot: i32,
}

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
        let segments = find_remote_lib_segments(target.pid, target.maps_search_name)?;
        if segments.is_empty() {
            warn!("hide_maps: no segments found for {}", target.maps_search_name);
            return Ok(false);
        }

        for seg in &segments {
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
                let local_syscall = libc::syscall as usize;
                let remote_syscall = find_remote_symbol(pid_raw, "libc.so", local_syscall)?;
                target.proc.call_function(
                    remote_syscall,
                    &[libc::SYS_mprotect as usize, seg.start, seg.size, seg.prot as usize],
                )?;
            }
        }

        info!("hide_maps: hidden {} segments", segments.len());
        Ok(true)
    }
}

fn find_remote_lib_segments(pid: i32, lib_name: &str) -> Result<Vec<LibSegment>> {
    let maps = get_process_maps(pid).context("Failed to read remote maps")?;
    let mut segments = Vec::new();

    for map in &maps {
        let path = match map.filename() {
            Some(p) => p.to_string_lossy(),
            None => continue,
        };

        if !path.contains(lib_name) {
            continue;
        }

        let prot = {
            let mut p = 0i32;
            if map.is_read() {
                p |= libc::PROT_READ;
            }
            if map.is_write() {
                p |= libc::PROT_WRITE;
            }
            if map.is_exec() {
                p |= libc::PROT_EXEC;
            }
            p
        };

        segments.push(LibSegment {
            start: map.start(),
            size: map.size(),
            prot,
        });
    }

    Ok(segments)
}
