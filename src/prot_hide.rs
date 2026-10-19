//! 远程 mmap / mprotect 带上内核 `PROT_HIDE`。
//!
//! 定制内核把 `PROT_HIDE`（0x40）从保护位里拆掉，并给 VMA 置 `VM_VMA_HIDE`，
//! 非 root 的 maps/smaps 不再列出这块映射。原内核认不出这个位，返回 EINVAL，
//! 这时退回不带该位的同一次调用。

use crate::ptrace_ex::{find_remote_export, remote_syscall};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::warn;

pub const PROT_HIDE: i32 = 0x40;

const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;

/// `hidden` 为真表示内核接受了 `PROT_HIDE`。
pub struct HiddenMap {
    pub addr: usize,
    pub hidden: bool,
}

pub fn remote_mmap_anonymous(proc: &RemoteProcess, size: usize, prot: i32) -> Result<HiddenMap> {
    if size == 0 {
        bail!("remote mmap size is 0");
    }
    let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize;
    map_with_hide(proc, 0, size, prot, flags, usize::MAX, 0)
}

pub fn remote_mprotect(proc: &RemoteProcess, addr: usize, size: usize, prot: i32) -> Result<bool> {
    if size == 0 {
        bail!("remote mprotect size is 0");
    }
    protect_with_hide(proc, addr, size, prot)
}

fn map_with_hide(
    proc: &RemoteProcess,
    addr: usize,
    size: usize,
    prot: i32,
    flags: usize,
    fd: usize,
    offset: usize,
) -> Result<HiddenMap> {
    let want = (prot & !PROT_HIDE) | PROT_HIDE;
    match syscall_mmap(proc, addr, size, want as usize, flags, fd, offset) {
        Ok(mapped) => Ok(HiddenMap { addr: mapped, hidden: true }),
        Err(err) if is_unsupported(&err) => {
            warn!("kernel rejected PROT_HIDE on mmap, retrying without it");
            let mapped = syscall_mmap(proc, addr, size, (prot & !PROT_HIDE) as usize, flags, fd, offset)?;
            Ok(HiddenMap { addr: mapped, hidden: false })
        }
        Err(err) => Err(err),
    }
}

fn protect_with_hide(proc: &RemoteProcess, addr: usize, size: usize, prot: i32) -> Result<bool> {
    let want = (prot & !PROT_HIDE) | PROT_HIDE;
    match syscall_mprotect(proc, addr, size, want as usize) {
        Ok(()) => Ok(true),
        Err(err) if is_unsupported(&err) => {
            warn!("kernel rejected PROT_HIDE on mprotect, retrying without it");
            syscall_mprotect(proc, addr, size, (prot & !PROT_HIDE) as usize)?;
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

fn syscall_mmap(
    proc: &RemoteProcess,
    addr: usize,
    size: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> Result<usize> {
    let ret = remote_syscall(
        proc,
        &[libc::SYS_mmap as usize, addr, size, prot, flags, fd, offset],
    )
    .context("remote mmap syscall")?;
    if ret == 0 || ret == usize::MAX {
        let err = read_errno(proc).unwrap_or(0);
        bail!("remote mmap failed (errno {err})");
    }
    Ok(ret)
}

fn syscall_mprotect(proc: &RemoteProcess, addr: usize, size: usize, prot: usize) -> Result<()> {
    let ret = remote_syscall(proc, &[libc::SYS_mprotect as usize, addr, size, prot])
        .context("remote mprotect syscall")?;
    if ret != 0 {
        let err = read_errno(proc).unwrap_or(0);
        bail!("remote mprotect failed (errno {err})");
    }
    Ok(())
}

fn is_unsupported(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}");
    text.contains(&format!("errno {EINVAL}")) || text.contains(&format!("errno {ENOSYS}"))
}

fn read_errno(proc: &RemoteProcess) -> Result<i32> {
    let errno_fn = find_remote_export(proc.pid.as_raw(), "libc.so", "__errno")?;
    let slot = proc.call_function(errno_fn, &[])?;
    if slot == 0 {
        bail!("__errno returned null");
    }
    let bytes = proc.read_mem(slot, 4)?;
    Ok(i32::from_le_bytes(bytes[..4].try_into().expect("4 errno bytes")))
}
