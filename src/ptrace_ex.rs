use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::debug;
use proc_maps::get_process_maps;
use std::process;

/// 在远程进程中查找某个 so 的基址
pub fn find_remote_lib_base(pid: i32, lib_name: &str) -> Result<Option<usize>> {
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
pub fn find_local_lib_base(lib_name: &str) -> Result<Option<usize>> {
    let pid = process::id() as i32;
    find_remote_lib_base(pid, lib_name)
}

/// 计算远程进程中某个函数的地址
/// 原理：local_func_addr - local_lib_base + remote_lib_base
pub fn find_remote_symbol(pid: i32, lib_name: &str, local_func_addr: usize) -> Result<usize> {
    let local_base = find_local_lib_base(lib_name)?.context(format!("Local lib {lib_name} not found"))?;
    let remote_base =
        find_remote_lib_base(pid, lib_name)?.context(format!("Remote lib {lib_name} not found in pid {pid}"))?;

    let offset = local_func_addr - local_base;
    Ok(remote_base + offset)
}

/// 在远程进程中分配内存（通过远程调用 mmap）
pub fn remote_mmap(proc: &RemoteProcess, size: usize) -> Result<usize> {
    let local_mmap = libc::mmap as usize;
    let remote_mmap = find_remote_symbol(proc.pid.as_raw(), "libc.so", local_mmap)?;

    debug!("remote mmap: {:#x}", remote_mmap);

    let addr = proc.call_function(
        remote_mmap,
        &[
            0,
            size,
            (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
            0,
            0,
        ],
    )?;

    if addr == usize::MAX || addr == 0 {
        bail!("Remote mmap failed, returned {:#x}", addr);
    }

    debug!("remote mmap allocated {size} bytes at {:#x}", addr);
    Ok(addr)
}

/// 在远程进程中释放内存
pub fn remote_munmap(proc: &RemoteProcess, addr: usize, size: usize) -> Result<()> {
    let local_munmap = libc::munmap as usize;
    let remote_munmap = find_remote_symbol(proc.pid.as_raw(), "libc.so", local_munmap)?;

    proc.call_function(remote_munmap, &[addr, size])?;
    Ok(())
}

/// 通过远程 syscall 调用 mmap（支持 MAP_FIXED）
pub fn remote_mmap_fixed(proc: &RemoteProcess, addr: usize, size: usize, prot: i32) -> Result<usize> {
    let pid = proc.pid.as_raw();
    let local_syscall = libc::syscall as usize;
    let remote_syscall = find_remote_symbol(pid, "libc.so", local_syscall)?;

    let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as usize;
    let ret = proc.call_function(
        remote_syscall,
        &[libc::SYS_mmap as usize, addr, size, prot as usize, flags, 0, 0],
    )?;

    if ret == usize::MAX || ret == 0 {
        bail!("Remote mmap MAP_FIXED failed at {:#x}, returned {:#x}", addr, ret);
    }
    Ok(ret)
}

/// 远程 close 一个 fd
pub fn remote_close(proc: &RemoteProcess, fd: i32) -> Result<()> {
    let pid = proc.pid.as_raw();
    let local_syscall = libc::syscall as usize;
    let remote_syscall = find_remote_symbol(pid, "libc.so", local_syscall)?;

    proc.call_function(remote_syscall, &[libc::SYS_close as usize, fd as usize])?;
    debug!("remote close fd={fd}");
    Ok(())
}

/// 远程调用 dlsym 查找符号
pub fn remote_dlsym(proc: &RemoteProcess, handle: usize, symbol: &str) -> Result<usize> {
    let pid = proc.pid.as_raw();
    let local_dlsym = libc::dlsym as usize;
    let remote_dlsym = find_remote_symbol(pid, "libdl.so", local_dlsym)?;

    let sym_with_null = format!("{symbol}\0");
    let remote_sym = remote_mmap(proc, sym_with_null.len())?;
    proc.write_mem(remote_sym, sym_with_null.as_bytes())?;

    let addr = proc.call_function(remote_dlsym, &[handle, remote_sym])?;

    let _ = remote_munmap(proc, remote_sym, sym_with_null.len());

    Ok(addr)
}

/// 远程调用 syscall
pub fn remote_syscall(proc: &RemoteProcess, args: &[usize]) -> Result<usize> {
    let pid = proc.pid.as_raw();
    let local_syscall = libc::syscall as usize;
    let remote_syscall = find_remote_symbol(pid, "libc.so", local_syscall)?;
    proc.call_function(remote_syscall, args)
}
