use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::debug;
use proc_maps::get_process_maps;
use std::fs;
use std::process;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;
const SHT_DYNSYM: u32 = 11;
const SHT_SYMTAB: u32 = 2;

/// 在远程进程中查找某个 so 的基址
pub fn find_remote_lib_base(pid: i32, lib_name: &str) -> Result<Option<usize>> {
    Ok(find_remote_lib(pid, lib_name)?.map(|(base, _)| base))
}

/// 查找远程 so 的最低映射地址和磁盘路径
pub fn find_remote_lib(pid: i32, lib_name: &str) -> Result<Option<(usize, String)>> {
    let maps = get_process_maps(pid).context("Failed to read remote maps")?;
    let mut best: Option<(usize, String)> = None;
    for map in &maps {
        if let Some(path) = map.filename() {
            let path_str = path.to_string_lossy();
            if path_str.contains(lib_name) {
                let start = map.start();
                if best.as_ref().map(|(base, _)| start < *base).unwrap_or(true) {
                    best = Some((start, path_str.into_owned()));
                }
            }
        }
    }
    Ok(best)
}

/// 解析远程进程已映射库中的导出/调试符号
pub fn find_remote_export(pid: i32, lib_name: &str, symbol: &str) -> Result<usize> {
    let (remote_base, path) = find_remote_lib(pid, lib_name)?
        .with_context(|| format!("{lib_name} not mapped in pid {pid}"))?;
    let offset = elf64_symbol_offset(&path, symbol)
        .with_context(|| format!("symbol {symbol} not found in {path}"))?;
    Ok(remote_base + offset)
}

fn elf64_symbol_offset(path: &str, symbol: &str) -> Result<usize> {
    let data = fs::read(path).with_context(|| format!("Failed to read {path}"))?;
    if data.len() < 64 || data[..4] != ELF_MAGIC {
        bail!("{path} is not an ELF");
    }
    if data[4] != 2 {
        bail!("Only ELF64 is supported: {path}");
    }

    let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;

    let mut load_vaddr = 0u64;
    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 32 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        if p_type == PT_LOAD {
            load_vaddr = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
            break;
        }
    }

    let mut found = None;
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + 40 > data.len() {
            break;
        }
        let sh_type = u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap());
        if sh_type != SHT_DYNSYM && sh_type != SHT_SYMTAB {
            continue;
        }
        let sym_off = u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize;
        let sym_size = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize;
        let strtab_idx = u32::from_le_bytes(data[sh + 40..sh + 44].try_into().unwrap()) as usize;
        let entsize = {
            let raw = u64::from_le_bytes(data[sh + 56..sh + 64].try_into().unwrap()) as usize;
            if raw == 0 { 24 } else { raw }
        };
        if strtab_idx >= e_shnum {
            continue;
        }
        let str_sh = e_shoff + strtab_idx * e_shentsize;
        let str_off = u64::from_le_bytes(data[str_sh + 24..str_sh + 32].try_into().unwrap()) as usize;
        let str_size = u64::from_le_bytes(data[str_sh + 32..str_sh + 40].try_into().unwrap()) as usize;
        if str_off + str_size > data.len() {
            continue;
        }
        let strtab = &data[str_off..str_off + str_size];
        let count = if entsize == 0 { 0 } else { sym_size / entsize };
        for j in 0..count {
            let off = sym_off + j * entsize;
            if off + 24 > data.len() {
                break;
            }
            let st_name = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            if st_name == 0 || st_name >= strtab.len() {
                continue;
            }
            let end = strtab[st_name..].iter().position(|&b| b == 0).unwrap_or(0);
            if let Ok(name) = std::str::from_utf8(&strtab[st_name..st_name + end]) {
                if name == symbol {
                    found = Some(st_value);
                    break;
                }
            }
        }
        if found.is_some() {
            break;
        }
    }

    let st_value = found.with_context(|| format!("symbol {symbol} not in {path}"))?;
    Ok(st_value.saturating_sub(load_vaddr) as usize)
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
