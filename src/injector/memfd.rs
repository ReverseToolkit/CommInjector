use crate::ptrace_ex::{find_remote_lib_base, find_remote_symbol, remote_mmap, remote_munmap};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::{debug, info};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::SystemTime;

use super::{Injector, LoadResult};

pub struct MemfdInjector;

impl Injector for MemfdInjector {
    fn load(&self, proc: &RemoteProcess, lib_path: &str) -> Result<LoadResult> {
        let pid = proc.pid.as_raw();
        let (handle, memfd, memfd_name) = remote_dlopen_memfd(proc, lib_path, libc::RTLD_NOW)?;

        let search = format!("memfd:{memfd_name}");
        let base_addr = find_remote_lib_base(pid, &search)?.unwrap_or(0);

        Ok(LoadResult {
            handle,
            base_addr,
            maps_search_name: search,
            memfd_fd: Some(memfd),
        })
    }
}

fn remote_memfd_create(proc: &RemoteProcess, name: &str) -> Result<i32> {
    let pid = proc.pid.as_raw();

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() + 1;
    let remote_name = remote_mmap(proc, name_len)?;
    let mut buf = name_bytes.to_vec();
    buf.push(0);
    proc.write_mem(remote_name, &buf)?;

    let local_syscall = libc::syscall as usize;
    let remote_syscall = find_remote_symbol(pid, "libc.so", local_syscall)?;

    let flags = (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as usize;
    let fd = proc.call_function(remote_syscall, &[libc::SYS_memfd_create as usize, remote_name, flags])? as i64 as i32;

    let _ = remote_munmap(proc, remote_name, name_len);

    if fd < 0 {
        bail!("Remote memfd_create failed, returned {fd}");
    }

    debug!("remote memfd_create returned fd={fd}");
    Ok(fd)
}

fn remote_memfd_seal(proc: &RemoteProcess, fd: i32) -> Result<()> {
    let pid = proc.pid.as_raw();
    let local_syscall = libc::syscall as usize;
    let remote_syscall = find_remote_symbol(pid, "libc.so", local_syscall)?;

    let seals = (libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL) as usize;
    proc.call_function(
        remote_syscall,
        &[libc::SYS_fcntl as usize, fd as usize, libc::F_ADD_SEALS as usize, seals],
    )?;
    Ok(())
}

fn remote_dlopen_memfd(proc: &RemoteProcess, lib_path: &str, flags: i32) -> Result<(usize, i32, String)> {
    let pid = proc.pid.as_raw();

    let seed = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let memfd_name: String = (0..8)
        .map(|i| (b'a' + ((seed >> (i * 4)) % 26) as u8) as char)
        .collect();
    info!("memfd name: {memfd_name}");

    let memfd = remote_memfd_create(proc, &memfd_name)?;

    let memfd_path = format!("/proc/{pid}/fd/{memfd}");
    let lib_data = fs::read(lib_path).context("Failed to read library file")?;

    let mut memfd_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&memfd_path)
        .context(format!("Failed to open {memfd_path}"))?;
    memfd_file
        .write_all(&lib_data)
        .context("Failed to write library to memfd")?;
    memfd_file.flush().context("Failed to flush memfd")?;

    let written_size = memfd_file.metadata().map(|m| m.len()).unwrap_or(0);
    debug!(
        "wrote {} bytes to {memfd_path}, file size={written_size}",
        lib_data.len()
    );
    if written_size == 0 {
        bail!("memfd write failed: file size is 0 after write");
    }
    drop(memfd_file);

    let _ = remote_memfd_seal(proc, memfd);

    let extinfo_size = 48;
    let remote_extinfo = remote_mmap(proc, extinfo_size)?;

    let mut extinfo_buf = vec![0u8; extinfo_size];
    extinfo_buf[..8].copy_from_slice(&0x10u64.to_ne_bytes());
    extinfo_buf[28..32].copy_from_slice(&memfd.to_ne_bytes());
    proc.write_mem(remote_extinfo, &extinfo_buf)?;

    let name_with_null = format!("{memfd_name}\0");
    let remote_name = remote_mmap(proc, name_with_null.len())?;
    proc.write_mem(remote_name, name_with_null.as_bytes())?;

    let local_dlopen_ext =
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, b"android_dlopen_ext\0".as_ptr() as *const _) } as usize;

    if local_dlopen_ext == 0 {
        bail!("android_dlopen_ext not found locally");
    }

    let remote_dlopen_ext = find_remote_symbol(pid, "libdl.so", local_dlopen_ext)?;
    debug!("remote android_dlopen_ext: {:#x}", remote_dlopen_ext);

    let handle = proc.call_function(remote_dlopen_ext, &[remote_name, flags as usize, remote_extinfo])?;

    let _ = remote_munmap(proc, remote_extinfo, extinfo_size);
    let _ = remote_munmap(proc, remote_name, name_with_null.len());

    if handle == 0 {
        let local_dlerror = libc::dlerror as usize;
        if let Ok(remote_dlerror) = find_remote_symbol(pid, "libdl.so", local_dlerror) {
            if let Ok(err_ptr) = proc.call_function(remote_dlerror, &[]) {
                if err_ptr != 0 {
                    if let Ok(err_str) = proc.read_cstring(err_ptr, 256) {
                        bail!("android_dlopen_ext failed: {err_str}");
                    }
                }
            }
        }
        bail!("android_dlopen_ext returned NULL");
    }

    Ok((handle, memfd, memfd_name))
}
