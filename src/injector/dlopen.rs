use crate::ptrace_ex::{find_remote_lib_base, find_remote_symbol, remote_mmap, remote_munmap};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Result, bail};
use log::debug;
use std::path::Path;

use super::{Injector, LoadResult};

pub struct DlopenInjector;

impl Injector for DlopenInjector {
    fn load(&self, proc: &RemoteProcess, lib_path: &str) -> Result<LoadResult> {
        let pid = proc.pid.as_raw();
        let handle = remote_dlopen(proc, lib_path, libc::RTLD_NOW)?;

        let base_addr = find_remote_lib_base(pid, lib_path)?
            .or_else(|| {
                Path::new(lib_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| find_remote_lib_base(pid, name).ok().flatten())
            })
            .unwrap_or(0);

        let search_name = Path::new(lib_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(lib_path)
            .to_string();

        Ok(LoadResult {
            handle,
            base_addr,
            maps_search_name: search_name,
            memfd_fd: None,
        })
    }
}

fn remote_dlopen(proc: &RemoteProcess, lib_path: &str, flags: i32) -> Result<usize> {
    let local_dlopen = libc::dlopen as usize;
    let remote_dlopen = find_remote_symbol(proc.pid.as_raw(), "libdl.so", local_dlopen)?;
    debug!("remote dlopen: {:#x}", remote_dlopen);

    let path_bytes = lib_path.as_bytes();
    let path_len = path_bytes.len() + 1;
    let remote_path = remote_mmap(proc, path_len)?;

    let mut buf = path_bytes.to_vec();
    buf.push(0);
    proc.write_mem(remote_path, &buf)?;

    let handle = proc.call_function(remote_dlopen, &[remote_path, flags as usize])?;
    let _ = remote_munmap(proc, remote_path, path_len);

    if handle == 0 {
        let local_dlerror = libc::dlerror as usize;
        if let Ok(remote_dlerror) = find_remote_symbol(proc.pid.as_raw(), "libdl.so", local_dlerror) {
            if let Ok(err_ptr) = proc.call_function(remote_dlerror, &[]) {
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
