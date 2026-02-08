use fs::OpenOptions;
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
use proc_maps::get_process_maps;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process;
use std::time::SystemTime;

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

    let addr = proc.call_function(
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

    proc.call_function(remote_munmap, &[addr, size])?;
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
    let handle = proc.call_function(remote_dlopen, &[remote_path, flags as usize])?;

    // 清理路径内存
    let _ = remote_munmap(proc, remote_path, path_len);

    if handle == 0 {
        // 尝试获取 dlerror
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

/// 通过远程 syscall 调用 memfd_create
fn remote_memfd_create(proc: &RemoteProcess, name: &str) -> Result<i32> {
    let pid = proc.pid.as_raw();

    // 写入 name 字符串到远程
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() + 1;
    let remote_name = remote_mmap(proc, name_len)?;
    let mut buf = name_bytes.to_vec();
    buf.push(0);
    proc.write_mem(remote_name, &buf)?;

    // aarch64 syscall: x8 = __NR_memfd_create (279), x0 = name, x1 = flags
    // 通过远程调用 syscall() 函数实现
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

/// 通过远程 syscall 对 memfd 执行 fcntl F_ADD_SEALS
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

/// 使用 memfd_create + android_dlopen_ext 注入
fn remote_dlopen_memfd(proc: &RemoteProcess, lib_path: &str, flags: i32) -> Result<usize> {
    let pid = proc.pid.as_raw();

    // 生成随机 memfd 名称
    let seed = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let memfd_name: String = (0..8)
        .map(|i| (b'a' + ((seed >> (i * 4)) % 26) as u8) as char)
        .collect();
    info!("memfd name: {memfd_name}");

    // 远程 memfd_create
    let memfd = remote_memfd_create(proc, &memfd_name)?;

    // 从注入器进程通过 /proc/<pid>/fd/<fd> 写入 so 内容
    let memfd_path = format!("/proc/{pid}/fd/{memfd}");
    let lib_data = fs::read(lib_path).context("Failed to read library file")?;

    let mut memfd_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&memfd_path)
        .context(format!("Failed to open {memfd_path}"))?;
    memfd_file.write_all(&lib_data).context("Failed to write library to memfd")?;
    memfd_file.flush().context("Failed to flush memfd")?;

    // 验证写入大小
    let written_size = memfd_file.metadata().map(|m| m.len()).unwrap_or(0);
    debug!("wrote {} bytes to {memfd_path}, file size={written_size}", lib_data.len());
    if written_size == 0 {
        bail!("memfd write failed: file size is 0 after write");
    }
    drop(memfd_file);

    // seal memfd
    let _ = remote_memfd_seal(proc, memfd);

    // 构造 android_dlextinfo 并写入远程内存
    // struct android_dlextinfo { uint64_t flags; void* reserved_addr; size_t reserved_size; int relro_fd; int library_fd; ... }
    // ANDROID_DLEXT_USE_LIBRARY_FD = 0x10, library_fd 在 offset 24 (aarch64)
    let extinfo_size = 48; // android_dlextinfo 足够大
    let remote_extinfo = remote_mmap(proc, extinfo_size)?;

    let mut extinfo_buf = vec![0u8; extinfo_size];
    // flags (uint64_t at offset 0) = ANDROID_DLEXT_USE_LIBRARY_FD (0x10)
    extinfo_buf[..8].copy_from_slice(&0x10u64.to_ne_bytes());
    // library_fd (int at offset 28) = memfd
    // struct layout: flags(0:8) reserved_addr(8:16) reserved_size(16:24) relro_fd(24:28) library_fd(28:32)
    extinfo_buf[28..32].copy_from_slice(&memfd.to_ne_bytes());
    proc.write_mem(remote_extinfo, &extinfo_buf)?;

    // 写入 memfd name 作为 dlopen 的 filename 参数
    let name_with_null = format!("{memfd_name}\0");
    let remote_name = remote_mmap(proc, name_with_null.len())?;
    proc.write_mem(remote_name, name_with_null.as_bytes())?;

    // 远程调用 android_dlopen_ext(name, flags, &extinfo)
    let local_dlopen_ext =
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, b"android_dlopen_ext\0".as_ptr() as *const _) } as usize;

    if local_dlopen_ext == 0 {
        bail!("android_dlopen_ext not found locally");
    }

    let remote_dlopen_ext = find_remote_symbol(pid, "libdl.so", local_dlopen_ext)?;
    debug!("remote android_dlopen_ext: {:#x}", remote_dlopen_ext);

    let handle = proc.call_function(remote_dlopen_ext, &[remote_name, flags as usize, remote_extinfo])?;

    // 清理
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

    Ok(handle)
}

/// 实际注入逻辑，由 inject 调用，错误由 inject 统一处理恢复
fn do_inject(proc: &RemoteProcess, pid: i32, lib_path: &str, use_memfd: bool) -> Result<InjectedInfo> {
    let handle = if use_memfd {
        info!("Using memfd injection");
        remote_dlopen_memfd(proc, lib_path, libc::RTLD_NOW)?
    } else {
        remote_dlopen(proc, lib_path, libc::RTLD_NOW)?
    };
    info!("dlopen returned handle: {:#x}", handle);

    let base_addr = if use_memfd {
        // memfd 加载后 maps 里显示 /memfd:xxx，用文件名不好找，直接搜 handle 对应的映射
        // 也可以尝试搜 memfd 名称
        find_remote_lib_base(pid, "memfd:")?.unwrap_or(0)
    } else {
        find_remote_lib_base(pid, lib_path)?
            .or_else(|| {
                Path::new(lib_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| find_remote_lib_base(pid, name).ok().flatten())
            })
            .unwrap_or(0)
    };

    if base_addr != 0 {
        info!("Library loaded at base: {:#x}", base_addr);
    } else {
        warn!("Could not find library base address in maps");
    }

    Ok(InjectedInfo {
        dl_handle: handle,
        base_addr,
    })
}

/// 注入 so 到目标进程
///
/// 流程：
/// 1. SIGSTOP 暂停目标进程
/// 2. ptrace attach
/// 3. 远程调用 dlopen 加载 so
/// 4. SIGCONT 恢复目标进程
/// 5. ptrace detach
pub fn inject(pid: i32, lib_path: &str, use_memfd: bool) -> Result<InjectedInfo> {
    info!("Injecting {} into pid {}", lib_path, pid);

    // 验证 so 文件存在
    if !Path::new(lib_path).exists() {
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

    // 设置 default_caller：用系统 so 基址作为远程函数调用的返回地址（LR）
    // 这样 cont 后命中该地址会触发 SIGSEGV，被我们捕获
    // refs: https://fadeevab.com/shared-library-injection-on-android-8/
    let caller = find_remote_lib_base(pid, "libRS.so")?
        .or_else(|| find_remote_lib_base(pid, "libc.so").ok().flatten())
        .unwrap_or(0);
    if caller != 0 {
        debug!("default_caller set to {:#x}", caller);
        proc.set_default_caller(caller);
    } else {
        warn!("Could not find a suitable default_caller, remote calls may fail");
    }

    // 执行注入，无论成功失败都必须恢复进程
    let result = do_inject(&proc, pid, lib_path, use_memfd);

    // 恢复目标进程
    if stopped {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGCONT);
        debug!("Resumed target process");
    }

    proc.detach()?;
    info!("Detached from pid {}", pid);

    result
}
