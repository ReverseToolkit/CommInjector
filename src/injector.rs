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
    pub maps_hidden: bool,
}

impl InjectedInfo {
    pub fn is_valid(&self) -> bool {
        self.dl_handle != 0 && self.base_addr != 0
    }
}

/// 库在远程进程中的一个内存段
struct LibSegment {
    start: usize,
    size: usize,
    prot: i32,
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

/// 通过远程 syscall 调用 mmap（支持 MAP_FIXED）
fn remote_mmap_fixed(proc: &RemoteProcess, addr: usize, size: usize, prot: i32) -> Result<usize> {
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

/// 查找注入库在远程进程中的所有内存段
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

/// 隐藏注入库在 /proc/pid/maps 中的痕迹
///
/// 原理（来自 Riru）：
/// 对每个 segment：备份内存 → munmap → mmap anonymous 到同一地址 → 恢复内存
/// 结果：内存内容不变，但 maps 中显示为匿名映射而非库文件路径
fn hide_library_from_maps(proc: &RemoteProcess, pid: i32, lib_name: &str) -> Result<bool> {
    let segments = find_remote_lib_segments(pid, lib_name)?;
    if segments.is_empty() {
        warn!("hide_maps: no segments found for {lib_name}");
        return Ok(false);
    }

    for seg in &segments {
        debug!("hide_maps: hiding segment {:#x} - {:#x} (size={})", seg.start, seg.start + seg.size, seg.size);

        // 备份 segment 内容
        let backup = proc.read_mem(seg.start, seg.size)?;

        // munmap 原始映射
        remote_munmap(proc, seg.start, seg.size)?;

        // 在同一地址重新 mmap 匿名映射
        let new_addr = remote_mmap_fixed(proc, seg.start, seg.size, libc::PROT_READ | libc::PROT_WRITE)?;
        if new_addr != seg.start {
            warn!("hide_maps: mmap returned {:#x}, expected {:#x}", new_addr, seg.start);
        }

        // 恢复内容
        proc.write_mem(seg.start, &backup)?;

        // 恢复原始保护属性（写入完成后再设置，因为可能是 r-x）
        if seg.prot != (libc::PROT_READ | libc::PROT_WRITE) {
            let pid_raw = proc.pid.as_raw();
            let local_syscall = libc::syscall as usize;
            let remote_syscall = find_remote_symbol(pid_raw, "libc.so", local_syscall)?;
            proc.call_function(
                remote_syscall,
                &[libc::SYS_mprotect as usize, seg.start, seg.size, seg.prot as usize],
            )?;
        }
    }

    info!("hide_maps: hidden {} segments", segments.len());
    Ok(true)
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

/// 远程 close 一个 fd
fn remote_close(proc: &RemoteProcess, fd: i32) -> Result<()> {
    let pid = proc.pid.as_raw();
    let local_syscall = libc::syscall as usize;
    let remote_syscall = find_remote_symbol(pid, "libc.so", local_syscall)?;

    proc.call_function(remote_syscall, &[libc::SYS_close as usize, fd as usize])?;
    debug!("remote close fd={fd}");
    Ok(())
}

/// 使用 memfd_create + android_dlopen_ext 注入
/// 返回 (dl_handle, memfd_fd, memfd_name)
fn remote_dlopen_memfd(proc: &RemoteProcess, lib_path: &str, flags: i32) -> Result<(usize, i32, String)> {
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

    Ok((handle, memfd, memfd_name))
}

/// 远程调用 dlsym 查找符号
fn remote_dlsym(proc: &RemoteProcess, handle: usize, symbol: &str) -> Result<usize> {
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

/// 实际注入逻辑，由 inject 调用，错误由 inject 统一处理恢复
fn do_inject(proc: &RemoteProcess, pid: i32, lib_path: &str, use_memfd: bool, hide_maps: bool) -> Result<InjectedInfo> {
    let (handle, memfd_fd, memfd_name) = if use_memfd {
        info!("Using memfd injection");
        let (h, fd, name) = remote_dlopen_memfd(proc, lib_path, libc::RTLD_NOW)?;
        (h, Some(fd), Some(name))
    } else {
        let h = remote_dlopen(proc, lib_path, libc::RTLD_NOW)?;
        (h, None, None)
    };
    info!("dlopen returned handle: {:#x}", handle);

    let (base_addr, maps_search_name) = if let Some(ref name) = memfd_name {
        let search = format!("memfd:{name}");
        let base = find_remote_lib_base(pid, &search)?.unwrap_or(0);
        (base, search)
    } else {
        let base = find_remote_lib_base(pid, lib_path)?
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
        (base, search_name)
    };

    if base_addr != 0 {
        info!("Library loaded at base: {:#x}", base_addr);
    } else {
        warn!("Could not find library base address in maps");
    }

    let maps_hidden = if hide_maps && base_addr != 0 {
        match hide_library_from_maps(proc, pid, &maps_search_name) {
            Ok(true) => {
                info!("Library segments hidden from maps");
                true
            }
            Ok(false) => {
                warn!("Failed to hide library segments from maps");
                false
            }
            Err(e) => {
                warn!("hide_maps error: {e:#}");
                false
            }
        }
    } else {
        false
    };

    // 关闭 memfd fd，避免在 /proc/pid/fd/ 中留下痕迹
    if let Some(fd) = memfd_fd {
        if let Err(e) = remote_close(proc, fd) {
            warn!("Failed to close memfd fd: {e:#}");
        }
    }

    Ok(InjectedInfo {
        dl_handle: handle,
        base_addr,
        maps_hidden,
    })
}

/// 注入 so 到目标进程
///
/// 流程：
/// 1. SIGSTOP 暂停目标进程
/// 2. ptrace attach
/// 3. 远程调用 dlopen 加载 so
/// 4. hide_maps / close memfd
/// 5. SIGCONT 恢复目标进程
/// 6. 远程调用 entry_point
/// 7. ptrace detach
pub fn inject(pid: i32, lib_path: &str, use_memfd: bool, hide_maps: bool) -> Result<InjectedInfo> {
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
    let result = do_inject(&proc, pid, lib_path, use_memfd, hide_maps);

    // 注入成功时：在 ptrace 下直接调用 JNI_OnLoad（不需要 SIGCONT）
    if let Ok(ref info) = result {
        if info.is_valid() {
            match remote_dlsym(&proc, info.dl_handle, "JNI_OnLoad") {
                Ok(ep) if ep != 0 => {
                    info!("Calling JNI_OnLoad at {:#x}", ep);
                    if let Err(e) = proc.call_function(ep, &[]) {
                        warn!("JNI_OnLoad call failed: {e:#}");
                    }
                }
                _ => {
                    debug!("No JNI_OnLoad symbol found, skipping");
                }
            }
        }
    }

    // 先 detach 再 SIGCONT，避免被检测到 ptrace
    proc.detach()?;
    info!("Detached from pid {}", pid);

    if stopped {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGCONT);
        debug!("Resumed target process");
    }
    info!("Detached from pid {}", pid);

    result
}
