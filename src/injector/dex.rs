use crate::prot_hide::{self, PROT_HIDE};
use crate::ptrace_ex::{remote_mmap, remote_munmap};
use crate::ptrace_ext::RemoteProcess;
use crate::remote_jni::RemoteJni;
use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
use proc_maps::get_process_maps;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use super::InjectedInfo;

pub fn is_dex_payload(path: &str) -> bool {
    let path = Path::new(path);
    if path.extension().and_then(|e| e.to_str()) == Some("dex") {
        return true;
    }
    fs::read(path)
        .ok()
        .is_some_and(|data| data.len() >= 8 && &data[0..4] == b"dex\n")
}

pub fn inject_dex(proc: &RemoteProcess, dex_path: &str, entry: &str) -> Result<InjectedInfo> {
    let (entry_class, entry_method) = parse_entry(entry)?;
    let dex_data = fs::read(dex_path).with_context(|| format!("Failed to read dex: {dex_path}"))?;
    if dex_data.len() < 0x70 || &dex_data[0..4] != b"dex\n" {
        bail!("Invalid dex file: {dex_path}");
    }

    info!(
        "DEX payload {} ({} bytes), entry={}.{}()",
        dex_path,
        dex_data.len(),
        entry_class,
        entry_method
    );

    let before = map_starts(proc.pid.as_raw());
    let remote_dex = remote_mmap(proc, dex_data.len())?;
    proc.write_mem(remote_dex, &dex_data)?;
    debug!("dex bytes at {remote_dex:#x}");

    let result = (|| {
        let jni = RemoteJni::attach(proc)?;
        jni.try_exempt_hidden_api();

        let loader = app_class_loader(&jni)?;
        info!("target ClassLoader={loader:#x}");

        let buffer = jni.new_direct_byte_buffer(remote_dex, dex_data.len())?;
        let added = make_dex_elements(&jni, buffer, loader)?;
        merge_dex_elements(&jni, loader, added)?;

        invoke_entry(&jni, loader, &entry_class, &entry_method)?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = remote_munmap(proc, remote_dex, dex_data.len());
        return Err(e);
    }

    let hidden = match hide_dex_mappings(&proc, remote_dex, dex_data.len(), &before) {
        Ok(hidden) => hidden,
        Err(err) => {
            warn!("PROT_HIDE on dex mappings failed: {err:#}");
            false
        }
    };

    Ok(InjectedInfo {
        dl_handle: 0,
        base_addr: remote_dex,
        hider_results: vec![("prot_hide".to_string(), hidden)],
        jni_onload: None,
        custom_link: false,
    })
}

fn hide_dex_mappings(proc: &RemoteProcess, buffer: usize, size: usize, before: &HashSet<usize>) -> Result<bool> {
    let page = page_size();
    let start = align_down(buffer, page);
    let end = align_up(buffer + size, page);
    let mut hidden = prot_hide::remote_mprotect(proc, start, end - start, libc::PROT_READ | PROT_HIDE)?;

    let maps = get_process_maps(proc.pid.as_raw()).context("Failed to read maps after dex load")?;
    for map in &maps {
        if before.contains(&map.start()) || map.start() == start {
            continue;
        }
        if !is_anonymous_dex_map(map.filename().map(|p| p.to_string_lossy().into_owned())) {
            continue;
        }
        if map.size() < 4 || !map.is_read() {
            continue;
        }
        let magic = proc.read_mem(map.start(), 4).unwrap_or_default();
        if magic != b"dex\n" {
            continue;
        }
        let mut prot = libc::PROT_READ;
        if map.is_write() {
            prot |= libc::PROT_WRITE;
        }
        if map.is_exec() {
            prot |= libc::PROT_EXEC;
        }
        info!("PROT_HIDE dex mapping {:#x} ({} bytes)", map.start(), map.size());
        hidden &= prot_hide::remote_mprotect(proc, map.start(), map.size(), prot | PROT_HIDE)?;
    }
    Ok(hidden)
}

fn is_anonymous_dex_map(path: Option<String>) -> bool {
    let Some(path) = path else {
        return true;
    };
    path.is_empty() || path.contains("memfd") || path.contains("dalvik")
}

fn map_starts(pid: i32) -> HashSet<usize> {
    get_process_maps(pid)
        .map(|maps| maps.iter().map(|map| map.start()).collect())
        .unwrap_or_default()
}

fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) 没有前置条件，失败时返回 -1。
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 { 4096 } else { n as usize }
}

fn align_down(value: usize, page: usize) -> usize {
    value & !(page - 1)
}

fn align_up(value: usize, page: usize) -> usize {
    align_down(value + page - 1, page)
}

fn app_class_loader(jni: &RemoteJni) -> Result<usize> {
    if let Ok(loader) = loader_from_application(jni) {
        return Ok(loader);
    }
    if let Ok(loader) = loader_from_bound_application(jni) {
        return Ok(loader);
    }
    loader_from_current_thread(jni).context("failed to resolve the app ClassLoader")
}

fn loader_from_application(jni: &RemoteJni) -> Result<usize> {
    let at = jni.find_class("android/app/ActivityThread")?;
    let current = jni.get_static_method_id(at, "currentApplication", "()Landroid/app/Application;")?;
    let app = jni.call_static_object(at, current, &[])?;
    if app == 0 {
        bail!("ActivityThread.currentApplication() is null");
    }
    context_class_loader(jni, app)
}

fn loader_from_bound_application(jni: &RemoteJni) -> Result<usize> {
    let at_clz = jni.find_class("android/app/ActivityThread")?;
    let current = jni.get_static_method_id(
        at_clz,
        "currentActivityThread",
        "()Landroid/app/ActivityThread;",
    )?;
    let at = jni.call_static_object(at_clz, current, &[])?;
    if at == 0 {
        bail!("currentActivityThread() is null");
    }

    let bound_id = jni.get_field_id(
        at_clz,
        "mBoundApplication",
        "Landroid/app/ActivityThread$AppBindData;",
    )?;
    let bound = jni.get_object_field(at, bound_id)?;
    if bound == 0 {
        bail!("mBoundApplication is null");
    }

    let data_clz = jni.find_class("android/app/ActivityThread$AppBindData")?;
    let info_id = jni.get_field_id(data_clz, "info", "Landroid/app/LoadedApk;")?;
    let apk = jni.get_object_field(bound, info_id)?;
    if apk == 0 {
        bail!("AppBindData.info is null");
    }

    let apk_clz = jni.find_class("android/app/LoadedApk")?;
    let get = jni.get_method_id(apk_clz, "getClassLoader", "()Ljava/lang/ClassLoader;")?;
    let loader = jni.call_object(apk, get, &[])?;
    if loader == 0 {
        bail!("LoadedApk.getClassLoader() is null");
    }
    Ok(loader)
}

fn loader_from_current_thread(jni: &RemoteJni) -> Result<usize> {
    let th_clz = jni.find_class("java/lang/Thread")?;
    let current = jni.get_static_method_id(th_clz, "currentThread", "()Ljava/lang/Thread;")?;
    let thread = jni.call_static_object(th_clz, current, &[])?;
    if thread == 0 {
        bail!("Thread.currentThread() is null");
    }
    let get = jni.get_method_id(th_clz, "getContextClassLoader", "()Ljava/lang/ClassLoader;")?;
    let loader = jni.call_object(thread, get, &[])?;
    if loader == 0 {
        bail!("Thread.getContextClassLoader() is null");
    }
    Ok(loader)
}

fn context_class_loader(jni: &RemoteJni, ctx: usize) -> Result<usize> {
    let ctx_clz = jni.find_class("android/content/Context")?;
    let get = jni.get_method_id(ctx_clz, "getClassLoader", "()Ljava/lang/ClassLoader;")?;
    let loader = jni.call_object(ctx, get, &[])?;
    if loader == 0 {
        bail!("Context.getClassLoader() is null");
    }
    Ok(loader)
}

fn make_dex_elements(jni: &RemoteJni, buffer: usize, parent: usize) -> Result<usize> {
    match make_in_memory_dex_elements(jni, buffer) {
        Ok(elements) => return Ok(elements),
        Err(e) => warn!("makeInMemoryDexElements failed, falling back: {e:#}"),
    }
    steal_in_memory_loader_elements(jni, buffer, parent)
}

fn make_in_memory_dex_elements(jni: &RemoteJni, buffer: usize) -> Result<usize> {
    let dpl = jni.find_class("dalvik/system/DexPathList")?;
    let make = jni.get_static_method_id(
        dpl,
        "makeInMemoryDexElements",
        "([Ljava/nio/ByteBuffer;Ljava/util/List;)[Ldalvik/system/DexPathList$Element;",
    )?;

    let bb_clz = jni.find_class("java/nio/ByteBuffer")?;
    let buffers = jni.new_object_array(1, bb_clz, 0)?;
    jni.set_object_array_element(buffers, 0, buffer)?;

    let list_clz = jni.find_class("java/util/ArrayList")?;
    let ctor = jni.get_method_id(list_clz, "<init>", "()V")?;
    let suppressed = jni.new_object(list_clz, ctor, &[])?;

    let elements = jni.call_static_object(dpl, make, &[buffers, suppressed])?;
    if elements == 0 {
        bail!("makeInMemoryDexElements returned null");
    }
    if jni.get_array_length(elements)? == 0 {
        bail!("makeInMemoryDexElements returned an empty array");
    }
    Ok(elements)
}

fn steal_in_memory_loader_elements(jni: &RemoteJni, buffer: usize, parent: usize) -> Result<usize> {
    let loader_clz = jni.find_class("dalvik/system/InMemoryDexClassLoader")?;
    let ctor = jni.get_method_id(
        loader_clz,
        "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
    )?;
    let child = jni.new_object(loader_clz, ctor, &[buffer, parent])?;
    let path_list = path_list_of(jni, child)?;
    let elements = dex_elements_of(jni, path_list)?;
    if jni.get_array_length(elements)? == 0 {
        bail!("InMemoryDexClassLoader produced no dexElements");
    }
    Ok(elements)
}

fn merge_dex_elements(jni: &RemoteJni, loader: usize, added: usize) -> Result<()> {
    let path_list = path_list_of(jni, loader)?;
    let old = dex_elements_of(jni, path_list)?;
    let old_len = jni.get_array_length(old)?;
    let add_len = jni.get_array_length(added)?;

    let elem_clz = jni.find_class("dalvik/system/DexPathList$Element")?;
    let merged = jni.new_object_array(old_len + add_len, elem_clz, 0)?;

    for i in 0..add_len {
        let el = jni.get_object_array_element(added, i)?;
        jni.set_object_array_element(merged, i, el)?;
    }
    for i in 0..old_len {
        let el = jni.get_object_array_element(old, i)?;
        jni.set_object_array_element(merged, add_len + i, el)?;
    }

    let dpl = jni.find_class("dalvik/system/DexPathList")?;
    let field = jni.get_field_id(
        dpl,
        "dexElements",
        "[Ldalvik/system/DexPathList$Element;",
    )?;
    jni.set_object_field(path_list, field, merged)?;
    info!("merged {add_len} dexElements into app ClassLoader (was {old_len})");
    Ok(())
}

fn path_list_of(jni: &RemoteJni, loader: usize) -> Result<usize> {
    let bcl = jni.find_class("dalvik/system/BaseDexClassLoader")?;
    let field = jni.get_field_id(bcl, "pathList", "Ldalvik/system/DexPathList;")?;
    let path_list = jni.get_object_field(loader, field)?;
    if path_list == 0 {
        bail!("BaseDexClassLoader.pathList is null");
    }
    Ok(path_list)
}

fn dex_elements_of(jni: &RemoteJni, path_list: usize) -> Result<usize> {
    let dpl = jni.find_class("dalvik/system/DexPathList")?;
    let field = jni.get_field_id(
        dpl,
        "dexElements",
        "[Ldalvik/system/DexPathList$Element;",
    )?;
    let elements = jni.get_object_field(path_list, field)?;
    if elements == 0 {
        bail!("DexPathList.dexElements is null");
    }
    Ok(elements)
}

fn parse_entry(entry: &str) -> Result<(String, String)> {
    let entry = entry.trim();
    if let Some((class, method)) = entry.split_once('#') {
        return require_entry(class, method);
    }
    if let Some((class, method)) = entry.split_once("::") {
        return require_entry(class, method);
    }
    if let Some((class, method)) = entry.rsplit_once('.') {
        return require_entry(class, method);
    }
    bail!("entry must be Class.method, Class#method, or Class::method");
}

fn require_entry(class: &str, method: &str) -> Result<(String, String)> {
    if class.is_empty() || method.is_empty() {
        bail!("entry must be Class.method, Class#method, or Class::method");
    }
    if method.contains('.') || method.contains('#') {
        bail!("entry method must be a simple name: {method}");
    }
    Ok((class.replace('/', "."), method.to_string()))
}

fn invoke_entry(jni: &RemoteJni, loader: usize, class_name: &str, method: &str) -> Result<()> {
    let class_clz = jni.find_class("java/lang/Class")?;
    let for_name = jni.get_static_method_id(
        class_clz,
        "forName",
        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
    )?;
    let jname = jni.new_string_utf(class_name)?;
    let klass = jni.call_static_object(class_clz, for_name, &[jname, 1, loader])?;
    if klass == 0 {
        bail!("Class.forName({class_name}) returned null");
    }

    let mid = jni.get_static_method_id(klass, method, "()V")?;
    jni.call_static_void(klass, mid, &[])?;
    info!("invoked {class_name}.{method}()");
    Ok(())
}
