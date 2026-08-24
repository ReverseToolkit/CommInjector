use crate::ptrace_ex::{remote_mmap, remote_munmap};
use crate::ptrace_ext::RemoteProcess;
use crate::remote_jni::RemoteJni;
use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
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

pub fn inject_dex(proc: &RemoteProcess, dex_path: &str) -> Result<InjectedInfo> {
    let dex_data = fs::read(dex_path).with_context(|| format!("Failed to read dex: {dex_path}"))?;
    if dex_data.len() < 0x70 || &dex_data[0..4] != b"dex\n" {
        bail!("Invalid dex file: {dex_path}");
    }

    let class_names = dex_class_names(&dex_data);
    info!(
        "DEX payload {} ({} bytes, {} classes)",
        dex_path,
        dex_data.len(),
        class_names.len()
    );

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

        let loaded = load_dex_classes(&jni, loader, &class_names)?;
        info!("loaded {loaded} classes into the app ClassLoader");
        Ok(())
    })();

    if let Err(e) = result {
        let _ = remote_munmap(proc, remote_dex, dex_data.len());
        return Err(e);
    }

    Ok(InjectedInfo {
        dl_handle: 0,
        base_addr: remote_dex,
        hider_results: Vec::new(),
    })
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

fn load_dex_classes(jni: &RemoteJni, loader: usize, names: &[String]) -> Result<usize> {
    let class_clz = jni.find_class("java/lang/Class")?;
    let for_name = jni.get_static_method_id(
        class_clz,
        "forName",
        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
    )?;

    let mut loaded = 0usize;
    for name in names {
        let jname = match jni.new_string_utf(name) {
            Ok(v) => v,
            Err(e) => {
                warn!("NewStringUTF({name}) failed: {e:#}");
                continue;
            }
        };
        match jni.call_static_object(class_clz, for_name, &[jname, 1, loader]) {
            Ok(klass) if klass != 0 => {
                debug!("loaded class {name}");
                loaded += 1;
            }
            Ok(_) => warn!("Class.forName({name}) returned null"),
            Err(e) => warn!("Class.forName({name}) failed: {e:#}"),
        }
    }
    Ok(loaded)
}

fn dex_class_names(dex: &[u8]) -> Vec<String> {
    if dex.len() < 0x70 {
        return Vec::new();
    }
    let string_ids_off = u32::from_le_bytes(dex[0x24..0x28].try_into().unwrap()) as usize;
    let type_ids_off = u32::from_le_bytes(dex[0x2c..0x30].try_into().unwrap()) as usize;
    let class_defs_size = u32::from_le_bytes(dex[0x38..0x3c].try_into().unwrap()) as usize;
    let class_defs_off = u32::from_le_bytes(dex[0x3c..0x40].try_into().unwrap()) as usize;

    let mut names = Vec::new();
    for i in 0..class_defs_size {
        let item = class_defs_off + i * 32;
        if item + 4 > dex.len() || type_ids_off + 4 > dex.len() {
            break;
        }
        let class_idx = u32::from_le_bytes(dex[item..item + 4].try_into().unwrap()) as usize;
        let type_off = type_ids_off + class_idx * 4;
        if type_off + 4 > dex.len() {
            continue;
        }
        let descriptor_idx = u32::from_le_bytes(dex[type_off..type_off + 4].try_into().unwrap()) as usize;
        if let Some(desc) = dex_string(dex, string_ids_off, descriptor_idx) {
            if let Some(name) = descriptor_to_name(desc) {
                names.push(name);
            }
        }
    }
    names
}

fn dex_string(dex: &[u8], string_ids_off: usize, idx: usize) -> Option<&str> {
    let id_off = string_ids_off + idx * 4;
    if id_off + 4 > dex.len() {
        return None;
    }
    let data_off = u32::from_le_bytes(dex[id_off..id_off + 4].try_into().unwrap()) as usize;
    if data_off >= dex.len() {
        return None;
    }
    let (utf16_size, hdr) = read_uleb128(&dex[data_off..])?;
    let start = data_off + hdr;
    if utf16_size == 0 || start >= dex.len() {
        return None;
    }
    let end = dex[start..].iter().position(|&b| b == 0).unwrap_or(0);
    std::str::from_utf8(&dex[start..start + end]).ok()
}

fn read_uleb128(data: &[u8]) -> Option<(u32, usize)> {
    let mut value = 0u32;
    let mut shift = 0;
    for (i, b) in data.iter().enumerate().take(5) {
        value |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

fn descriptor_to_name(descriptor: &str) -> Option<String> {
    if !descriptor.starts_with('L') || !descriptor.ends_with(';') || descriptor.len() < 3 {
        return None;
    }
    Some(descriptor[1..descriptor.len() - 1].replace('/', "."))
}
