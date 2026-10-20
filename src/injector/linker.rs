//! 在目标进程里用自带 linker 装载 so。
//!
//! 不调用 `dlopen` / `android_dlopen_ext`，所以这份 so 不会进入系统 soinfo。
//! 映射通过 `PROT_HIDE` 创建。依赖库仍然交给系统 linker 打开，符号用 `dlsym(RTLD_DEFAULT)` 解析。
//! `__cxa_atexit`、`__cxa_thread_atexit` 和 `__register_atfork` 指到隐藏页里的空桩，返回 0，不写入 libc 的回调表。
//! 本模块的 TLS 走 global-dynamic / TLSDESC；initial-exec（`TLS_TPREL`）在进程起来之后无法再插进 bionic 的静态 TLS，遇到就失败。

use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result, bail};
use log::{debug, info};

use crate::elf_image::{
    self, R_AARCH64_ABS64, R_AARCH64_COPY, R_AARCH64_GLOB_DAT, R_AARCH64_IRELATIVE, R_AARCH64_JUMP_SLOT,
    R_AARCH64_RELATIVE, R_AARCH64_TLS_DTPMOD, R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL,
    R_AARCH64_TLSDESC, STT_TLS, SharedObject,
};
use crate::prot_hide;
use crate::ptrace_ex::{find_remote_symbol, remote_mmap, remote_munmap as unmap};
use crate::ptrace_ext::RemoteProcess;

use super::{Injector, LoadResult};

pub struct LinkerInjector;

impl Injector for LinkerInjector {
    fn load(&self, proc: &RemoteProcess, lib_path: &str) -> Result<LoadResult> {
        let data = fs::read(lib_path).with_context(|| format!("Failed to read {lib_path}"))?;
        let object = elf_image::parse(&data)?;
        if let Some(name) = &object.soname {
            info!("custom linker loading {name}");
        }
        load_object(proc, &data, &object)
    }
}

fn load_object(proc: &RemoteProcess, data: &[u8], object: &SharedObject) -> Result<LoadResult> {
    let page = page_size();
    let map_start = align_down(object.min_vaddr, page);
    let map_end = align_up(object.min_vaddr + object.span, page);
    let span = (map_end - map_start) as usize;
    let reserved = prot_hide::remote_mmap_anonymous(proc, span, libc::PROT_NONE, false)?;
    let bias = reserved.addr as u64 - map_start;
    info!("custom linker reserved {span:#x} bytes at {:#x}", reserved.addr);

    let mut ranges = Vec::new();
    let mut runtime_base = None;
    if let Err(err) = (|| -> Result<()> {
        ranges = copy_segments(proc, data, object, bias, page)?;
        let mut runtime = install_runtime(proc, object, bias)?;
        runtime_base = Some(runtime.base);
        ranges.push(runtime.range());
        ensure_needed(proc, &object.needed)?;
        let mut symbols = HashMap::new();
        apply_relocations(proc, object, bias, &mut symbols, &mut runtime)?;
        apply_relr(proc, object, bias)?;
        apply_irelative(proc, object, bias)?;
        call_init(proc, object, bias)?;
        Ok(())
    })() {
        let _ = unmap(proc, reserved.addr, span);
        if let Some(base) = runtime_base {
            let _ = unmap(proc, base, RUNTIME_BLOB.len());
        }
        return Err(err);
    }

    let jni_onload = object
        .dynsyms
        .iter()
        .find(|sym| sym.name == "JNI_OnLoad" && sym.is_defined())
        .map(|sym| (bias + sym.value) as usize);

    Ok(LoadResult {
        handle: reserved.addr,
        base_addr: (bias + object.min_vaddr) as usize,
        maps_search_name: String::new(),
        memfd_fd: None,
        jni_onload,
        ranges,
    })
}

fn copy_segments(
    proc: &RemoteProcess,
    data: &[u8],
    object: &SharedObject,
    bias: u64,
    page: u64,
) -> Result<Vec<super::MappedRange>> {
    let mut ranges = Vec::new();
    for seg in &object.loads {
        let start = align_down(seg.vaddr, page);
        let end = align_up(seg.vaddr + seg.memsz, page);
        let addr = (bias + start) as usize;
        let size = (end - start) as usize;
        let prot = seg.prot;
        prot_hide::remote_mprotect(proc, addr, size, prot, false)?;
        ranges.push(super::MappedRange { start: addr, size, prot });
        if seg.filesz == 0 {
            continue;
        }
        let file_off = seg.offset as usize;
        let file_end = file_off + seg.filesz as usize;
        if file_end > data.len() {
            bail!("PT_LOAD extends past the file");
        }
        let dest = (bias + seg.vaddr) as usize;
        write_chunks(proc, dest, &data[file_off..file_end])?;
        debug!("mapped PT_LOAD {:#x} prot={prot:#x}", dest);
    }
    Ok(ranges)
}

const RUNTIME_BLOB: &[u8] = include_bytes!("runtime_stub.bin");
const OFF_TLS_GET: usize = 0;
const OFF_TLSDESC: usize = 0xb0;
const OFF_CXA: usize = 0x13c;
const OFF_TLSDESC_WEAK: usize = 0x144;
const OFF_DATA: usize = 0x158;
const DATA_KEY: usize = 0;
const DATA_SIZE: usize = 8;
const DATA_TMPL: usize = 24;
const DATA_TMPL_SZ: usize = 32;
const DATA_REAL_TLS: usize = 40;
const DATA_CALLOC: usize = 48;
const DATA_MEMCPY: usize = 56;
const DATA_GETSPEC: usize = 64;
const DATA_SETSPEC: usize = 72;
const DATA_MOD: usize = 80;
const DATA_DESC: usize = 88;
const DESC_STRIDE: usize = 16;
const DESC_SLOTS: usize = 64;
const TLS_MODULE_ID: u64 = 0x1_0000;

struct Runtime {
    base: usize,
    tls_get: usize,
    tlsdesc: usize,
    tlsdesc_weak: usize,
    cxa: usize,
    desc_used: usize,
    module_id: u64,
    range_start: usize,
    range_size: usize,
}

impl Runtime {
    fn range(&self) -> super::MappedRange {
        super::MappedRange {
            start: self.range_start,
            size: self.range_size,
            prot: libc::PROT_READ | libc::PROT_EXEC,
        }
    }
}

fn install_runtime(proc: &RemoteProcess, object: &SharedObject, bias: u64) -> Result<Runtime> {
    let mapped = prot_hide::remote_mmap_anonymous(
        proc,
        RUNTIME_BLOB.len(),
        libc::PROT_READ | libc::PROT_WRITE,
        false,
    )?;
    write_chunks(proc, mapped.addr, RUNTIME_BLOB)?;
    let base = mapped.addr;
    let data = base + OFF_DATA;
    let libc_tls = crate::ptrace_ex::remote_dlsym(proc, 0, "__tls_get_addr").unwrap_or(0);
    let calloc = must_dlsym(proc, "calloc")?;
    let memcpy = must_dlsym(proc, "memcpy")?;
    let getspecific = must_dlsym(proc, "pthread_getspecific")?;
    let setspecific = must_dlsym(proc, "pthread_setspecific")?;
    let key_create = must_dlsym(proc, "pthread_key_create")?;
    let (tmpl, tmpl_sz, memsz) = match &object.tls {
        Some(tls) => ((bias + tls.vaddr) as usize, tls.filesz as usize, tls.memsz as usize),
        None => (0, 0, 0),
    };
    proc.write_mem_io(data + DATA_SIZE, &(memsz as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_TMPL, &(tmpl as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_TMPL_SZ, &(tmpl_sz as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_REAL_TLS, &(libc_tls as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_CALLOC, &(calloc as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_MEMCPY, &(memcpy as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_GETSPEC, &(getspecific as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_SETSPEC, &(setspecific as u64).to_le_bytes())?;
    proc.write_mem_io(data + DATA_MOD, &TLS_MODULE_ID.to_le_bytes())?;
    if object.tls.is_some() {
        let rc = proc.call_function(key_create, &[data + DATA_KEY, 0])?;
        if rc != 0 {
            bail!("pthread_key_create failed: {rc:#x}");
        }
    }
    let page = page_size() as usize;
    let code_end = OFF_DATA.next_multiple_of(page).min(RUNTIME_BLOB.len().next_multiple_of(page));
    prot_hide::remote_mprotect(proc, base, code_end.max(page), libc::PROT_READ | libc::PROT_EXEC, false)?;
    if RUNTIME_BLOB.len() > code_end {
        prot_hide::remote_mprotect(
            proc,
            base + code_end,
            RUNTIME_BLOB.len() - code_end,
            libc::PROT_READ | libc::PROT_WRITE,
            false,
        )?;
    }
    Ok(Runtime {
        base,
        tls_get: base + OFF_TLS_GET,
        tlsdesc: base + OFF_TLSDESC,
        tlsdesc_weak: base + OFF_TLSDESC_WEAK,
        cxa: base + OFF_CXA,
        desc_used: 0,
        module_id: TLS_MODULE_ID,
        range_start: base,
        range_size: code_end.max(page),
    })
}

fn must_dlsym(proc: &RemoteProcess, name: &str) -> Result<usize> {
    let addr = crate::ptrace_ex::remote_dlsym(proc, 0, name)?;
    if addr == 0 {
        bail!("runtime dependency {name} was not found");
    }
    Ok(addr)
}

fn write_chunks(proc: &RemoteProcess, mut addr: usize, data: &[u8]) -> Result<()> {
    const CHUNK: usize = 64 * 1024;
    for piece in data.chunks(CHUNK) {
        proc.write_mem_io(addr, piece)?;
        addr += piece.len();
    }
    Ok(())
}

fn ensure_needed(proc: &RemoteProcess, needed: &[String]) -> Result<()> {
    for name in needed {
        let noload = libc::RTLD_NOW | 4;
        match remote_dlopen_optional(proc, name, noload)? {
            Some(_) => debug!("dependency already loaded: {name}"),
            None => {
                let flags = libc::RTLD_NOW | 0x100;
                remote_dlopen_optional(proc, name, flags)?
                    .with_context(|| format!("failed to load dependency {name}"))?;
                info!("loaded dependency {name}");
            }
        }
    }
    Ok(())
}

fn remote_dlopen_optional(proc: &RemoteProcess, lib_path: &str, flags: i32) -> Result<Option<usize>> {
    let remote_dlopen = find_remote_symbol(proc.pid.as_raw(), "libdl.so", libc::dlopen as usize)?;
    let path_len = lib_path.len() + 1;
    let remote_path = remote_mmap(proc, path_len)?;
    let mut buf = Vec::with_capacity(path_len);
    buf.extend_from_slice(lib_path.as_bytes());
    buf.push(0);
    proc.write_mem(remote_path, &buf)?;
    let handle = proc.call_function(remote_dlopen, &[remote_path, flags as usize])?;
    let _ = unmap(proc, remote_path, path_len);
    if handle == 0 {
        Ok(None)
    } else {
        Ok(Some(handle))
    }
}

fn apply_relocations(
    proc: &RemoteProcess,
    object: &SharedObject,
    bias: u64,
    cache: &mut HashMap<String, usize>,
    runtime: &mut Runtime,
) -> Result<()> {
    for reloc in &object.relocs {
        let location = (bias + reloc.offset) as usize;
        let sym = if reloc.sym == 0 {
            None
        } else {
            Some(
                object
                    .dynsyms
                    .get(reloc.sym as usize)
                    .with_context(|| format!("relocation symbol {} is out of range", reloc.sym))?,
            )
        };
        match reloc.ty {
            R_AARCH64_RELATIVE => {
                let value = bias.wrapping_add(reloc.addend as u64);
                proc.write_mem_io(location, &value.to_le_bytes())?;
            }
            R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT | R_AARCH64_ABS64 => {
                let sym = sym.context("absolute relocation is missing a symbol")?;
                if sym.ty == STT_TLS {
                    bail!("non-TLS relocation against TLS symbol {}", sym.name);
                }
                let resolved = resolve_symbol(proc, object, sym, bias, cache, runtime)?;
                let value = match resolved {
                    Some(addr) => (addr as u64).wrapping_add(reloc.addend as u64),
                    None => 0,
                };
                proc.write_mem_io(location, &value.to_le_bytes())?;
            }
            R_AARCH64_COPY => {
                let sym = sym.context("COPY relocation is missing a symbol")?;
                let resolved = resolve_symbol(proc, object, sym, bias, cache, runtime)?
                    .with_context(|| format!("COPY symbol {} was not found", sym.name))?;
                if sym.size == 0 || sym.size > 1 << 20 {
                    bail!("COPY relocation for {} has size {}", sym.name, sym.size);
                }
                let bytes = proc.read_mem(resolved, sym.size as usize)?;
                proc.write_mem_io(location, &bytes)?;
            }
            R_AARCH64_TLS_DTPMOD => {
                let id = tls_module_id(object, sym)?;
                proc.write_mem_io(location, &id.to_le_bytes())?;
            }
            R_AARCH64_TLS_DTPREL => {
                let sym = sym.context("TLS_DTPREL is missing a symbol")?;
                let value = (sym.value as i64).wrapping_add(reloc.addend) as u64;
                proc.write_mem_io(location, &value.to_le_bytes())?;
            }
            R_AARCH64_TLS_TPREL => {
                bail!(
                    "initial-exec TLS relocation at {:#x} cannot be applied after the process has started",
                    reloc.offset
                );
            }
            R_AARCH64_TLSDESC => apply_tlsdesc(proc, object, sym, reloc.addend, location, runtime)?,
            R_AARCH64_IRELATIVE | 0 => {}
            other => bail!("unsupported relocation type {other:#x} at {:#x}", reloc.offset),
        }
    }
    Ok(())
}

fn tls_module_id(object: &SharedObject, sym: Option<&elf_image::DynSym>) -> Result<u64> {
    match sym {
        Some(sym) if sym.is_defined() => {
            if object.tls.is_none() {
                bail!("TLS relocation but the payload has no PT_TLS");
            }
            Ok(TLS_MODULE_ID)
        }
        Some(sym) if sym.is_weak() => Ok(0),
        Some(sym) => bail!("TLS symbol {} is not defined in the payload", sym.name),
        None => Ok(0),
    }
}

fn apply_tlsdesc(
    proc: &RemoteProcess,
    object: &SharedObject,
    sym: Option<&elf_image::DynSym>,
    addend: i64,
    location: usize,
    runtime: &mut Runtime,
) -> Result<()> {
    let weak = match sym {
        Some(sym) if !sym.is_defined() && sym.is_weak() => true,
        Some(sym) if !sym.is_defined() => bail!("TLSDESC symbol {} is not in the payload", sym.name),
        _ => false,
    };
    if weak {
        let desc = [runtime.tlsdesc_weak as u64, addend as u64];
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&desc[0].to_le_bytes());
        bytes[8..].copy_from_slice(&desc[1].to_le_bytes());
        proc.write_mem_io(location, &bytes)?;
        return Ok(());
    }
    if object.tls.is_none() {
        bail!("TLSDESC but the payload has no PT_TLS");
    }
    if runtime.desc_used >= DESC_SLOTS {
        bail!("too many TLSDESC relocations");
    }
    let offset = (sym.map(|s| s.value).unwrap_or(0) as i64).wrapping_add(addend) as u64;
    let arg = runtime.base + OFF_DATA + DATA_DESC + runtime.desc_used * DESC_STRIDE;
    runtime.desc_used += 1;
    proc.write_mem_io(arg, &TLS_MODULE_ID.to_le_bytes())?;
    proc.write_mem_io(arg + 8, &offset.to_le_bytes())?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(runtime.tlsdesc as u64).to_le_bytes());
    bytes[8..].copy_from_slice(&(arg as u64).to_le_bytes());
    proc.write_mem_io(location, &bytes)?;
    Ok(())
}

fn apply_relr(proc: &RemoteProcess, object: &SharedObject, bias: u64) -> Result<()> {
    for vaddr in elf_image::relr_addresses(&object.relr) {
        let location = (bias + vaddr) as usize;
        let bytes = proc.read_mem(location, 8)?;
        let addend = u64::from_le_bytes(bytes.try_into().expect("8 reloc bytes"));
        let value = addend.wrapping_add(bias);
        proc.write_mem_io(location, &value.to_le_bytes())?;
    }
    Ok(())
}

fn apply_irelative(proc: &RemoteProcess, object: &SharedObject, bias: u64) -> Result<()> {
    for reloc in object.relocs.iter().filter(|r| r.ty == R_AARCH64_IRELATIVE) {
        let resolver = (bias.wrapping_add(reloc.addend as u64)) as usize;
        let resolved = proc
            .call_function(resolver, &[])
            .with_context(|| format!("IRELATIVE resolver at {resolver:#x} failed"))?;
        let location = (bias + reloc.offset) as usize;
        proc.write_mem_io(location, &resolved.to_le_bytes())?;
    }
    Ok(())
}

fn call_init(proc: &RemoteProcess, object: &SharedObject, bias: u64) -> Result<()> {
    if let Some(init) = object.init {
        let addr = (bias + init) as usize;
        debug!("calling DT_INIT {addr:#x}");
        proc.call_function(addr, &[])?;
    }
    let Some(array) = &object.init_array else {
        return Ok(());
    };
    let count = (array.bytes / 8) as usize;
    let base = (bias + array.vaddr) as usize;
    for i in 0..count {
        let slot = proc.read_mem(base + i * 8, 8)?;
        let func = u64::from_le_bytes(slot.try_into().expect("8 init bytes")) as usize;
        if func == 0 {
            continue;
        }
        debug!("calling init_array[{i}] {func:#x}");
        proc.call_function(func, &[])?;
    }
    Ok(())
}

fn resolve_symbol(
    proc: &RemoteProcess,
    object: &SharedObject,
    sym: &elf_image::DynSym,
    bias: u64,
    cache: &mut HashMap<String, usize>,
    runtime: &Runtime,
) -> Result<Option<usize>> {
    if sym.is_defined() {
        let addr = if sym.is_absolute() {
            sym.value as usize
        } else {
            (bias + sym.value) as usize
        };
        return Ok(Some(addr));
    }
    if sym.name.is_empty() {
        return Ok(None);
    }
    if let Some(addr) = hooked_symbol(&sym.name, runtime) {
        return Ok(Some(addr));
    }
    if let Some(addr) = cache.get(&sym.name) {
        return Ok(Some(*addr));
    }
    if let Some(local) = object
        .dynsyms
        .iter()
        .find(|item| item.name == sym.name && item.is_defined())
    {
        let addr = (bias + local.value) as usize;
        cache.insert(sym.name.clone(), addr);
        return Ok(Some(addr));
    }
    match crate::ptrace_ex::remote_dlsym(proc, 0, &sym.name) {
        Ok(addr) if addr != 0 => {
            cache.insert(sym.name.clone(), addr);
            Ok(Some(addr))
        }
        _ if sym.is_weak() => Ok(None),
        _ => bail!("undefined symbol {}", sym.name),
    }
}

fn hooked_symbol(name: &str, runtime: &Runtime) -> Option<usize> {
    match name {
        "__tls_get_addr" => Some(runtime.tls_get),
        "__cxa_atexit" | "atexit" | "__cxa_thread_atexit" | "__cxa_thread_atexit_impl" | "__register_atfork" => {
            Some(runtime.cxa)
        }
        _ => None,
    }
}

fn page_size() -> u64 {
    // SAFETY: sysconf(_SC_PAGESIZE) 没有前置条件，失败时返回 -1。
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 { 4096 } else { n as u64 }
}

fn align_down(value: u64, page: u64) -> u64 {
    value & !(page - 1)
}

fn align_up(value: u64, page: u64) -> u64 {
    align_down(value + page - 1, page)
}
