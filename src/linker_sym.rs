use anyhow::{Context, Result, bail};
use std::fs;
use xdl_rs::safe::{XdlLibrary, XdlOpenFlags};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;

/// 从 linker 镜像解析符号，返回相对 load base 的偏移
pub struct LinkerSyms {
    pub soinfo_unload: usize,
    pub find_containing_library: usize,
    pub pdg_ctor: usize,
    pub pdg_dtor: usize,
}

pub fn resolve(linker_path: &str) -> Result<LinkerSyms> {
    let llvm_suffix = detect_llvm_suffix(linker_path)?;

    let soinfo_unload = find_symbol_offset(linker_path, &format!("__dl__ZL13soinfo_unloadP6soinfo{llvm_suffix}"))?
        .or_else(|| find_symbol_by_prefix(linker_path, "__dl__ZL13soinfo_unloadP6soinfo").ok().flatten())
        .context("soinfo_unload symbol not found")?;

    let find_containing_library =
        find_symbol_offset(linker_path, &format!("__dl__Z23find_containing_libraryPKv{llvm_suffix}"))?
            .or_else(|| find_symbol_by_prefix(linker_path, "__dl__Z23find_containing_libraryPKv").ok().flatten())
            .context("find_containing_library symbol not found")?;

    let pdg_ctor = find_symbol_offset(linker_path, &format!("__dl__ZN18ProtectedDataGuardC2Ev{llvm_suffix}"))?
        .or_else(|| find_symbol_by_prefix(linker_path, "__dl__ZN18ProtectedDataGuardC2Ev").ok().flatten())
        .context("ProtectedDataGuard ctor not found")?;

    let pdg_dtor = find_symbol_offset(linker_path, &format!("__dl__ZN18ProtectedDataGuardD2Ev{llvm_suffix}"))?
        .or_else(|| find_symbol_by_prefix(linker_path, "__dl__ZN18ProtectedDataGuardD2Ev").ok().flatten())
        .context("ProtectedDataGuard dtor not found")?;

    Ok(LinkerSyms {
        soinfo_unload,
        find_containing_library,
        pdg_ctor,
        pdg_dtor,
    })
}

/// Android 15+ linker 符号可能带 `.llvm.xxx` 后缀，从 somain 推导
fn detect_llvm_suffix(linker_path: &str) -> Result<String> {
    const SOMAIN_PREFIX: &str = "__dl__ZL6somain";
    const SOLINKER_PREFIX: &str = "__dl__ZL8solinker";

    let full = find_symbol_name_by_prefix(linker_path, SOMAIN_PREFIX)?
        .or_else(|| find_symbol_name_by_prefix(linker_path, SOLINKER_PREFIX).ok().flatten())
        .unwrap_or_else(|| SOMAIN_PREFIX.to_string());

    let base_len = if full.starts_with(SOLINKER_PREFIX) {
        SOLINKER_PREFIX.len()
    } else {
        SOMAIN_PREFIX.len()
    };

    if full.len() <= base_len {
        return Ok(String::new());
    }
    Ok(full[base_len..].to_string())
}

fn find_symbol_name_by_prefix(linker_path: &str, prefix: &str) -> Result<Option<String>> {
    let data = fs::read(linker_path).context("Failed to read linker")?;
    let mut found = None;
    find_symbol_value(&data, |name| {
        if found.is_none() && name.starts_with(prefix) {
            found = Some(name.to_string());
        }
        false
    })?;
    Ok(found)
}

fn find_symbol_offset(linker_path: &str, exact: &str) -> Result<Option<usize>> {
    let data = fs::read(linker_path).context("Failed to read linker")?;
    let sym_value = match find_symbol_value(&data, |name| name == exact)? {
        Some(v) => v,
        None => return Ok(None),
    };
    Ok(Some(sym_value_to_offset(linker_path, sym_value)?))
}

fn find_symbol_by_prefix(linker_path: &str, prefix: &str) -> Result<Option<usize>> {
    let data = fs::read(linker_path).context("Failed to read linker")?;
    let sym_value = match find_symbol_value(&data, |name| name.starts_with(prefix))? {
        Some(v) => v,
        None => return Ok(None),
    };
    Ok(Some(sym_value_to_offset(linker_path, sym_value)?))
}

fn sym_value_to_offset(linker_path: &str, sym_value: u64) -> Result<usize> {
    let lib = XdlLibrary::open(linker_path, XdlOpenFlags::TryForceLoad)
        .map_err(|e| anyhow::anyhow!("xdl_open({linker_path}) failed: {e}"))?;
    let base = lib.info().map_err(|e| anyhow::anyhow!("xdl_info failed: {e}"))?.base_addr as u64;
    Ok(sym_value.saturating_sub(base) as usize)
}

fn find_symbol_value(data: &[u8], mut pred: impl FnMut(&str) -> bool) -> Result<Option<u64>> {
    if data.len() < 64 || data[..4] != ELF_MAGIC {
        bail!("Invalid ELF");
    }
    if data[4] != 2 {
        bail!("Only ELF64 linker is supported");
    }

    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(data[62..64].try_into().unwrap()) as usize;

    if e_shoff + e_shentsize * e_shnum > data.len() || e_shstrndx >= e_shnum {
        bail!("Invalid ELF section headers");
    }

    for i in 0..e_shnum {
        let sh_type = section_type(data, e_shoff, e_shentsize, i);
        if sh_type != SHT_SYMTAB && sh_type != SHT_DYNSYM {
            continue;
        }
        let sym_off = section_offset(data, e_shoff, e_shentsize, i);
        let sym_size = section_size(data, e_shoff, e_shentsize, i);
        let sym_entsize = section_entsize(data, e_shoff, e_shentsize, i).max(24);
        let strtab_idx = section_link(data, e_shoff, e_shentsize, i);
        let strtab_off = section_offset(data, e_shoff, e_shentsize, strtab_idx);
        let strtab_size = section_size(data, e_shoff, e_shentsize, strtab_idx);
        let strtab = &data[strtab_off..strtab_off + strtab_size];

        let count = sym_size / sym_entsize;
        for j in 0..count {
            let off = sym_off + j * sym_entsize;
            if off + 24 > data.len() {
                break;
            }
            let st_name = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            if st_name == 0 || st_name >= strtab.len() {
                continue;
            }
            let name = read_cstr(strtab, st_name);
            if pred(name) {
                return Ok(Some(st_value));
            }
        }
    }
    Ok(None)
}

fn section_header(data: &[u8], e_shoff: usize, e_shentsize: usize, idx: usize) -> usize {
    e_shoff + idx * e_shentsize
}

fn section_type(data: &[u8], e_shoff: usize, e_shentsize: usize, idx: usize) -> u32 {
    let off = section_header(data, e_shoff, e_shentsize, idx);
    u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap())
}

fn section_offset(data: &[u8], e_shoff: usize, e_shentsize: usize, idx: usize) -> usize {
    let off = section_header(data, e_shoff, e_shentsize, idx);
    u64::from_le_bytes(data[off + 24..off + 32].try_into().unwrap()) as usize
}

fn section_size(data: &[u8], e_shoff: usize, e_shentsize: usize, idx: usize) -> usize {
    let off = section_header(data, e_shoff, e_shentsize, idx);
    u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap()) as usize
}

fn section_link(data: &[u8], e_shoff: usize, e_shentsize: usize, idx: usize) -> usize {
    let off = section_header(data, e_shoff, e_shentsize, idx);
    u32::from_le_bytes(data[off + 40..off + 44].try_into().unwrap()) as usize
}

fn section_entsize(data: &[u8], e_shoff: usize, e_shentsize: usize, idx: usize) -> usize {
    let off = section_header(data, e_shoff, e_shentsize, idx);
    u64::from_le_bytes(data[off + 56..off + 64].try_into().unwrap()) as usize
}

fn read_cstr(buf: &[u8], start: usize) -> &str {
    let end = buf[start..].iter().position(|&b| b == 0).unwrap_or(0);
    std::str::from_utf8(&buf[start..start + end]).unwrap_or("")
}
