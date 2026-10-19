//! 解析要注入的 ELF64 / AArch64 共享对象，供远程 linker 使用。
//!
//! 只接受 `ET_DYN`。`PT_TLS` 记下来，由运行时按 global-dynamic / TLSDESC 分配，不并进 bionic 的静态 TLS。

use anyhow::{Context, Result, bail};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_TLS: u32 = 7;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_SONAME: i64 = 14;
const DT_JMPREL: i64 = 23;
const DT_INIT_ARRAY: i64 = 25;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_TEXTREL: i64 = 22;
const DT_PLTREL: i64 = 20;
const DT_PLTRELSZ: i64 = 2;
const DT_RELRSZ: i64 = 35;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELR: i64 = 36;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_ANDROID_REL: i64 = 0x6000_000f;
const DT_ANDROID_RELSZ: i64 = 0x6000_0010;
const DT_ANDROID_RELA: i64 = 0x6000_0011;
const DT_ANDROID_RELASZ: i64 = 0x6000_0012;
const STB_WEAK: u8 = 2;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;

pub const R_AARCH64_COPY: u32 = 1024;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_TLS_DTPMOD: u32 = 1028;
pub const R_AARCH64_TLS_DTPREL: u32 = 1029;
pub const R_AARCH64_TLS_TPREL: u32 = 1030;
pub const R_AARCH64_TLSDESC: u32 = 1031;
pub const R_AARCH64_IRELATIVE: u32 = 1032;

pub struct SharedObject {
    pub loads: Vec<Segment>,
    pub min_vaddr: u64,
    pub span: u64,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub relocs: Vec<Rela>,
    pub relr: Vec<u64>,
    pub init: Option<u64>,
    pub init_array: Option<InitArray>,
    pub dynsyms: Vec<DynSym>,
    pub tls: Option<TlsSegment>,
}

pub struct TlsSegment {
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

pub struct Segment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub prot: i32,
}

pub struct Rela {
    pub offset: u64,
    pub ty: u32,
    pub sym: u32,
    pub addend: i64,
}

pub struct DynSym {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub shndx: u16,
    pub bind: u8,
    pub ty: u8,
}

pub const STT_TLS: u8 = 6;

pub struct InitArray {
    pub vaddr: u64,
    pub bytes: u64,
}

impl DynSym {
    pub fn is_defined(&self) -> bool {
        self.shndx != SHN_UNDEF
    }

    pub fn is_weak(&self) -> bool {
        self.bind == STB_WEAK
    }

    pub fn is_absolute(&self) -> bool {
        self.shndx == SHN_ABS
    }
}

pub fn parse(data: &[u8]) -> Result<SharedObject> {
    if data.len() < 64 || data[..4] != ELF_MAGIC {
        bail!("payload is not an ELF");
    }
    if data[4] != 2 || data[5] != 1 {
        bail!("only ELF64 little-endian is supported");
    }
    let e_type = read_u16(data, 16)?;
    let e_machine = read_u16(data, 18)?;
    if e_type != ET_DYN {
        bail!("payload is not a shared object (e_type={e_type})");
    }
    if e_machine != EM_AARCH64 {
        bail!("payload is not AArch64 (e_machine={e_machine})");
    }

    let phoff = read_u64(data, 32)? as usize;
    let phentsize = read_u16(data, 54)? as usize;
    let phnum = read_u16(data, 56)? as usize;
    if phentsize < 56 {
        bail!("unexpected program header size {phentsize}");
    }

    let mut loads = Vec::new();
    let mut dynamic_off = None;
    let mut dynamic_size = 0usize;
    let mut tls = None;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = read_u32(data, off)?;
        let p_flags = read_u32(data, off + 4)?;
        let p_offset = read_u64(data, off + 8)?;
        let p_vaddr = read_u64(data, off + 16)?;
        let p_filesz = read_u64(data, off + 32)?;
        let p_memsz = read_u64(data, off + 40)?;
        match p_type {
            PT_LOAD => loads.push(Segment {
                vaddr: p_vaddr,
                offset: p_offset,
                filesz: p_filesz,
                memsz: p_memsz,
                prot: prot_from_flags(p_flags),
            }),
            PT_DYNAMIC => {
                dynamic_off = Some(p_offset as usize);
                dynamic_size = p_filesz as usize;
            }
            PT_TLS if p_memsz > 0 => {
                tls = Some(TlsSegment {
                    vaddr: p_vaddr,
                    filesz: p_filesz,
                    memsz: p_memsz,
                    align: read_u64(data, off + 48).unwrap_or(8).max(8),
                });
            }
            _ => {}
        }
    }
    if loads.is_empty() {
        bail!("ELF has no PT_LOAD");
    }
    let min_vaddr = loads.iter().map(|s| s.vaddr).min().unwrap_or(0);
    let max_vaddr = loads
        .iter()
        .map(|s| s.vaddr.saturating_add(s.memsz))
        .max()
        .unwrap_or(0);
    let span = max_vaddr.saturating_sub(min_vaddr);
    if span == 0 {
        bail!("ELF load span is empty");
    }

    let dyn_off = dynamic_off.context("ELF has no PT_DYNAMIC")?;
    let dynamic = parse_dynamic(data, dyn_off, dynamic_size, &loads)?;
    Ok(SharedObject {
        loads,
        min_vaddr,
        span,
        needed: dynamic.needed,
        soname: dynamic.soname,
        relocs: dynamic.relocs,
        relr: dynamic.relr,
        init: dynamic.init,
        init_array: dynamic.init_array,
        dynsyms: dynamic.dynsyms,
        tls,
    })
}

struct ParsedDynamic {
    needed: Vec<String>,
    soname: Option<String>,
    relocs: Vec<Rela>,
    relr: Vec<u64>,
    init: Option<u64>,
    init_array: Option<InitArray>,
    dynsyms: Vec<DynSym>,
}

struct DynRaw {
    strtab: u64,
    symtab: u64,
    strsz: u64,
    syment: u64,
    hash: u64,
    gnu_hash: u64,
    rela: u64,
    relasz: u64,
    rel: u64,
    relsz: u64,
    android_rela: u64,
    android_relasz: u64,
    android_rel: u64,
    android_relsz: u64,
    jmprel: u64,
    pltrelsz: u64,
    pltrel: u64,
    relr: u64,
    relrsz: u64,
    init: u64,
    init_array: u64,
    init_arraysz: u64,
    needed: Vec<u64>,
    soname: u64,
}

fn parse_dynamic(data: &[u8], off: usize, size: usize, loads: &[Segment]) -> Result<ParsedDynamic> {
    let mut raw = DynRaw {
        strtab: 0,
        symtab: 0,
        strsz: 0,
        syment: 24,
        hash: 0,
        gnu_hash: 0,
        rela: 0,
        relasz: 0,
        rel: 0,
        relsz: 0,
        android_rela: 0,
        android_relasz: 0,
        android_rel: 0,
        android_relsz: 0,
        jmprel: 0,
        pltrelsz: 0,
        pltrel: 0,
        relr: 0,
        relrsz: 0,
        init: 0,
        init_array: 0,
        init_arraysz: 0,
        needed: Vec::new(),
        soname: 0,
    };
    let end = off.saturating_add(size).min(data.len());
    let mut cursor = off;
    while cursor + 16 <= end {
        let tag = read_i64(data, cursor)?;
        let val = read_u64(data, cursor + 8)?;
        cursor += 16;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_NEEDED => raw.needed.push(val),
            DT_STRTAB => raw.strtab = val,
            DT_SYMTAB => raw.symtab = val,
            DT_STRSZ => raw.strsz = val,
            DT_SYMENT => raw.syment = val,
            DT_HASH => raw.hash = val,
            DT_GNU_HASH => raw.gnu_hash = val,
            DT_RELA => raw.rela = val,
            DT_RELASZ => raw.relasz = val,
            DT_REL => raw.rel = val,
            DT_RELSZ => raw.relsz = val,
            DT_ANDROID_RELA => raw.android_rela = val,
            DT_ANDROID_RELASZ => raw.android_relasz = val,
            DT_ANDROID_REL => raw.android_rel = val,
            DT_ANDROID_RELSZ => raw.android_relsz = val,
            DT_JMPREL => raw.jmprel = val,
            DT_PLTRELSZ => raw.pltrelsz = val,
            DT_PLTREL => raw.pltrel = val,
            DT_RELR => raw.relr = val,
            DT_RELRSZ => raw.relrsz = val,
            DT_INIT => raw.init = val,
            DT_INIT_ARRAY => raw.init_array = val,
            DT_INIT_ARRAYSZ => raw.init_arraysz = val,
            DT_SONAME => raw.soname = val,
            DT_TEXTREL => {}
            _ => {}
        }
    }
    if raw.strtab == 0 || raw.symtab == 0 {
        bail!("ELF dynamic segment has no symbol table");
    }
    let str_off = vaddr_to_offset(loads, raw.strtab)?;
    let strsz = raw.strsz as usize;
    if str_off + strsz > data.len() {
        bail!("dynamic string table is out of range");
    }
    let strtab = &data[str_off..str_off + strsz];
    let sym_count = symbol_count(data, loads, raw.hash, raw.gnu_hash)?;
    let syment = if raw.syment == 0 { 24 } else { raw.syment as usize };
    let sym_off = vaddr_to_offset(loads, raw.symtab)?;
    let mut dynsyms = Vec::with_capacity(sym_count);
    for i in 0..sym_count {
        let off = sym_off + i * syment;
        let name_off = read_u32(data, off)? as usize;
        let info = *data.get(off + 4).context("dynsym truncated")?;
        let shndx = read_u16(data, off + 6)?;
        let value = read_u64(data, off + 8)?;
        let size = read_u64(data, off + 16)?;
        dynsyms.push(DynSym {
            name: cstr_at(strtab, name_off).unwrap_or_default(),
            value,
            size,
            shndx,
            bind: info >> 4,
            ty: info & 0xf,
        });
    }

    let mut relocs = if raw.android_relasz != 0 {
        read_packed(data, loads, raw.android_rela, raw.android_relasz, true)?
    } else {
        read_rela(data, loads, raw.rela, raw.relasz)?
    };
    if raw.android_relsz != 0 {
        relocs.extend(read_packed(data, loads, raw.android_rel, raw.android_relsz, false)?);
    } else {
        relocs.extend(read_rel(data, loads, raw.rel, raw.relsz)?);
    }
    if raw.jmprel != 0 && raw.pltrelsz != 0 {
        let inside_rela = raw.pltrel == DT_RELA as u64
            && range_covered(raw.rela, raw.relasz, raw.jmprel, raw.pltrelsz);
        let inside_rel = raw.pltrel == DT_REL as u64 && range_covered(raw.rel, raw.relsz, raw.jmprel, raw.pltrelsz);
        if !inside_rela && !inside_rel {
            if raw.pltrel == DT_REL as u64 {
                relocs.extend(read_rel(data, loads, raw.jmprel, raw.pltrelsz)?);
            } else {
                relocs.extend(read_rela(data, loads, raw.jmprel, raw.pltrelsz)?);
            }
        }
    }
    let relr = read_words(data, loads, raw.relr, raw.relrsz)?;
    let needed = raw
        .needed
        .into_iter()
        .map(|off| cstr_at(strtab, off as usize).context("DT_NEEDED string is out of range"))
        .collect::<Result<Vec<_>>>()?;
    let soname = if raw.soname == 0 {
        None
    } else {
        Some(cstr_at(strtab, raw.soname as usize).context("DT_SONAME is out of range")?)
    };
    let init = if raw.init == 0 { None } else { Some(raw.init) };
    let init_array = if raw.init_array == 0 || raw.init_arraysz == 0 {
        None
    } else {
        Some(InitArray {
            vaddr: raw.init_array,
            bytes: raw.init_arraysz,
        })
    };
    Ok(ParsedDynamic {
        needed,
        soname,
        relocs,
        relr,
        init,
        init_array,
        dynsyms,
    })
}

fn range_covered(outer: u64, outer_size: u64, inner: u64, inner_size: u64) -> bool {
    inner >= outer && inner.saturating_add(inner_size) <= outer.saturating_add(outer_size)
}

fn read_rela(data: &[u8], loads: &[Segment], vaddr: u64, size: u64) -> Result<Vec<Rela>> {
    if vaddr == 0 || size == 0 {
        return Ok(Vec::new());
    }
    let off = vaddr_to_offset(loads, vaddr)?;
    let bytes = size as usize;
    if off + bytes > data.len() || bytes % 24 != 0 {
        bail!("RELA table is truncated");
    }
    let mut out = Vec::with_capacity(bytes / 24);
    for i in 0..(bytes / 24) {
        let at = off + i * 24;
        let info = read_u64(data, at + 8)?;
        out.push(Rela {
            offset: read_u64(data, at)?,
            ty: info as u32,
            sym: (info >> 32) as u32,
            addend: read_i64(data, at + 16)?,
        });
    }
    Ok(out)
}

fn read_rel(data: &[u8], loads: &[Segment], vaddr: u64, size: u64) -> Result<Vec<Rela>> {
    if vaddr == 0 || size == 0 {
        return Ok(Vec::new());
    }
    let off = vaddr_to_offset(loads, vaddr)?;
    let bytes = size as usize;
    if off + bytes > data.len() || bytes % 16 != 0 {
        bail!("REL table is truncated");
    }
    let mut out = Vec::with_capacity(bytes / 16);
    for i in 0..(bytes / 16) {
        let at = off + i * 16;
        let info = read_u64(data, at + 8)?;
        out.push(Rela {
            offset: read_u64(data, at)?,
            ty: info as u32,
            sym: (info >> 32) as u32,
            addend: 0,
        });
    }
    Ok(out)
}

fn read_packed(data: &[u8], loads: &[Segment], vaddr: u64, size: u64, rela: bool) -> Result<Vec<Rela>> {
    if vaddr == 0 || size == 0 {
        return Ok(Vec::new());
    }
    let off = vaddr_to_offset(loads, vaddr)?;
    let bytes = size as usize;
    let blob = data.get(off..off + bytes).context("packed reloc table is truncated")?;
    if blob.len() < 4 || &blob[..4] != b"APS2" {
        bail!("android packed reloc table is not APS2");
    }
    decode_aps2(&blob[4..], rela)
}

const GROUPED_BY_INFO: u64 = 1;
const GROUPED_BY_OFFSET_DELTA: u64 = 2;
const GROUPED_BY_ADDEND: u64 = 4;
const GROUP_HAS_ADDEND: u64 = 8;

fn decode_aps2(data: &[u8], rela: bool) -> Result<Vec<Rela>> {
    let mut cur = 0usize;
    let pop = |cur: &mut usize| -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *data.get(*cur).context("packed reloc ended early")?;
            *cur += 1;
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    value |= !0u64 << shift;
                }
                return Ok(value);
            }
        }
    };
    let num = pop(&mut cur)?;
    let mut reloc_offset = pop(&mut cur)?;
    let mut reloc_info = 0u64;
    let mut reloc_addend = 0i64;
    let mut out = Vec::new();
    let mut idx = 0u64;
    while idx < num {
        let group_size = pop(&mut cur)?;
        let flags = pop(&mut cur)?;
        let offset_delta = if flags & GROUPED_BY_OFFSET_DELTA != 0 {
            pop(&mut cur)?
        } else {
            0
        };
        if flags & GROUPED_BY_INFO != 0 {
            reloc_info = pop(&mut cur)?;
        }
        let add_flags = flags & (GROUP_HAS_ADDEND | GROUPED_BY_ADDEND);
        if rela && add_flags == (GROUP_HAS_ADDEND | GROUPED_BY_ADDEND) {
            reloc_addend = reloc_addend.wrapping_add(pop(&mut cur)? as i64);
        } else if add_flags != GROUP_HAS_ADDEND {
            reloc_addend = 0;
        }
        for _ in 0..group_size {
            if flags & GROUPED_BY_OFFSET_DELTA != 0 {
                reloc_offset = reloc_offset.wrapping_add(offset_delta);
            } else {
                reloc_offset = reloc_offset.wrapping_add(pop(&mut cur)?);
            }
            if flags & GROUPED_BY_INFO == 0 {
                reloc_info = pop(&mut cur)?;
            }
            if rela && add_flags == GROUP_HAS_ADDEND {
                reloc_addend = reloc_addend.wrapping_add(pop(&mut cur)? as i64);
            }
            out.push(Rela {
                offset: reloc_offset,
                ty: reloc_info as u32,
                sym: (reloc_info >> 32) as u32,
                addend: reloc_addend,
            });
        }
        idx += group_size;
    }
    Ok(out)
}

fn read_words(data: &[u8], loads: &[Segment], vaddr: u64, size: u64) -> Result<Vec<u64>> {
    if vaddr == 0 || size == 0 {
        return Ok(Vec::new());
    }
    let off = vaddr_to_offset(loads, vaddr)?;
    let bytes = size as usize;
    if off + bytes > data.len() || bytes % 8 != 0 {
        bail!("RELR table is truncated");
    }
    let mut out = Vec::with_capacity(bytes / 8);
    for i in 0..(bytes / 8) {
        out.push(read_u64(data, off + i * 8)?);
    }
    Ok(out)
}

/// RELR 里每个需要加 load bias 的虚拟地址。
pub fn relr_addresses(relr: &[u64]) -> Vec<u64> {
    let mut where_ = 0u64;
    let mut out = Vec::new();
    for &entry in relr {
        if entry & 1 == 0 {
            where_ = entry;
            out.push(where_);
            where_ = where_.saturating_add(8);
        } else {
            // bit 0 是奇数标记。右移之后，第 i 位对应 where + i*8。
            let mut bitmap = entry >> 1;
            let mut index = 0u64;
            while bitmap != 0 {
                if bitmap & 1 == 1 {
                    out.push(where_.saturating_add(index * 8));
                }
                bitmap >>= 1;
                index += 1;
            }
            where_ = where_.saturating_add(63 * 8);
        }
    }
    out
}

fn symbol_count(data: &[u8], loads: &[Segment], hash: u64, gnu_hash: u64) -> Result<usize> {
    if hash != 0 {
        let off = vaddr_to_offset(loads, hash)?;
        let nchain = read_u32(data, off + 4)? as usize;
        if nchain > 0 {
            return Ok(nchain);
        }
    }
    if gnu_hash != 0 {
        return gnu_hash_count(data, loads, gnu_hash);
    }
    bail!("ELF has neither DT_HASH nor DT_GNU_HASH");
}

fn gnu_hash_count(data: &[u8], loads: &[Segment], gnu_hash: u64) -> Result<usize> {
    let off = vaddr_to_offset(loads, gnu_hash)?;
    let nbuckets = read_u32(data, off)? as usize;
    let symoffset = read_u32(data, off + 4)? as usize;
    let bloom_size = read_u32(data, off + 8)? as usize;
    let buckets_off = off + 16 + bloom_size * 8;
    if nbuckets == 0 {
        return Ok(symoffset);
    }
    let mut max_sym = 0u32;
    for i in 0..nbuckets {
        let bucket = read_u32(data, buckets_off + i * 4)?;
        if bucket > max_sym {
            max_sym = bucket;
        }
    }
    if max_sym < symoffset as u32 {
        return Ok(symoffset);
    }
    let chain_off = buckets_off + nbuckets * 4;
    let mut idx = (max_sym as usize) - symoffset;
    loop {
        let value = read_u32(data, chain_off + idx * 4)?;
        if value & 1 == 1 {
            return Ok(symoffset + idx + 1);
        }
        idx += 1;
        if idx > data.len() / 4 {
            bail!("DT_GNU_HASH chain does not terminate");
        }
    }
}

fn prot_from_flags(flags: u32) -> i32 {
    let mut prot = 0;
    if flags & PF_R != 0 {
        prot |= libc::PROT_READ;
    }
    if flags & PF_W != 0 {
        prot |= libc::PROT_WRITE;
    }
    if flags & PF_X != 0 {
        prot |= libc::PROT_EXEC;
    }
    prot
}

fn vaddr_to_offset(loads: &[Segment], vaddr: u64) -> Result<usize> {
    for seg in loads {
        if vaddr >= seg.vaddr && vaddr < seg.vaddr.saturating_add(seg.filesz.max(seg.memsz)) {
            return Ok((seg.offset + (vaddr - seg.vaddr)) as usize);
        }
    }
    bail!("vaddr {vaddr:#x} is not inside a PT_LOAD");
}

fn cstr_at(strtab: &[u8], off: usize) -> Option<String> {
    let bytes = strtab.get(off..)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data.get(off..off + 2).context("ELF truncated")?;
    Ok(u16::from_le_bytes(bytes.try_into().expect("2 bytes")))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data.get(off..off + 4).context("ELF truncated")?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64> {
    let bytes = data.get(off..off + 8).context("ELF truncated")?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}

fn read_i64(data: &[u8], off: usize) -> Result<i64> {
    Ok(read_u64(data, off)? as i64)
}

#[cfg(test)]
mod tests {
    use super::relr_addresses;

    #[test]
    fn relr_decodes_address_and_bitmap() {
        // address 0x1000, then a bitmap with bit 0 set (word at where+8) and bit 2 (where+24)
        let relr = [0x1000u64, 0b101];
        assert_eq!(relr_addresses(&relr), vec![0x1000, 0x1010]);
    }
}
