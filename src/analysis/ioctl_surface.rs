//! Windows driver IOCTL attack-surface mapping (engine-native).
//!
//! Statically recovers a Windows kernel driver's IOCTL dispatch surface straight
//! from the PE: walk `.pdata` function boundaries; in each function collect the
//! immediates compared against a register (`cmp/sub reg, imm32`) that are
//! "IOCTL-shaped" (a plausible CTL_CODE); functions clustering such constants are
//! the dispatcher(s). For each code, decode CTL_CODE and best-effort resolve the
//! handler (the `je/jne` branch target or the `call` that follows).
//!
//! Crucially this also decodes the canonical MSVC x64 **two-level switch jump
//! table** that WDM and WDF/KMDF `EvtIoDeviceControl` dispatchers lower to, where
//! the full IOCTL codes never appear as `je` immediates -- only a base adjust, a
//! bounds `cmp`, a `lea anchor,[rip+X]`, an optional `movzx idx,byte[anchor+idx]`
//! byte-index table, a `mov off,dword[anchor+idx*4]` offset table, and a
//! `jmp reg`. `resolve_jump_table` reconstructs code -> case-block -> handler.
//!
//! This is the engine-native home for logic that previously lived as a standalone
//! capstone script; it builds on glaurung's iced backend and `object` PE parsing,
//! and is the foundation a future symbolic IOCTL sink pass dispatches from.

use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectSection};

use crate::core::address::{Address, AddressKind};
use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler};
use crate::core::instruction::{Instruction, OperandKind};
use crate::disasm::iced::IcedDisassembler;

const METHOD: [&str; 4] = ["BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"];
const ACCESS: [&str; 4] = ["ANY", "READ", "WRITE", "READ|WRITE"];

/// One recovered IOCTL code with its decoded CTL_CODE fields and best-effort handler.
#[derive(Debug, Clone)]
pub struct IoctlCode {
    pub code: u32,
    pub ins_va: u64,
    pub handler_va: Option<u64>,
    pub is_base: bool,
    /// "cmp" (immediate compare) or "jump_table" (decoded switch table).
    pub source: &'static str,
}

impl IoctlCode {
    pub fn device_type(&self) -> u16 {
        ((self.code >> 16) & 0xFFFF) as u16
    }
    pub fn access(&self) -> &'static str {
        ACCESS[((self.code >> 14) & 3) as usize]
    }
    pub fn function(&self) -> u16 {
        ((self.code >> 2) & 0xFFF) as u16
    }
    pub fn method(&self) -> &'static str {
        METHOD[(self.code & 3) as usize]
    }
}

/// A dispatcher function and everything recovered from it.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    pub va: u64,
    /// Codes found via `cmp/sub reg,imm32` immediates.
    pub cmp_codes: Vec<IoctlCode>,
    /// Codes recovered by decoding the MSVC two-level switch jump table.
    pub jump_table: BTreeMap<u32, u64>,
    /// Case-block call handlers (handler_va, is_tail_call).
    pub handlers: Vec<(u64, bool)>,
}

/// The full IOCTL surface of a driver.
#[derive(Debug, Clone, Default)]
pub struct IoctlSurface {
    pub dispatchers: Vec<Dispatcher>,
    /// KMDF callback roots: address-taken `.pdata` functions (e.g. EvtIoDeviceControl,
    /// EvtIoRead/Write) registered via a WDF_IO_QUEUE_CONFIG and reached through the WDF
    /// function table -- NOT the WDM DriverObject->MajorFunction the cmp-immediate scan
    /// keys on. Without these, a pure-KMDF driver whose dispatcher uses a computed/table
    /// index (codes never appear as immediates) is invisible. Seed symbolic analysis here.
    pub callback_roots: Vec<u64>,
    /// Functions carrying any IOCTL-shaped constant.
    pub n_code_functions: usize,
    /// Functions with a decoded jump table.
    pub n_jumptable: usize,
}

/// Decode whether an immediate is a plausible CTL_CODE. Mirrors the calibrated
/// false-positive filters from the original sweep tooling (sentinel device types,
/// sign-extended / mask immediates, NTSTATUS-shaped values, four-char ASCII
/// signatures that storage/network helpers compare against).
pub fn is_ioctl_shaped(v: u32) -> bool {
    if v < 0x10000 {
        return false;
    }
    let dev = (v >> 16) & 0xFFFF;
    let func = (v >> 2) & 0xFFF;
    if dev == 0 || dev == 0x7FFF || dev == 0xFFFF || dev >= 0xFF00 {
        return false;
    }
    if v >= 0xFFFF_0000 || (0x7FFF_0000..=0x7FFF_FFFF).contains(&v) {
        return false;
    }
    if v & 0xFFF == 0 {
        return false;
    }
    if func == 0xFFF {
        return false;
    }
    let top = v >> 28;
    if top == 0xC || top == 0x8 {
        return false;
    }
    // four printable-ASCII bytes => a signature, not a CTL_CODE
    let all_printable = (0..4).all(|s| {
        let b = (v >> (s * 8)) & 0xFF;
        (0x20..=0x7E).contains(&b)
    });
    if all_printable {
        return false;
    }
    true
}

/// Section map for VA -> file-offset translation.
struct SecMap {
    /// (va_start, va_end, file_off, file_len)
    secs: Vec<(u64, u64, usize, usize)>,
    image_base: u64,
}

impl SecMap {
    fn build(obj: &object::read::File) -> Self {
        let mut secs = Vec::new();
        for s in obj.sections() {
            let va = s.address();
            let vsize = s.size();
            if let Some((foff, fsize)) = s.file_range() {
                secs.push((va, va + vsize, foff as usize, fsize as usize));
            }
        }
        secs.sort_by_key(|t| t.0);
        SecMap {
            secs,
            image_base: obj.relative_address_base(),
        }
    }

    fn off(&self, va: u64) -> Option<usize> {
        for &(start, end, foff, flen) in &self.secs {
            if va >= start && va < end {
                let delta = (va - start) as usize;
                if delta < flen {
                    return Some(foff + delta);
                }
                return None; // in virtual padding beyond raw data
            }
        }
        None
    }

    fn read_u8(&self, data: &[u8], va: u64) -> Option<u8> {
        self.off(va).and_then(|o| data.get(o).copied())
    }
    fn read_u32(&self, data: &[u8], va: u64) -> Option<u32> {
        let o = self.off(va)?;
        let b = data.get(o..o + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Parse the x64 `.pdata` exception directory into (begin_va, end_va) function ranges.
fn pdata_ranges(obj: &object::read::File, image_base: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let sec = match obj.section_by_name(".pdata") {
        Some(s) => s,
        None => return out,
    };
    let bytes = match sec.data() {
        Ok(b) => b,
        Err(_) => return out,
    };
    let n = bytes.len() / 12;
    for i in 0..n {
        let o = i * 12;
        let begin = u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]) as u64;
        let end =
            u32::from_le_bytes([bytes[o + 4], bytes[o + 5], bytes[o + 6], bytes[o + 7]]) as u64;
        if end > begin {
            out.push((image_base + begin, image_base + end));
        }
    }
    out
}

/// Linear-disassemble a VA range into instructions.
fn disasm_range(
    dis: &IcedDisassembler,
    data: &[u8],
    sm: &SecMap,
    start_va: u64,
    end_va: u64,
) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut va = start_va;
    while va < end_va {
        let off = match sm.off(va) {
            Some(o) => o,
            None => break,
        };
        let slice = match data.get(off..) {
            Some(s) if !s.is_empty() => s,
            _ => break,
        };
        let addr = match Address::new(AddressKind::VA, va, 64, None, None) {
            Ok(a) => a,
            Err(_) => break,
        };
        match dis.disassemble_instruction(&addr, slice) {
            Ok(ins) => {
                let len = ins.length as u64;
                if len == 0 {
                    break;
                }
                va += len;
                out.push(ins);
            }
            Err(_) => break,
        }
    }
    out
}

fn imm_of(ins: &Instruction, idx: usize) -> Option<i64> {
    ins.operands.get(idx).and_then(|o| o.immediate)
}

/// The handler for a switch case: the first `call <imm>` reached from `target_va`
/// before the block ends (`ret`). Prefer a call to a `.pdata` function start.
fn first_call_in_block(
    dis: &IcedDisassembler,
    data: &[u8],
    sm: &SecMap,
    target_va: u64,
    pdata_starts: &BTreeSet<u64>,
) -> Option<u64> {
    let insns = disasm_range(dis, data, sm, target_va, target_va + 0x300);
    let mut fallback = None;
    for x in &insns {
        if x.mnemonic == "call" {
            if let Some(op) = x.operands.first() {
                if op.kind == OperandKind::Immediate {
                    if let Some(t) = op.immediate {
                        let tgt = t as u64;
                        if pdata_starts.contains(&tgt) {
                            return Some(tgt);
                        }
                        if fallback.is_none() {
                            fallback = Some(tgt);
                        }
                    }
                }
            }
        }
        if x.mnemonic == "ret" {
            break;
        }
    }
    fallback
}

/// Decode the canonical MSVC x64 two-level switch jump table in a function.
fn resolve_jump_table(
    dis: &IcedDisassembler,
    insns: &[Instruction],
    data: &[u8],
    sm: &SecMap,
    pdata_starts: &BTreeSet<u64>,
) -> BTreeMap<u32, u64> {
    let mut out = BTreeMap::new();
    for ji in 0..insns.len() {
        let jins = &insns[ji];
        if jins.mnemonic != "jmp" {
            continue;
        }
        match jins.operands.first() {
            Some(op) if op.kind == OperandKind::Register => {}
            _ => continue,
        }
        let lo = ji.saturating_sub(30);
        let win = &insns[lo..ji];
        let mut anchor: Option<u64> = None;
        let mut dword_t: Option<u64> = None;
        let mut byte_t: Option<u64> = None;
        let mut count: Option<u32> = None;
        let mut base_code: Option<u32> = None;
        for x in win {
            let m = x.mnemonic.as_str();
            match m {
                "lea" => {
                    if let Some(o) = x.operands.get(1) {
                        if o.kind == OperandKind::Memory
                            && o.base.as_deref() == Some("rip")
                        {
                            // iced resolves rip-relative displacement to absolute
                            if let Some(d) = o.displacement {
                                anchor = Some(d as u64);
                            }
                        }
                    }
                }
                "mov" => {
                    if let (Some(o), Some(a)) = (x.operands.get(1), anchor) {
                        if o.kind == OperandKind::Memory
                            && o.scale == Some(4)
                            && o.index.is_some()
                        {
                            dword_t = Some((a as i64 + o.displacement.unwrap_or(0)) as u64);
                        }
                    }
                }
                "movzx" => {
                    if let (Some(o), Some(a)) = (x.operands.get(1), anchor) {
                        if o.kind == OperandKind::Memory
                            && o.index.is_some()
                            && matches!(o.scale, None | Some(1))
                        {
                            byte_t = Some((a as i64 + o.displacement.unwrap_or(0)) as u64);
                        }
                    }
                }
                "cmp" => {
                    if let Some(n) = imm_of(x, 1) {
                        let n = (n & 0xFFFF_FFFF) as u32;
                        if n > 0 && n < 0x1000 {
                            count = Some(n);
                        }
                    }
                }
                "add" => {
                    if let Some(n) = imm_of(x, 1) {
                        base_code = Some(((-(n & 0xFFFF_FFFF)) & 0xFFFF_FFFF) as u32);
                    }
                }
                "sub" => {
                    if let Some(n) = imm_of(x, 1) {
                        base_code = Some((n & 0xFFFF_FFFF) as u32);
                    }
                }
                _ => {}
            }
        }
        if std::env::var("GLAURUNG_IOCTL_DEBUG").is_ok() {
            eprintln!(
                "  [jt] jmp@{:#x} anchor={:x?} dword_t={:x?} byte_t={:x?} count={:?} base_code={:x?}",
                jins.address.value, anchor, dword_t, byte_t, count, base_code
            );
        }
        let (anchor, dword_t, count, base_code) = match (anchor, dword_t, count, base_code) {
            (Some(a), Some(d), Some(c), Some(b)) => (a, d, c, b),
            _ => continue,
        };
        for idx in 0..=count {
            let ci = match byte_t {
                Some(bt) => match sm.read_u8(data, bt + idx as u64) {
                    Some(c) => c as u64,
                    None => continue,
                },
                None => idx as u64,
            };
            let offset = match sm.read_u32(data, dword_t + ci * 4) {
                Some(o) => o,
                None => continue,
            };
            let target = anchor.wrapping_add(offset as u64);
            if !pdata_starts.contains(&target) && sm.off(target).is_none() {
                continue;
            }
            let code = base_code.wrapping_add(idx);
            if !is_ioctl_shaped(code) {
                continue;
            }
            if let Some(h) = first_call_in_block(dis, data, sm, target, pdata_starts) {
                out.insert(code, h);
            }
        }
    }
    out
}

/// Fallback: case-block call targets in a dispatcher (`call <imm>` to a `.pdata`
/// function start). Returns (handler_va, is_tail_call) sorted by handler.
fn harvest_call_handlers(insns: &[Instruction], pdata_starts: &BTreeSet<u64>) -> Vec<(u64, bool)> {
    let mut map: BTreeMap<u64, bool> = BTreeMap::new();
    for i in 0..insns.len() {
        let x = &insns[i];
        if x.mnemonic != "call" {
            continue;
        }
        let tgt = match x.operands.first() {
            Some(o) if o.kind == OperandKind::Immediate => match o.immediate {
                Some(t) => t as u64,
                None => continue,
            },
            _ => continue,
        };
        if !pdata_starts.contains(&tgt) {
            continue;
        }
        let tail = (i + 1..(i + 4).min(insns.len())).any(|j| insns[j].mnemonic == "jmp");
        let e = map.entry(tgt).or_insert(false);
        *e = *e || tail;
    }
    map.into_iter().collect()
}

/// Map the IOCTL attack surface of a Windows driver PE.
pub fn map_ioctl_surface(data: &[u8], min_codes: usize, all_functions: bool) -> IoctlSurface {
    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return IoctlSurface::default(),
    };
    let sm = SecMap::build(&obj);
    let image_base = sm.image_base;
    let ranges = pdata_ranges(&obj, image_base);
    let pdata_starts: BTreeSet<u64> = ranges.iter().map(|&(b, _)| b).collect();
    let dis = IcedDisassembler::new(Architecture::X86_64, Endianness::Little);

    let mut per_func: BTreeMap<u64, Vec<IoctlCode>> = BTreeMap::new();
    let mut jt_maps: BTreeMap<u64, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut handlers_map: BTreeMap<u64, Vec<(u64, bool)>> = BTreeMap::new();
    // Address-taken .pdata functions (`lea reg,[rip+fn]`): callback registrations.
    // KMDF EvtIoDeviceControl & friends are taken this way for WDF_IO_QUEUE_CONFIG.
    let mut lea_taken: BTreeSet<u64> = BTreeSet::new();

    let is_dispatcher = |codes: &[IoctlCode]| -> bool {
        if all_functions {
            return true;
        }
        if codes.iter().any(|c| c.is_base) {
            return true;
        }
        let mut devs: BTreeMap<u16, usize> = BTreeMap::new();
        for c in codes {
            *devs.entry(c.device_type()).or_insert(0) += 1;
        }
        devs.values().copied().max().unwrap_or(0) >= min_codes
    };

    for (b, en) in &ranges {
        let fv = *b;
        let insns = disasm_range(&dis, data, &sm, fv, *en);
        if insns.is_empty() {
            continue;
        }
        let mut has_jmp_reg = false;
        let mut codes: Vec<IoctlCode> = Vec::new();
        for i in 0..insns.len() {
            let ins = &insns[i];
            let m = ins.mnemonic.as_str();
            if m == "jmp" {
                if let Some(o) = ins.operands.first() {
                    if o.kind == OperandKind::Register {
                        has_jmp_reg = true;
                    }
                }
                continue;
            }
            if m == "lea" {
                if let Some(o) = ins.operands.get(1) {
                    if o.kind == OperandKind::Memory && o.base.as_deref() == Some("rip") {
                        if let Some(d) = o.displacement {
                            lea_taken.insert(d as u64);
                        }
                    }
                }
                continue;
            }
            if m != "cmp" && m != "sub" {
                continue;
            }
            for op in &ins.operands {
                if op.kind != OperandKind::Immediate {
                    continue;
                }
                let imm = match op.immediate {
                    Some(v) => (v & 0xFFFF_FFFF) as u32,
                    None => continue,
                };
                if !is_ioctl_shaped(imm) {
                    continue;
                }
                // best-effort handler: nearest following je/jne/call within 6
                let mut handler = None;
                for j in (i + 1)..(i + 6).min(insns.len()) {
                    let nxt = &insns[j];
                    let nm = nxt.mnemonic.as_str();
                    if matches!(nm, "je" | "jne" | "jz" | "jnz" | "call") {
                        if let Some(o) = nxt.operands.first() {
                            if o.kind == OperandKind::Immediate {
                                if let Some(t) = o.immediate {
                                    handler = Some(t as u64);
                                    break;
                                }
                            }
                        }
                    }
                }
                codes.push(IoctlCode {
                    code: imm,
                    ins_va: ins.address.value,
                    handler_va: handler,
                    is_base: m == "sub",
                    source: "cmp",
                });
            }
        }
        let has_codes = !codes.is_empty();
        if has_jmp_reg {
            let jt = resolve_jump_table(&dis, &insns, data, &sm, &pdata_starts);
            if !jt.is_empty() {
                jt_maps.insert(fv, jt);
            }
        }
        if (has_codes && is_dispatcher(&codes)) || jt_maps.contains_key(&fv) {
            handlers_map.insert(fv, harvest_call_handlers(&insns, &pdata_starts));
        }
        if has_codes {
            per_func.insert(fv, codes);
        }
    }

    // dispatcher = cmp-cluster OR decoded jump table
    let mut disp_keys: BTreeSet<u64> = per_func
        .iter()
        .filter(|(_, c)| is_dispatcher(c))
        .map(|(k, _)| *k)
        .collect();
    disp_keys.extend(jt_maps.keys().copied());

    let mut dispatchers: Vec<Dispatcher> = disp_keys
        .iter()
        .map(|&fv| Dispatcher {
            va: fv,
            cmp_codes: per_func.get(&fv).cloned().unwrap_or_default(),
            jump_table: jt_maps.get(&fv).cloned().unwrap_or_default(),
            handlers: handlers_map.get(&fv).cloned().unwrap_or_default(),
        })
        .collect();

    // rank: jump-table decoders and base-style / bigger clusters first
    dispatchers.sort_by(|a, b| {
        let score = |d: &Dispatcher| -> (usize, bool, usize) {
            let mut devs: BTreeMap<u16, usize> = BTreeMap::new();
            for c in &d.cmp_codes {
                *devs.entry(c.device_type()).or_insert(0) += 1;
            }
            (
                d.jump_table.len(),
                d.cmp_codes.iter().any(|c| c.is_base),
                devs.values().copied().max().unwrap_or(0),
            )
        };
        score(b).cmp(&score(a))
    });

    // KMDF augmentation: if this is a WDF driver, the IOCTL dispatcher (EvtIoDeviceControl)
    // is an address-taken callback reached via the WDF function table, which the WDM
    // cmp-immediate scan above does not find. Surface the address-taken .pdata functions
    // (minus those already recognised as dispatchers) as callback roots so the symbolic
    // engine seeds at the real KMDF handlers instead of analysing nothing.
    let is_kmdf = data.windows(14).any(|w| w == b"WdfVersionBind");
    let mut callback_roots: Vec<u64> = Vec::new();
    if is_kmdf {
        let disp_set: BTreeSet<u64> = dispatchers.iter().map(|d| d.va).collect();
        callback_roots = lea_taken
            .into_iter()
            .filter(|t| pdata_starts.contains(t) && !disp_set.contains(t))
            .collect();
        callback_roots.sort_unstable();
    }

    IoctlSurface {
        dispatchers,
        callback_roots,
        n_code_functions: per_func.len(),
        n_jumptable: jt_maps.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_shape_filters() {
        assert!(is_ioctl_shaped(0x22242c)); // real CTL_CODE (dev 0x22, func 0x90b)
        assert!(is_ioctl_shaped(0x9c402443)); // amdpsp family
        assert!(!is_ioctl_shaped(0x0)); // too small
        assert!(!is_ioctl_shaped(0xFFFFFFFF)); // sentinel / mask
        assert!(!is_ioctl_shaped(0x41424344)); // "ABCD" ascii signature
        assert!(!is_ioctl_shaped(0xC0000001)); // NTSTATUS-shaped
        assert!(!is_ioctl_shaped(0x00220000)); // func==0, too round
    }

    /// Parity check against real driver fixtures. Gated on GLAURUNG_IOCTL_FIXTURES
    /// (a dir holding the .sys files) so we don't commit third-party binaries.
    /// Expected unique-code counts are the cross-checked reference values.
    #[test]
    fn parity_on_real_drivers() {
        let dir = match std::env::var("GLAURUNG_IOCTL_FIXTURES") {
            Ok(d) => d,
            Err(_) => return,
        };
        let cases = [
            ("PXGX112.sys", 2usize, 0usize),
            ("e22w8x64.sys", 85, 22),
            ("glusbflt.sys", 3, 0),
            ("vn0601.sys", 6, 0),
        ];
        for (name, expect_codes, expect_jt) in cases {
            let data = match std::fs::read(format!("{dir}/{name}")) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let s = map_ioctl_surface(&data, 2, false);
            let mut codes = BTreeSet::new();
            let mut jt = 0usize;
            for d in &s.dispatchers {
                for c in &d.cmp_codes {
                    codes.insert(c.code);
                }
                for k in d.jump_table.keys() {
                    codes.insert(*k);
                }
                jt += d.jump_table.len();
            }
            assert_eq!(codes.len(), expect_codes, "{name} unique codes");
            assert_eq!(jt, expect_jt, "{name} jump-table codes");
        }
    }

    #[test]
    fn ctl_code_decode() {
        let c = IoctlCode {
            code: 0x22242c,
            ins_va: 0,
            handler_va: None,
            is_base: false,
            source: "cmp",
        };
        assert_eq!(c.device_type(), 0x22);
        assert_eq!(c.function(), 0x90b);
        assert_eq!(c.method(), "BUFFERED");
        assert_eq!(c.access(), "ANY");
    }
}
