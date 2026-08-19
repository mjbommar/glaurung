//! Speculative scans of the raw image for function starts.
//!
//! Every pass in this module has the same shape: it takes the image bytes and
//! the executable regions parsed by the parent module, sweeps them looking for
//! a byte pattern, and returns candidate addresses. Nothing here disassembles,
//! walks blocks, or builds a CFG — the parent's `discover_function` does that,
//! and treats everything produced here as a *candidate* that its own gates may
//! still reject. The one exception to "returns addresses" is
//! [`collect_code_labels`], which names the block leaders a completed walk left
//! behind, and shares [`classify_code_label`]'s byte predicates with the scans.
//!
//! The `_scan_` and `_candidate` predicates are the gates each sweep applies
//! before promoting a hit; `prologue_gate_tests` and `elf_prologue_scan_tests`
//! (below) are their tests and moved here with them.
//!
//! Several predicates that look like they belong here live in the sibling
//! [`entry_shape`](super::entry_shape) module instead, because the call graph
//! says they are shared vocabulary rather than scan-private helpers. That
//! module owns the single question "does this byte window look like a function
//! start?"; this one owns "which offsets should we ask about?":
//! - [`head_looks_like_fn_start`](super::entry_shape::head_looks_like_fn_start)
//!   and
//!   [`has_function_boundary_marker`](super::entry_shape::has_function_boundary_marker)
//!   are also the parent's tail-call and xref-seed gates.
//! - [`pe_head_looks_like_simd_continuation`](super::entry_shape::pe_head_looks_like_simd_continuation)
//!   is also called by `pe_xref_seed_looks_like_function_start`.
//! - [`classify_pe_thunk_head`](super::entry_shape::classify_pe_thunk_head) and
//!   its `PeThunkKind`/`PeThunkMatch` vocabulary are also called by
//!   `pe_tail_target_looks_like_function_start` and the parent's
//!   `classify_function_shapes`.
//!
//! `PeTinyStubScanResult` and `PeRawCallFunctionStart` are the two scan results
//! whose fields the parent reads directly, so they stay declared there and cost
//! no widening.

use super::*;

fn pe_prologue_scan_candidate(data: &[u8], file_off: usize) -> bool {
    has_function_boundary_marker(data, file_off) && head_looks_like_fn_start(&data[file_off..])
}

/// Conservative PE start-pattern scan for leaf/tiny functions that are not
/// exported, covered by `.pdata`, or reached by direct calls.
///
/// This intentionally scans only 16-byte-aligned executable VAs and requires
/// both an MSVC-style boundary marker and a recognized prologue/thunk head.
/// Candidates are queued after trusted export/`.pdata` seeds, so the later
/// body-overlap gate can discard candidates that fall inside an already
/// discovered function.
// AArch64 hardened function-entry signatures (little-endian 32-bit words).
const AARCH64_PACIASP: u32 = 0xd503_233f;
const AARCH64_PACIBSP: u32 = 0xd503_237f;
const AARCH64_BTI_C: u32 = 0xd503_245f;
const AARCH64_BTI_JC: u32 = 0xd503_24df;

/// Scan AArch64 executable regions for pointer-authentication function
/// prologues, recovering entry points on **stripped** hardened binaries where
/// no symbol table survives.
///
/// The reliable entry signal is `PACIASP`/`PACIBSP` — a function that signs its
/// return address does so as its first real instruction. When the function is
/// also a BTI target the compiler emits a `BTI c`/`BTI jc` landing pad one word
/// earlier, which is the true entry, so we rewind to it. A bare `BTI c` is *not*
/// used as a seed: it also guards internal branch targets and would over-generate.
pub(super) fn scan_aarch64_prologue_function_starts(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if arch != BArch::AArch64 {
        return Vec::new();
    }
    let read_word = |va: u64| -> Option<u32> {
        // Scanning for function starts reads instructions, so resolve as code.
        let off = indexed_code_offset(image, data, va)?;
        let b = data.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    let mut starts = Vec::new();
    for region in regions {
        let mut va = align_up_u64(region.start, 4);
        while va + 4 <= region.end {
            if let Some(word) = read_word(va) {
                if word == AARCH64_PACIASP || word == AARCH64_PACIBSP {
                    // Rewind to a preceding BTI landing pad if present.
                    let start = match va.checked_sub(4) {
                        Some(prev)
                            if prev >= region.start
                                && matches!(
                                    read_word(prev),
                                    Some(AARCH64_BTI_C | AARCH64_BTI_JC)
                                ) =>
                        {
                            prev
                        }
                        _ => va,
                    };
                    starts.push(start);
                }
            }
            va = match va.checked_add(4) {
                Some(next) => next,
                None => break,
            };
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// Head patterns that open a System V x86-64 function.
///
/// Deliberately narrower than [`head_looks_like_fn_start`], which also accepts
/// thunk and stub shapes that suit PE. Here the candidate must look like a real
/// GCC/Clang function entry, because ELF discovery already has `.eh_frame` for
/// the easy cases and this scan exists only for what `.eh_frame` cannot cover:
/// hand-written assembly, `-fno-asynchronous-unwind-tables` builds such as
/// Alpine's `busybox`, and `.init`/`.fini` fragments.
fn elf_x86_prologue_head(head: &[u8]) -> bool {
    match head {
        // endbr64 — CET, and the first instruction of essentially every
        // function in a current distro build.
        [0xf3, 0x0f, 0x1e, 0xfa, ..] => true,
        // push rbp; mov rbp, rsp
        [0x55, 0x48, 0x89, 0xe5, ..] => true,
        // push rbp alone, then any callee-saved push
        [0x55, 0x41, 0x54 | 0x55 | 0x56 | 0x57, ..] => true,
        // push rbx / rbp / rsi / rdi followed by a REX-prefixed move
        [0x53 | 0x55 | 0x56 | 0x57, 0x48, 0x89, ..] => true,
        // sub rsp, imm8 / imm32
        [0x48, 0x83, 0xec, ..] => true,
        [0x48, 0x81, 0xec, ..] => true,
        _ => false,
    }
}

/// AArch64 words that open a function without pointer authentication.
///
/// `stp x29, x30, [sp, #-N]!` is the canonical frame save and `sub sp, sp, #N`
/// the canonical frame allocation. Matching only PAC prologues meant this scan
/// found nothing on the Ubuntu and Alpine AArch64 builds actually in the sample
/// tree, which are BTI-enabled but not PAC-signed.
fn aarch64_unhardened_prologue(word: u32) -> bool {
    // stp x29, x30, [sp, #imm]!  — pre-indexed, base sp, pair x29/x30.
    // Encoding: 1010 1001 10ii iiii i111 1011 111x xxxx with Rt=x29, Rt2=x30.
    let stp_frame = (word & 0xffc0_7fff) == 0xa980_7bfd;
    // sub sp, sp, #imm  (64-bit, immediate form, Rd=Rn=sp=31)
    let sub_sp = (word & 0xff80_03ff) == 0xd100_03ff;
    stp_frame || sub_sp
}

pub(super) fn scan_pe_prologue_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let mut starts = Vec::new();
    for region in regions {
        let mut va = align_up_u64(region.start, 16);
        while va < region.end {
            if let Some(file_off) = pe_va_to_file_off(data, va) {
                if file_off < data.len() && pe_prologue_scan_candidate(data, file_off) {
                    starts.push(va);
                }
            }
            va = match va.checked_add(16) {
                Some(next) => next,
                None => break,
            };
        }
    }
    starts
}

/// Scan ELF executable regions for function prologues.
///
/// Candidates are emitted as ordinary `Prologue` seeds, which remain
/// body-overlap gated: unlike an `.eh_frame` FDE start this is a heuristic, and
/// it must never split a function that a trusted seed already proved.
pub(super) fn scan_elf_prologue_function_starts(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        return Vec::new();
    }
    let mut starts = Vec::new();
    match arch {
        BArch::X86_64 => {
            for region in regions {
                // 16-byte alignment is what both GCC and Clang use for function
                // entries by default; scanning every byte would trade a large
                // slowdown for candidates that are almost all false.
                let mut va = align_up_u64(region.start, 16);
                while va < region.end {
                    if let Some(off) = indexed_code_offset(image, data, va) {
                        if off < data.len()
                            && has_function_boundary_marker(data, off)
                            && elf_x86_prologue_head(&data[off..])
                        {
                            starts.push(va);
                        }
                    }
                    va = match va.checked_add(16) {
                        Some(next) => next,
                        None => break,
                    };
                }
            }
        }
        BArch::AArch64 => {
            for region in regions {
                let mut va = align_up_u64(region.start, 4);
                while va + 4 <= region.end {
                    if let Some(off) = indexed_code_offset(image, data, va) {
                        if let Some(b) = data.get(off..off + 4) {
                            let word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                            if aarch64_unhardened_prologue(word) {
                                starts.push(va);
                            }
                        }
                    }
                    va = match va.checked_add(4) {
                        Some(next) => next,
                        None => break,
                    };
                }
            }
        }
        _ => {}
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

fn thunk_scan_has_padding(data: &[u8], file_off: usize, len: usize) -> bool {
    if has_function_boundary_marker(data, file_off) {
        return true;
    }
    matches!(
        data.get(file_off.saturating_add(len)),
        Some(0xcc | 0x90 | 0xc3)
    )
}

fn pe_thunk_scan_candidate(data: &[u8], file_off: usize, va: u64, _regions: &[ExecRegion]) -> bool {
    if file_off >= data.len() {
        return false;
    }
    // `scan_pe_thunk_function_starts`, the only caller, returns early unless the
    // image is 64-bit.
    let Some(matched) = classify_pe_thunk_head(va, &data[file_off..], true) else {
        return false;
    };
    match matched.kind {
        PeThunkKind::ImportMemory => {
            ((matched.length == 6 && data.get(file_off..file_off + 2) == Some(&[0xff, 0x25]))
                || (matched.length == 7
                    && data.get(file_off..file_off + 3) == Some(&[0x48, 0xff, 0x25])))
                && (file_off == 0 || data.get(file_off - 1) != Some(&0x48))
                && va % 8 == 0
                && thunk_scan_has_padding(data, file_off, matched.length)
        }
        PeThunkKind::TailJump => false,
    }
}

fn is_exec_va(regions: &[ExecRegion], va: u64) -> bool {
    regions.iter().any(|r| va >= r.start && va < r.end)
}

fn is_padding_after(data: &[u8], file_off: usize) -> bool {
    matches!(data.get(file_off), None | Some(0xcc | 0x90 | 0xc3))
}

fn rel32_target_from(data: &[u8], file_off: usize, va: u64, insn_len: u64) -> Option<u64> {
    rel_target(va, insn_len, read_i32_le_at(data, file_off + 1)? as i64)
}

fn pe_adjustor_jump_stub_len(
    data: &[u8],
    file_off: usize,
    va: u64,
    regions: &[ExecRegion],
) -> Option<usize> {
    let head = data.get(file_off..)?;
    if head.len() < 12 || head[0] != 0x48 || !matches!(head[1], 0x8b | 0x8d) {
        return None;
    }
    // mov/lea rcx|rbx, [rdx+disp32]
    if !matches!(head[2], 0x8a | 0x9a) {
        return None;
    }
    let mut jmp_off = file_off + 7;
    let mut len = 12usize;
    if data.get(jmp_off) != Some(&0xe9) {
        // Optional add rcx/rbx, imm8 before the jump.
        if head.len() < 16 || head[7] != 0x48 || head[8] != 0x83 {
            return None;
        }
        match (head[2], head[9]) {
            (0x8a, 0xc1) | (0x9a, 0xc3) => {}
            _ => return None,
        }
        jmp_off = file_off + 11;
        len = 16;
    }
    if data.get(jmp_off) != Some(&0xe9) {
        return None;
    }
    let jmp_va = va.checked_add((jmp_off - file_off) as u64)?;
    let target = rel32_target_from(data, jmp_off, jmp_va, 5)?;
    if !is_exec_va(regions, target) {
        return None;
    }
    Some(len)
}

fn pe_tiny_return_helper_len(data: &[u8], file_off: usize) -> Option<usize> {
    let head = data.get(file_off..)?;
    if head.len() >= 3 && head[0] == 0xc2 {
        return Some(3);
    }
    if head.len() >= 3 && head[0..3] == [0x33, 0xc0, 0xc3] {
        return Some(3);
    }
    if head.len() >= 6 && head[0] == 0xb8 && head[5] == 0xc3 {
        return Some(6);
    }
    // Tiny move/lea/load/store helper ending in ret, bounded tightly to avoid
    // mistaking vectorized loop labels for functions.
    if !matches!(
        head.first(),
        Some(0x32 | 0x33 | 0x40 | 0x45 | 0x48 | 0x49 | 0x4c | 0x4d | 0x8a | 0x8b)
    ) {
        return None;
    }
    if pe_head_looks_like_simd_continuation(head) {
        return None;
    }
    let max_len = std::cmp::min(32, head.len());
    for idx in 1..max_len {
        if head[idx] == 0xc3 {
            if head[..idx]
                .iter()
                .any(|b| matches!(*b, 0xe8 | 0xe9 | 0xeb | 0xcc))
            {
                return None;
            }
            return Some(idx + 1);
        }
    }
    None
}

fn pe_tiny_stub_scan_candidate(
    data: &[u8],
    file_off: usize,
    va: u64,
    regions: &[ExecRegion],
) -> bool {
    if file_off >= data.len() {
        return false;
    }
    if pe_head_looks_like_simd_continuation(&data[file_off..]) {
        return false;
    }
    if let Some(len) = pe_adjustor_jump_stub_len(data, file_off, va, regions) {
        return is_padding_after(data, file_off.saturating_add(len))
            || has_function_boundary_marker(data, file_off)
            || data.get(file_off.saturating_add(len)..).is_some_and(|_| {
                pe_adjustor_jump_stub_len(data, file_off + len, va + len as u64, regions).is_some()
                    || pe_prologue_scan_candidate(data, file_off + len)
                    || head_looks_like_fn_start(&data[file_off + len..])
            });
    }
    if va % 4 != 0 {
        return false;
    }
    if !has_function_boundary_marker(data, file_off) {
        return false;
    }
    pe_tiny_return_helper_len(data, file_off)
        .map(|len| is_padding_after(data, file_off.saturating_add(len)))
        .unwrap_or(false)
}

fn pe_tiny_stub_scan_promotes_candidate(
    data: &[u8],
    file_off: usize,
    va: u64,
    regions: &[ExecRegion],
    code_pointer_targets: &std::collections::HashSet<u64>,
) -> bool {
    pe_tiny_stub_scan_candidate(data, file_off, va, regions)
        && (pe_adjustor_jump_stub_len(data, file_off, va, regions).is_none()
            || code_pointer_targets.contains(&va))
}

pub(super) fn scan_pe_tiny_stub_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
    pdata_starts: &std::collections::HashSet<u64>,
    code_pointer_targets: &std::collections::HashSet<u64>,
) -> PeTinyStubScanResult {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return PeTinyStubScanResult::default();
    }
    let mut result = PeTinyStubScanResult::default();
    for region in regions {
        let mut va = region.start;
        while va < region.end {
            if pdata_starts.contains(&va) {
                result.pdata_rejected.push(va);
            } else if let Some(file_off) = pe_va_to_file_off(data, va) {
                if file_off < data.len() && pe_tiny_stub_scan_candidate(data, file_off, va, regions)
                {
                    if pe_tiny_stub_scan_promotes_candidate(
                        data,
                        file_off,
                        va,
                        regions,
                        code_pointer_targets,
                    ) {
                        result.starts.push(va);
                    } else {
                        result.unpromoted_candidates.push(va);
                    }
                }
            }
            va = match va.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
    }
    result
}

fn pe_low_confidence_call_target_head(data: &[u8], file_off: usize) -> bool {
    if file_off >= data.len() {
        return false;
    }
    if pe_head_looks_like_simd_continuation(&data[file_off..]) {
        return false;
    }
    let head = &data[file_off..];
    if head_looks_like_fn_start(head) || pe_tiny_return_helper_len(data, file_off).is_some() {
        return true;
    }
    matches!(
        head,
        [0x48, 0x3b | 0x63 | 0x83 | 0x8b | 0x8d | 0x89, ..]
            | [0x4c, 0x3b | 0x63 | 0x8b | 0x8d | 0x89, ..]
            | [0x45, 0x33 | 0x85, ..]
            | [0x33, 0xd2, 0x33, 0xc9, ..]
            | [0xc7, 0x44, 0x24, ..]
            | [0x8b | 0x0f, ..]
    )
}

fn classify_code_label(data: &[u8], va: u64) -> String {
    let Some(file_off) = pe_va_to_file_off(data, va) else {
        return "block_label".to_string();
    };
    if file_off >= data.len() {
        return "block_label".to_string();
    }
    let head = &data[file_off..];
    if pe_head_looks_like_simd_continuation(head) {
        return "simd_block_label".to_string();
    }
    if matches!(head, [0x48, 0x8b, _, 0x24, ..] | [0x48, 0x83, 0xc4, ..])
        || pe_tiny_return_helper_len(data, file_off).is_some()
    {
        return "epilogue_label".to_string();
    }
    if matches!(head, [0xe8, ..] | [0xe9, ..] | [0xeb, ..]) {
        return "block_label".to_string();
    }
    "block_label".to_string()
}

pub(super) fn collect_code_labels(data: &[u8], functions: &[Function]) -> Vec<CodeLabel> {
    let mut labels = Vec::new();
    for func in functions {
        for bb in &func.basic_blocks {
            let va = bb.start_address.value;
            if va == func.entry_point.value {
                continue;
            }
            labels.push(CodeLabel {
                va,
                function_va: func.entry_point.value,
                kind: classify_code_label(data, va),
            });
        }
    }
    labels.sort_by_key(|label| (label.function_va, label.va));
    labels.dedup_by_key(|label| (label.function_va, label.va));
    labels
}

pub(super) fn scan_pe_raw_call_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
    pdata_starts: &std::collections::HashSet<u64>,
) -> Vec<PeRawCallFunctionStart> {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let mut target_counts: std::collections::BTreeMap<u64, usize> =
        std::collections::BTreeMap::new();
    for region in regions {
        let Some(region_off) = pe_va_to_file_off(data, region.start) else {
            continue;
        };
        let span = std::cmp::min(
            (region.end - region.start) as usize,
            data.len().saturating_sub(region_off),
        );
        for rel in 0..span.saturating_sub(5) {
            let file_off = region_off + rel;
            if data.get(file_off) != Some(&0xe8) {
                continue;
            }
            let call_va = region.start + rel as u64;
            let Some(target_va) = rel32_target_from(data, file_off, call_va, 5) else {
                continue;
            };
            *target_counts.entry(target_va).or_default() += 1;
        }
    }
    target_counts
        .into_iter()
        .filter_map(|(target_va, count)| {
            if pdata_starts.contains(&target_va) || !is_exec_va(regions, target_va) {
                return None;
            }
            let target_off = pe_va_to_file_off(data, target_va)?;
            if target_off >= data.len()
                || pe_head_looks_like_simd_continuation(&data[target_off..])
                || pe_tiny_stub_scan_candidate(data, target_off, target_va, regions)
            {
                return None;
            }
            let boundary = has_function_boundary_marker(data, target_off);
            let boundary_low_confidence =
                boundary && pe_low_confidence_call_target_head(data, target_off);
            let repeated_strong_head = count >= 2
                && (head_looks_like_fn_start(&data[target_off..])
                    || pe_tiny_return_helper_len(data, target_off).is_some());
            let repeated_low_confidence =
                count >= 3 && pe_low_confidence_call_target_head(data, target_off);
            if boundary_low_confidence || repeated_strong_head || repeated_low_confidence {
                Some(PeRawCallFunctionStart {
                    va: target_va,
                    allow_body_split: boundary_low_confidence && count >= 3,
                })
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct PeSectionScan {
    name: String,
    virtual_address: u32,
    raw_pointer: u32,
    raw_size: u32,
    characteristics: u32,
}

fn parse_pe_image_base_and_sections(data: &[u8]) -> Option<(u64, Vec<PeSectionScan>)> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let read_u16 = |off: usize| -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        data.get(off..off + 8).map(|b| {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
            (hi << 32) | lo
        })
    };
    let e_lfanew = read_u32(0x3c)? as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    let n_sections = read_u16(coff_off + 2)? as usize;
    let opt_size = read_u16(coff_off + 16)? as usize;
    let opt_off = coff_off + 20;
    let magic = read_u16(opt_off)?;
    let image_base = match magic {
        0x20B => read_u64(opt_off + 24)?,
        0x10B => read_u32(opt_off + 28)? as u64,
        _ => return None,
    };
    let sec_off = opt_off + opt_size;
    let mut sections = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_name = data.get(s..s + 8)?;
        let name_len = raw_name
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_len]).to_string();
        sections.push(PeSectionScan {
            name,
            virtual_address: read_u32(s + 12).unwrap_or(0),
            raw_pointer: read_u32(s + 20).unwrap_or(0),
            raw_size: read_u32(s + 16).unwrap_or(0),
            characteristics: read_u32(s + 36).unwrap_or(0),
        });
    }
    Some((image_base, sections))
}

fn pe_code_pointer_target_confidence(data: &[u8], target_off: usize) -> Option<&'static str> {
    if target_off >= data.len() || pe_head_looks_like_simd_continuation(&data[target_off..]) {
        return None;
    }
    if has_function_boundary_marker(data, target_off) {
        return Some("boundary");
    }
    if head_looks_like_fn_start(&data[target_off..])
        || pe_tiny_return_helper_len(data, target_off).is_some()
    {
        return Some("head");
    }
    if pe_low_confidence_call_target_head(data, target_off) {
        return Some("low_confidence_head");
    }
    None
}

/// Scan PE data sections for image-VA pointers that land in executable code.
///
/// This is intentionally data-reference provenance, not a broad code sweep:
/// it scans aligned pointer slots in readable, non-executable PE sections and
/// only accepts targets that already look like plausible function starts.
pub fn scan_pe_code_pointers(data: &[u8]) -> Vec<PeCodePointer> {
    let (regions, arch, _end, _entry) = parse_exec_regions(data);
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let Some((image_base, sections)) = parse_pe_image_base_and_sections(data) else {
        return Vec::new();
    };
    let pointer_size = 8usize;
    let mut pointers = Vec::new();
    for section in sections {
        let executable = section.characteristics & 0x2000_0000 != 0;
        let readable = section.characteristics & 0x4000_0000 != 0;
        if executable || !readable || section.raw_size < pointer_size as u32 {
            continue;
        }
        let name_lower = section.name.to_ascii_lowercase();
        if matches!(
            name_lower.as_str(),
            ".rsrc" | ".reloc" | ".debug" | ".pdata" | ".xdata"
        ) {
            continue;
        }
        let raw_start = section.raw_pointer as usize;
        if raw_start >= data.len() {
            continue;
        }
        let raw_len = std::cmp::min(section.raw_size as usize, data.len() - raw_start);
        let mut section_hits: Vec<(u64, u64, &'static str, usize)> = Vec::new();
        for slot_size in [8usize, 4usize] {
            let mut rel = 0usize;
            while rel + slot_size <= raw_len {
                let slot_off = raw_start + rel;
                let raw = if slot_size == 8 {
                    u64::from_le_bytes(match data.get(slot_off..slot_off + slot_size) {
                        Some(bytes) => match bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => break,
                        },
                        None => break,
                    })
                } else {
                    u32::from_le_bytes(match data.get(slot_off..slot_off + slot_size) {
                        Some(bytes) => match bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => break,
                        },
                        None => break,
                    }) as u64
                };
                let candidates: [Option<u64>; 2] = if slot_size == 8 {
                    [Some(raw), None]
                } else {
                    [image_base.checked_add(raw), None]
                };
                for target_va in candidates.into_iter().flatten() {
                    if target_va >= image_base && is_exec_va(&regions, target_va) {
                        if let Some(target_off) = pe_va_to_file_off(data, target_va) {
                            if let Some(confidence) =
                                pe_code_pointer_target_confidence(data, target_off)
                            {
                                let pointer_va =
                                    image_base + section.virtual_address as u64 + rel as u64;
                                section_hits.push((pointer_va, target_va, confidence, slot_size));
                            }
                        }
                    }
                }
                rel = rel.saturating_add(slot_size);
            }
        }
        section_hits.sort_by_key(|hit| (hit.0, hit.1));
        section_hits.dedup_by_key(|hit| (hit.0, hit.1));
        let mut table_index = 0usize;
        let mut idx = 0usize;
        while idx < section_hits.len() {
            let run_start = idx;
            while idx + 1 < section_hits.len()
                && section_hits[idx + 1].0 == section_hits[idx].0 + section_hits[idx].3 as u64
            {
                idx += 1;
            }
            let run_end = idx;
            let table_length = run_end - run_start + 1;
            for (pointer_va, target_va, confidence, slot_size) in &section_hits[run_start..=run_end]
            {
                pointers.push(PeCodePointer {
                    pointer_va: *pointer_va,
                    target_va: *target_va,
                    section_name: section.name.clone(),
                    slot_size: *slot_size,
                    table_index,
                    table_length,
                    confidence: (*confidence).to_string(),
                });
            }
            table_index = table_index.saturating_add(1);
            idx += 1;
        }
    }
    pointers.sort_by_key(|ptr| (ptr.pointer_va, ptr.target_va));
    pointers.dedup_by_key(|ptr| (ptr.pointer_va, ptr.target_va));
    pointers
}

pub(super) fn should_seed_pe_code_pointer(ptr: &PeCodePointer) -> bool {
    if ptr.slot_size == 8 {
        return true;
    }
    ptr.slot_size == 4 && ptr.table_length >= 8 && ptr.confidence == "boundary"
}

/// Scan executable PE bytes for compact thunk-table entries that are not
/// necessarily 16-byte aligned and may not carry unwind metadata.
pub(super) fn scan_pe_thunk_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if !arch.is_64_bit() || data.len() < 2 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let mut starts = Vec::new();
    for region in regions {
        let mut va = region.start;
        while va < region.end {
            if let Some(file_off) = pe_va_to_file_off(data, va) {
                if file_off < data.len() && pe_thunk_scan_candidate(data, file_off, va, regions) {
                    starts.push(va);
                }
            }
            va = match va.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
    }
    starts
}

#[cfg(test)]
mod prologue_gate_tests {
    use super::{
        classify_pe_thunk_head, is_code_padding_terminator, memory_operand_va,
        pe_adjustor_jump_stub_len, pe_head_looks_like_simd_continuation,
        pe_low_confidence_call_target_head, pe_prologue_scan_candidate, pe_tiny_return_helper_len,
        pe_tiny_stub_scan_candidate, pe_tiny_stub_scan_promotes_candidate, BArch, ExecRegion,
        PeThunkKind,
    };
    // Named through its own module rather than the parent's re-export: nothing
    // outside `entry_shape` calls this in the shipped build, so a `use` of it in
    // `cfg` would be an unused import there.
    use crate::analysis::cfg::entry_shape::looks_like_fn_start;
    use crate::core::instruction::{Access, Instruction, Operand};
    use std::collections::HashSet;

    fn data_with_pre(prev: &[u8], head: &[u8]) -> (Vec<u8>, usize) {
        let mut d = Vec::with_capacity(prev.len() + head.len());
        d.extend_from_slice(prev);
        let off = d.len();
        d.extend_from_slice(head);
        (d, off)
    }

    #[test]
    fn accepts_cc_padded_boundary() {
        let (d, off) = data_with_pre(&[0xcc, 0xcc], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_c3_ret_boundary() {
        let (d, off) = data_with_pre(&[0xc3], &[0x40, 0x53]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_90_nop_boundary() {
        let (d, off) = data_with_pre(&[0x90, 0x90], &[0x48, 0x83, 0xec, 0x28]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_recognised_prologue_no_marker() {
        // No fn-boundary marker before, but byte 0 is a textbook
        // parameter-spill prologue.
        let (d, off) = data_with_pre(&[0xaa], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn prologue_scan_requires_marker_and_recognised_head() {
        let (d, off) = data_with_pre(&[0xcc], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(pe_prologue_scan_candidate(&d, off));

        let (d, off) = data_with_pre(&[0xaa], &[0x48, 0x89, 0x5c, 0x24, 0x08]);
        assert!(!pe_prologue_scan_candidate(&d, off));

        let (d, off) = data_with_pre(&[0xcc], &[0x83, 0xff, 0x02, 0x0f, 0x85]);
        assert!(!pe_prologue_scan_candidate(&d, off));
    }

    #[test]
    fn x86_int3_and_ud2_are_padding_terminators() {
        assert!(is_code_padding_terminator("Int3", BArch::X86_64));
        assert!(is_code_padding_terminator("ud2", BArch::X86));
        assert!(!is_code_padding_terminator("int3", BArch::AArch64));
        assert!(!is_code_padding_terminator("nop", BArch::X86_64));
    }

    #[test]
    fn tiny_stub_scan_accepts_adjustor_jump_table_entries() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8d, 0x8a, 0x28, 0x00, 0x00, 0x00, 0xe9, 0xf4, 0x0f, 0x00, 0x00, 0xcc,
        ];
        assert_eq!(
            pe_adjustor_jump_stub_len(&data, 0, 0x1000, &regions),
            Some(12)
        );
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1001, &regions));
    }

    #[test]
    fn tiny_stub_scan_promotes_adjustors_only_with_code_pointer_target() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8d, 0x8a, 0x28, 0x00, 0x00, 0x00, 0xe9, 0xf4, 0x0f, 0x00, 0x00, 0xcc,
        ];
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
        assert!(!pe_tiny_stub_scan_promotes_candidate(
            &data,
            0,
            0x1000,
            &regions,
            &HashSet::new()
        ));

        let mut targets = HashSet::new();
        targets.insert(0x1000);
        assert!(pe_tiny_stub_scan_promotes_candidate(
            &data, 0, 0x1000, &regions, &targets
        ));
    }

    #[test]
    fn tiny_stub_scan_accepts_adjustor_before_prologue() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8d, 0x8a, 0x28, 0x00, 0x00, 0x00, 0xe9, 0xf4, 0x0f, 0x00, 0x00, 0x48, 0x89,
            0x54, 0x24, 0x10,
        ];
        assert_eq!(
            pe_adjustor_jump_stub_len(&data, 0, 0x1000, &regions),
            Some(12)
        );
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
    }

    #[test]
    fn tiny_stub_scan_accepts_adjustor_jump_table_entry_with_add() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x3000,
            _file_off_start: 0,
        }];
        let data = [
            0x48, 0x8b, 0x8a, 0x50, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc1, 0x08, 0xe9, 0xf0, 0x0f,
            0x00, 0x00, 0xcc,
        ];
        assert_eq!(
            pe_adjustor_jump_stub_len(&data, 0, 0x1000, &regions),
            Some(16)
        );
        assert!(pe_tiny_stub_scan_candidate(&data, 0, 0x1000, &regions));
    }

    #[test]
    fn tiny_stub_scan_accepts_bounded_return_helpers() {
        let (data, off) = data_with_pre(&[0xcc], &[0xc2, 0x00, 0x00, 0xcc]);
        assert_eq!(pe_tiny_return_helper_len(&data, off), Some(3));
        assert!(pe_tiny_stub_scan_candidate(&data, off, 0x1000, &[]));

        let (data, off) = data_with_pre(&[0xcc], &[0x33, 0xc0, 0xc3, 0xcc]);
        assert_eq!(pe_tiny_return_helper_len(&data, off), Some(3));
        assert!(pe_tiny_stub_scan_candidate(&data, off, 0x1000, &[]));

        let (data, off) = data_with_pre(&[0xcc], &[0x4d, 0x3b, 0xc8, 0x0f, 0x94, 0xc0, 0xc3, 0xcc]);
        assert_eq!(pe_tiny_return_helper_len(&data, off), Some(7));
        assert!(pe_tiny_stub_scan_candidate(&data, off, 0x1000, &[]));
    }

    #[test]
    fn simd_heads_are_not_low_confidence_function_starts() {
        let data = [0x90, 0x0f, 0x10, 0x0c, 0x11, 0xc3];
        assert!(pe_head_looks_like_simd_continuation(&data[1..]));
        assert!(!pe_low_confidence_call_target_head(&data, 1));
    }

    #[test]
    fn low_confidence_call_targets_require_a_start_shape() {
        let data = [0xcc, 0xba, 0x02, 0x00, 0x00, 0x00, 0x33, 0xc9];
        assert!(!pe_low_confidence_call_target_head(&data, 1));

        let data = [0x90, 0xc7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00];
        assert!(pe_low_confidence_call_target_head(&data, 1));
    }

    #[test]
    fn accepts_iat_thunk() {
        let (d, off) = data_with_pre(&[0xaa], &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn accepts_tiny_ret_stub() {
        let (d, off) = data_with_pre(&[0xaa], &[0x33, 0xc0, 0xc3]);
        assert!(looks_like_fn_start(&d, off));
    }

    #[test]
    fn rejects_mid_fn_continuation_no_marker() {
        // No fn-boundary marker; byte 0 is `cmp edi, 2` which is
        // valid x86 but not a recognised prologue. This is exactly
        // the false-positive pattern xref backtracking introduces.
        let (d, off) = data_with_pre(&[0xaa], &[0x83, 0xff, 0x02, 0x0f, 0x85]);
        assert!(!looks_like_fn_start(&d, off));
    }

    #[test]
    fn rejects_mid_instruction_landing() {
        // No marker, byte 0 is a ModR/M byte (0x24) -- xref-target
        // landed in the middle of an existing instruction.
        let (d, off) = data_with_pre(&[0xaa], &[0x24, 0x10, 0x00, 0x00]);
        assert!(!looks_like_fn_start(&d, off));
    }

    #[test]
    fn rejects_file_off_zero() {
        let d = vec![0x48, 0x89, 0x5c, 0x24];
        assert!(!looks_like_fn_start(&d, 0));
    }

    #[test]
    fn classifies_tail_jump_thunk() {
        let matched =
            classify_pe_thunk_head(0x1000, &[0xe9, 0xfb, 0x0f, 0x00, 0x00], true).unwrap();
        assert_eq!(matched.kind, PeThunkKind::TailJump);
        assert_eq!(matched.target_va, 0x2000);
        assert_eq!(matched.length, 5);
    }

    #[test]
    fn classifies_rip_import_jump_thunk() {
        let matched =
            classify_pe_thunk_head(0x1000, &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00], true).unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1016);
        assert_eq!(matched.length, 6);
    }

    #[test]
    fn classifies_cfg_dispatch_memory_jump_thunk() {
        let matched =
            classify_pe_thunk_head(0x1000, &[0x48, 0xff, 0x25, 0x10, 0x00, 0x00, 0x00], true)
                .unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1017);
        assert_eq!(matched.length, 7);
    }

    #[test]
    fn classifies_import_call_ret_wrapper() {
        let matched = classify_pe_thunk_head(
            0x1000,
            &[0x48, 0xff, 0x15, 0x20, 0x00, 0x00, 0x00, 0xc3],
            true,
        )
        .unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1027);
        assert_eq!(matched.length, 8);
    }

    #[test]
    fn rejects_non_wrapper_import_call() {
        assert!(classify_pe_thunk_head(
            0x1000,
            &[0x48, 0xff, 0x15, 0x20, 0x00, 0x00, 0x00, 0x90],
            true
        )
        .is_none());
    }

    /// `FF /4 disp32` is RIP-relative only in 64-bit mode.
    ///
    /// In 32-bit mode the operand is an absolute VA, and resolving it as though
    /// RIP-relative produced a target outside the image for every import thunk in
    /// `hello-c-mingw32-O2.exe`. The thunk at `0x004071e0` names the `msvcrt`
    /// `wcslen` slot at `0x0040c1fc`; the old arithmetic gave `0x008133e2`.
    #[test]
    fn classifies_x86_absolute_import_jump_thunk() {
        let head = [0xff, 0x25, 0xfc, 0xc1, 0x40, 0x00];
        let matched = classify_pe_thunk_head(0x0040_71e0, &head, false).unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x0040_c1fc);
        assert_eq!(matched.length, 6);

        let as_x64 = classify_pe_thunk_head(0x0040_71e0, &head, true).unwrap();
        assert_eq!(
            as_x64.target_va,
            0x0040_71e0 + 6 + 0x0040_c1fc,
            "the 64-bit reading is RIP-relative and lands nowhere in a PE32 image"
        );
    }

    /// The same absolute rule for the `call [disp32]; ret` wrapper shape.
    #[test]
    fn classifies_x86_absolute_import_call_ret_wrapper() {
        let matched = classify_pe_thunk_head(
            0x0040_1000,
            &[0xff, 0x15, 0x00, 0x20, 0x40, 0x00, 0xc3],
            false,
        )
        .unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x0040_2000);
        assert_eq!(matched.length, 7);
    }

    /// `0x48` is `dec eax` in 32-bit mode, not a REX prefix, so the REX-prefixed
    /// thunk encodings must not be recognised there.
    #[test]
    fn rejects_rex_prefixed_thunk_encodings_in_32_bit_mode() {
        assert!(
            classify_pe_thunk_head(0x1000, &[0x48, 0xff, 0x25, 0x10, 0x00, 0x00, 0x00], false)
                .is_none()
        );
        assert!(classify_pe_thunk_head(
            0x1000,
            &[0x48, 0x8b, 0x05, 0x30, 0x00, 0x00, 0x00, 0xff, 0xe0],
            false
        )
        .is_none());
    }

    /// Relative jumps are relative in both modes: the arch flag must not touch them.
    #[test]
    fn tail_jump_targets_do_not_depend_on_mode() {
        let head = [0xe9, 0xfb, 0x0f, 0x00, 0x00];
        assert_eq!(
            classify_pe_thunk_head(0x1000, &head, false)
                .unwrap()
                .target_va,
            classify_pe_thunk_head(0x1000, &head, true)
                .unwrap()
                .target_va
        );
    }

    #[test]
    fn classifies_mov_rax_import_jump_thunk() {
        let matched = classify_pe_thunk_head(
            0x1000,
            &[0x48, 0x8b, 0x05, 0x30, 0x00, 0x00, 0x00, 0xff, 0xe0],
            true,
        )
        .unwrap();
        assert_eq!(matched.kind, PeThunkKind::ImportMemory);
        assert_eq!(matched.target_va, 0x1037);
        assert_eq!(matched.length, 9);
    }

    #[test]
    fn thunk_scan_accepts_padded_jump_table_entry() {
        let mut data = vec![0xff, 0x25, 0x02, 0x12, 0x00, 0x00, 0xcc];
        assert!(super::pe_thunk_scan_candidate(&data, 0, 0x14000ee48, &[]));

        data[6] = 0x48;
        assert!(!super::pe_thunk_scan_candidate(&data, 0, 0x14000ee48, &[]));
    }

    #[test]
    fn thunk_scan_rejects_unpadded_neighboring_import_thunks() {
        let data = vec![
            0xff, 0x25, 0x02, 0x12, 0x00, 0x00, 0xff, 0x25, 0x0c, 0x12, 0x00, 0x00,
        ];
        assert!(!super::pe_thunk_scan_candidate(&data, 6, 0x14000ee48, &[]));
    }

    #[test]
    fn thunk_scan_accepts_padded_rex_import_jump_forms() {
        let data = vec![0x48, 0xff, 0x25, 0x30, 0x2c, 0x00, 0x00, 0xcc];
        assert!(super::pe_thunk_scan_candidate(&data, 0, 0x140001470, &[]));
    }

    #[test]
    fn resolves_rip_relative_memory_operand_va() {
        let ins = Instruction {
            address: crate::core::address::Address::new(
                crate::core::address::AddressKind::VA,
                0x1000,
                64,
                None,
                None,
            )
            .unwrap(),
            bytes: vec![0xff, 0x25, 0x10, 0x00, 0x00, 0x00],
            mnemonic: "jmp".to_string(),
            operands: vec![Operand::memory(
                0,
                Access::Read,
                Some(0x1016),
                Some("rip".to_string()),
                None,
                None,
            )],
            length: 6,
            arch: "x86_64".to_string(),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        };

        assert_eq!(memory_operand_va(&ins), Some(0x1016));
    }
}

#[cfg(test)]
mod elf_prologue_scan_tests {
    use super::*;

    /// The AArch64 prologue masks must match the real encodings and nothing else.
    ///
    /// These are bit patterns, so a wrong mask fails silently by matching
    /// everything or nothing; both were plausible and neither would surface in
    /// a metric until discovery recall moved the wrong way.
    #[test]
    fn aarch64_prologue_masks_match_the_real_encodings() {
        // stp x29, x30, [sp, #-16]!   (pre-indexed frame save)
        assert!(aarch64_unhardened_prologue(0xa9bf_7bfd));
        // stp x29, x30, [sp, #-64]!   — different immediate, same shape
        assert!(aarch64_unhardened_prologue(0xa9bc_7bfd));
        // sub sp, sp, #0x30
        assert!(aarch64_unhardened_prologue(0xd100_c3ff));
        // sub sp, sp, #0x10
        assert!(aarch64_unhardened_prologue(0xd100_43ff));

        // stp x19, x20, [sp, #-16]! — a callee-saved pair, not the frame pair,
        // and a very common instruction: matching it would over-generate badly.
        assert!(!aarch64_unhardened_prologue(0xa9bf_53f3));
        // sub x0, x0, #1 — not the stack pointer.
        assert!(!aarch64_unhardened_prologue(0xd100_0400));
        // nop
        assert!(!aarch64_unhardened_prologue(0xd503_201f));
        // ret
        assert!(!aarch64_unhardened_prologue(0xd65f_03c0));
    }

    /// The x86-64 head predicate accepts real GCC/Clang entries and rejects
    /// mid-function bytes.
    #[test]
    fn elf_x86_prologue_head_is_specific() {
        assert!(elf_x86_prologue_head(&[0xf3, 0x0f, 0x1e, 0xfa])); // endbr64
        assert!(elf_x86_prologue_head(&[0x55, 0x48, 0x89, 0xe5])); // push rbp; mov rbp,rsp
        assert!(elf_x86_prologue_head(&[0x48, 0x83, 0xec, 0x28])); // sub rsp, 0x28

        assert!(!elf_x86_prologue_head(&[0x90])); // nop
        assert!(!elf_x86_prologue_head(&[0xc3])); // ret
        assert!(!elf_x86_prologue_head(&[0x48, 0x89, 0xc6])); // mov rsi, rax
        assert!(!elf_x86_prologue_head(&[]));
    }

    /// On a real ELF the scan must not invent starts outside executable memory.
    #[test]
    fn elf_scan_stays_inside_executable_regions() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            eprintln!("skipping ELF prologue scan test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let (regions, arch, _, _) = parse_exec_regions(&data);
        let starts = scan_elf_prologue_function_starts(None, &data, &regions, arch);
        assert!(
            !starts.is_empty(),
            "no prologue candidates on a real unstripped C++ binary"
        );
        for va in &starts {
            assert!(
                regions.iter().any(|r| *va >= r.start && *va < r.end),
                "candidate {va:#x} is outside every executable region"
            );
        }
    }

    /// A PE must not be fed to the ELF scan, and vice versa.
    #[test]
    fn elf_scan_rejects_non_elf_input() {
        let regions = vec![ExecRegion {
            start: 0x1000,
            end: 0x2000,
            _file_off_start: 0,
        }];
        assert!(
            scan_elf_prologue_function_starts(None, b"MZ\x90\x00", &regions, BArch::X86_64)
                .is_empty()
        );
    }
}
