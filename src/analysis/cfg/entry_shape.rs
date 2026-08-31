//! "Does this byte sequence look like a function start?"
//!
//! One question, asked of raw bytes: is the head at this offset the entry of a
//! real function, or an interior label that an xref happened to land on? Every
//! predicate here answers some form of it, and none of them disassembles, walks
//! a block, or touches a `Function` -- they read a byte window and return a
//! verdict. That is the seam: the parent `cfg` module decides what to do with
//! the verdict, and the sibling `scan` module decides which offsets to ask
//! about.
//!
//! Three layers, low to high:
//!
//! - **Prologue shape.** [`has_function_boundary_marker`] looks *backwards* one
//!   to four bytes for the padding an MSVC-style compiler emits between
//!   functions; [`head_looks_like_fn_start`] looks *forwards* for a recognised
//!   x86-64 prologue; [`looks_like_fn_start`] is their disjunction; and
//!   [`pe_head_looks_like_simd_continuation`] is the veto that keeps a
//!   vectorised loop body from reading as an entry.
//! - **Thunk shape.** [`classify_pe_thunk_head`] recognises the handful of
//!   canonical one-block jump/call wrappers, reporting target and length
//!   through [`PeThunkMatch`]. It is deliberately narrower than
//!   [`looks_like_fn_start`]: this one *labels* a function, that one only
//!   decides whether an address is safe to promote to a seed.
//! - **Composed gates.** [`pe_tail_target_looks_like_function_start`],
//!   [`elf_x86_tail_target_looks_like_function_start`] and
//!   [`pe_xref_seed_looks_like_function_start`] are the three questions the
//!   parent's walk actually asks.
//!
//! `pe_va_to_file_off` and `indexed_code_offset` stay in
//! [`super::image_view`]: they are shared address plumbing with callers all
//! over `cfg`, and answering "where are these bytes" is not this module's
//! question. `classify_function_shapes` DOES live here, at the foot of the
//! file. It mutates `Function` metadata, which no other item here does, but
//! every judgement it makes is `classify_pe_thunk_head`'s -- it is this
//! module's predicate applied to the whole discovered set, and splitting the
//! two left the promotion rule and the shape rule free to drift apart.
//!
//! The tests for these predicates live in `scan::prologue_gate_tests` and stay
//! there. That module is not a test module for this one: its cases interleave
//! these predicates with `scan`'s own (`pe_prologue_scan_candidate`,
//! `pe_tiny_stub_scan_candidate`, `pe_low_confidence_call_target_head`), and
//! `simd_heads_are_not_low_confidence_function_starts` asserts one of each
//! inside a single test. Moving them would mean splitting that test.

use crate::core::binary::Arch as BArch;

use super::*;

pub(super) fn pe_tail_target_looks_like_function_start(
    data: &[u8],
    target_va: u64,
    is_64bit: bool,
) -> bool {
    let Some(file_off) = pe_va_to_file_off(data, target_va) else {
        return false;
    };
    if file_off >= data.len() {
        return false;
    }
    if has_function_boundary_marker(data, file_off) {
        return true;
    }
    let head_end = std::cmp::min(file_off.saturating_add(16), data.len());
    classify_pe_thunk_head(target_va, &data[file_off..head_end], is_64bit).is_some()
}

/// Does an x86 ELF direct-jump target carry strong independent function-entry
/// evidence?
///
/// A bare long jump is not enough: optimized functions contain distant cold
/// blocks and switch arms.  CET's ENDBR landing pad followed immediately by a
/// recognised prologue is much narrower and survives fully stripping the local
/// symbol.  This is the shape produced by sibling-call wrappers in current GCC
/// and Clang output (for example DecBench libedit's `em_inc_search_prev`).
pub(super) fn elf_x86_tail_target_looks_like_function_start(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    target_va: u64,
    arch: BArch,
) -> bool {
    if !matches!(arch, BArch::X86 | BArch::X86_64) || !data.starts_with(b"\x7fELF") {
        return false;
    }
    let Some(file_off) = indexed_code_offset(image, data, target_va) else {
        return false;
    };
    let Some(head) = data.get(file_off..) else {
        return false;
    };
    let landing_pad_len = match head {
        [0xf3, 0x0f, 0x1e, 0xfa, ..] if arch == BArch::X86_64 => 4,
        [0xf3, 0x0f, 0x1e, 0xfb, ..] if arch == BArch::X86 => 4,
        _ => return false,
    };
    let after_landing_pad = &head[landing_pad_len..];
    head_looks_like_fn_start(after_landing_pad)
        // SysV prologues commonly save a low callee-saved register without a
        // REX prefix.  This is too weak for the general xref-start gate, but is
        // strong enough behind an architecture-matching CET landing pad.
        || matches!(after_landing_pad, [0x53 | 0x55 | 0x56 | 0x57, ..])
}

/// Heuristic: does `data[file_off..]` look like the start of a real
/// function?
///
/// Used to gate xref-target promotion in the recursive worklist.
/// Trusted seeds (symbol table, .pdata, FLIRT, vtable, jump-table,
/// entrypoint) MUST NOT be subjected to this gate -- it's only for
/// the addresses we follow via direct-call/jump xrefs, which can
/// land in the middle of an existing function's body (mid-fn
/// continuation labels) or even mid-instruction.
///
/// "Looks like a fn start" rule:
///
/// 1. **Strong yes**: the byte just before `file_off` is a function-
///    boundary marker emitted by the MSVC compiler:
///    - `0xcc` (INT3 padding, the dominant case on Win64)
///    - `0xc3` (RET; previous function ended)
///    - `0x90` (single-byte NOP padding)
///    - `0x66 0x90` (2-byte NOP via `xchg ax, ax`)
///    - `0x0f 0x1f ..` (3+ byte NOP families)
/// 2. **Otherwise**: byte 0 must match a recognised x86-64 prologue
///    pattern (REX-prefix push, parameter spill, frame setup, IAT
///    thunk, RET stub, ...).
///
/// Returns `true` if either signal fires, `false` if neither does.
/// Empirical validation on ntoskrnl's 31,729 g-only seeds (asb
/// iter 14 sweep): ~77 % have neither signal and are rejected as
/// likely mid-instruction xref landings.
#[allow(dead_code)]
pub(super) fn looks_like_fn_start(data: &[u8], file_off: usize) -> bool {
    if file_off == 0 || file_off >= data.len() {
        return false;
    }
    has_function_boundary_marker(data, file_off) || head_looks_like_fn_start(&data[file_off..])
}

pub(super) fn has_function_boundary_marker(data: &[u8], file_off: usize) -> bool {
    if file_off == 0 || file_off >= data.len() {
        return false;
    }
    let prev = data[file_off - 1];
    if prev == 0xcc || prev == 0xc3 || prev == 0x90 {
        return true;
    }
    // 2-byte NOP via `xchg ax, ax`
    if file_off >= 2 && data[file_off - 2] == 0x66 && prev == 0x90 {
        return true;
    }
    // Multi-byte NOP encodings (0f 1f .. /0 series)
    if file_off >= 3 && data[file_off - 3] == 0x0f && data[file_off - 2] == 0x1f {
        return true;
    }
    if file_off >= 4
        && data[file_off - 4] == 0x0f
        && data[file_off - 3] == 0x1f
        && data[file_off - 2] == 0x40
    {
        return true;
    }
    false
}

pub(super) fn head_looks_like_fn_start(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    // Recognised x86-64 function prologue patterns.
    match head {
        // mov [rsp+disp8], rXX (REX.W parameter spill: 48 89 X 24 ..)
        [0x48, 0x89, _, 0x24, ..] => true,
        // REX-prefixed push rbx/rbp/rsi/rdi (40 53/55/56/57)
        [0x40, 0x53 | 0x55 | 0x56 | 0x57, ..] => true,
        // push r12-r15 (41 54/55/56/57)
        [0x41, 0x54 | 0x55 | 0x56 | 0x57, ..] => true,
        // sub rsp, imm8 / imm32
        [0x48, 0x83, 0xec, ..] => true,
        [0x48, 0x81, 0xec, ..] => true,
        // mov rax, rsp (SEH frame setup)
        [0x48, 0x8b, 0xc4, ..] => true,
        // jmp rel32 (tail-call thunk)
        [0xe9, ..] => true,
        // jmp [rip+rel32] (IAT thunk)
        [0xff, 0x25, ..] => true,
        // mov eax, imm32 (HRESULT stub / syscall stub)
        [0xb8, ..] => true,
        // xor eax, eax; ret (tiny RET stub)
        [0x33, 0xc0, 0xc3, ..] => true,
        // mov rax, gs:[imm32] (TEB-access prologue)
        [0x65, 0x48, 0x8b, 0x04, 0x25, ..] => true,
        _ => false,
    }
}

pub(super) fn pe_xref_seed_looks_like_function_start(data: &[u8], va: u64) -> bool {
    match pe_va_to_file_off(data, va) {
        Some(file_off) => {
            if file_off >= data.len() {
                return false;
            }
            !pe_head_looks_like_simd_continuation(&data[file_off..])
                && looks_like_fn_start(data, file_off)
        }
        None => false,
    }
}

pub(super) fn pe_head_looks_like_simd_continuation(head: &[u8]) -> bool {
    matches!(
        head,
        // movups/movaps and related SSE load/store forms commonly appear
        // after alignment NOPs inside vectorized loops. A raw xref landing
        // there is a block label, not a function entry.
        [0x0f, 0x10 | 0x11 | 0x28 | 0x29 | 0x6f | 0x7f, ..]
            // VEX/EVEX vector op prefixes.
            | [0xc4 | 0xc5 | 0x62, ..]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeThunkKind {
    /// A direct jump to another code address.
    TailJump,
    /// A jump/call wrapper through an IAT-like memory slot.
    ImportMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PeThunkMatch {
    pub(super) kind: PeThunkKind,
    pub(super) target_va: u64,
    pub(super) length: usize,
}

fn add_signed_u64(base: u64, disp: i64) -> Option<u64> {
    if disp >= 0 {
        base.checked_add(disp as u64)
    } else {
        base.checked_sub(disp.unsigned_abs())
    }
}

pub(super) fn read_i32_le_at(data: &[u8], off: usize) -> Option<i32> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_le_bytes)
}

pub(super) fn rel_target(entry_va: u64, insn_len: u64, disp: i64) -> Option<u64> {
    add_signed_u64(entry_va.checked_add(insn_len)?, disp)
}

/// Classify PE/x86 function heads that are really tiny thunk wrappers.
///
/// This is intentionally narrower than `looks_like_fn_start`: that helper
/// decides whether an xref target is safe to promote into a function seed,
/// while this one mutates the resulting `Function` metadata. Only canonical
/// one-block jump/call-wrapper shapes are labelled `FunctionKind::Thunk`.
///
/// # `is_64bit` is not a formality
///
/// `FF /4 disp32` is `jmp [rip+disp32]` on x86-64 and `jmp [disp32]` — a plain
/// ABSOLUTE address — on 32-bit x86. RIP-relative addressing does not exist in
/// 32-bit mode, so resolving a PE32 import thunk as `entry + 6 + disp` produces
/// a VA that points nowhere. Measured on
/// `samples/binaries/platforms/windows/i386/export/windows/i686/O2/hello-c-mingw32-O2.exe`:
/// all 34 of its `FF 25` import thunks resolved outside the image (e.g. the
/// `msvcrt!wcslen` thunk at `0x004071e0` gave `0x8133e2` where the operand names
/// `0x0040c1fc`), and `classify_function_shapes` stored every one of them in
/// `Function::thunk_target`. That gate admits `BArch::X86` explicitly, so the
/// path was live, not hypothetical.
///
/// The `0x48` (REX.W) forms are 64-bit-only encodings: in 32-bit mode `0x48` is
/// `dec eax`, a different instruction, so they are rejected rather than
/// reinterpreted.
pub(super) fn classify_pe_thunk_head(
    entry_va: u64,
    head: &[u8],
    is_64bit: bool,
) -> Option<PeThunkMatch> {
    // jmp rel32 — relative in both modes.
    if head.len() >= 5 && head[0] == 0xe9 {
        let target_va = rel_target(entry_va, 5, read_i32_le_at(head, 1)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::TailJump,
            target_va,
            length: 5,
        });
    }
    // jmp rel8 — relative in both modes.
    if head.len() >= 2 && head[0] == 0xeb {
        let target_va = rel_target(entry_va, 2, head[1] as i8 as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::TailJump,
            target_va,
            length: 2,
        });
    }
    // jmp/call [rip+disp32] (x64) or jmp/call [disp32] (x86).
    if head.len() >= 6 && head[0] == 0xff && (head[1] == 0x25 || head[1] == 0x15) {
        if head[1] == 0x15 && head.get(6) != Some(&0xc3) {
            return None;
        }
        let operand = read_i32_le_at(head, 2)?;
        let target_va = if is_64bit {
            rel_target(entry_va, 6, operand as i64)?
        } else {
            u64::from(operand as u32)
        };
        return Some(PeThunkMatch {
            kind: PeThunkKind::ImportMemory,
            target_va,
            length: if head[1] == 0x15 { 7 } else { 6 },
        });
    }
    // REX.W jmp/call qword ptr [rip+disp32] — a 64-bit-only encoding.
    if is_64bit
        && head.len() >= 7
        && head[0] == 0x48
        && head[1] == 0xff
        && (head[2] == 0x25 || head[2] == 0x15)
    {
        if head[2] == 0x15 && head.get(7) != Some(&0xc3) {
            return None;
        }
        let target_va = rel_target(entry_va, 7, read_i32_le_at(head, 3)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::ImportMemory,
            target_va,
            length: if head[2] == 0x15 { 8 } else { 7 },
        });
    }
    // mov rax, qword ptr [rip+disp32]; jmp rax — a 64-bit-only encoding.
    if is_64bit && head.len() >= 9 && head[0..3] == [0x48, 0x8b, 0x05] && head[7..9] == [0xff, 0xe0]
    {
        let target_va = rel_target(entry_va, 7, read_i32_le_at(head, 3)? as i64)?;
        return Some(PeThunkMatch {
            kind: PeThunkKind::ImportMemory,
            target_va,
            length: 9,
        });
    }
    None
}

// The whole-result pass over the shapes above.
//
// `classify_pe_thunk_head` answers "is this 16 bytes a thunk head?"; this is the
// sweep that asks it of every discovered function small enough to be one, and
// promotes the matches to `FunctionKind::Thunk` with a resolved target. It sits
// here because it has no independent judgement -- every decision it makes is
// this file's, applied to the discovered set.

#[derive(Debug, Clone, Default)]
pub(super) struct FunctionShapeStats {
    pub(super) thunk_functions: usize,
    pub(super) import_thunk_functions: usize,
    pub(super) tail_thunk_functions: usize,
    pub(super) tiny_functions_le8: usize,
    pub(super) tiny_functions_le32: usize,
}

pub(super) fn classify_function_shapes(
    data: &[u8],
    arch: BArch,
    functions: &mut [Function],
) -> FunctionShapeStats {
    let mut stats = FunctionShapeStats::default();
    let is_pe_image = data.len() >= 2 && &data[..2] == b"MZ";
    let bits = if arch.is_64_bit() { 64 } else { 32 };

    for func in functions {
        let size = func.total_size();
        if size <= 8 {
            stats.tiny_functions_le8 = stats.tiny_functions_le8.saturating_add(1);
        }
        if size <= 32 {
            stats.tiny_functions_le32 = stats.tiny_functions_le32.saturating_add(1);
        }
        if !is_pe_image || !(arch.is_64_bit() || arch == BArch::X86) || size > 32 {
            continue;
        }
        let Some(file_off) = pe_va_to_file_off(data, func.entry_point.value) else {
            continue;
        };
        if file_off >= data.len() {
            continue;
        }
        let head_end = std::cmp::min(file_off.saturating_add(16), data.len());
        let Some(matched) = classify_pe_thunk_head(
            func.entry_point.value,
            &data[file_off..head_end],
            arch.is_64_bit(),
        ) else {
            continue;
        };
        if let Ok(target) = Address::new(AddressKind::VA, matched.target_va, bits, None, None) {
            func.kind = FunctionKind::Thunk;
            func.thunk_target = Some(target);
            stats.thunk_functions = stats.thunk_functions.saturating_add(1);
            match matched.kind {
                PeThunkKind::TailJump => {
                    stats.tail_thunk_functions = stats.tail_thunk_functions.saturating_add(1);
                }
                PeThunkKind::ImportMemory => {
                    stats.import_thunk_functions = stats.import_thunk_functions.saturating_add(1);
                }
            }
        }
    }

    stats
}
