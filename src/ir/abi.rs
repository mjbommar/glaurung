//! What a calling convention says a call does, recorded on the call itself.
//!
//! An instruction stream does not say which ABI it obeys, so the lifter cannot fill
//! this in: `call 0x1234` is the same bytes under SysV and Win64. The convention is
//! known one level up, where the function is decompiled — so this pass runs there,
//! once, and writes the effects onto every [`Op::Call`].
//!
//! Everything downstream then reads them from the op instead of deciding for itself
//! what a call means. That is the point: before this existed,
//! [`crate::ir::use_def::def_uses`] reported a call as defining nothing and using
//! nothing, so
//!
//! * a read of the return register after a call saw the value from BEFORE it — `fib`
//!   recursed and then used its own argument where the returned value belonged;
//! * the argument-register setup looked dead, so value numbering renamed it out from
//!   under argument reconstruction and calls rendered with no arguments at all;
//! * and every pass that wanted the truth had to special-case calls, which is how the
//!   same ABI knowledge ended up restated in `naming`, `dead_stores`, `value_number`
//!   and the renderers.
//!
//! The effects deliberately describe the ABI, not this program: `result` is written by
//! every call whether or not the source used it. Whether the *program* consumed it is
//! a separate question, answered later (`call_args::attribute_call_results`) and for a
//! different purpose — printing an assignment.

use crate::ir::call_args::CallConv;
use crate::ir::regview;
use crate::ir::types::{CallEffects, LlirFunction, Op, VReg};
use crate::ir::use_def::def_uses;

/// The register a callee leaves its return value in.
pub fn return_register(cc: CallConv) -> &'static str {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => "rax",
        CallConv::Cdecl32 => "rax",
        CallConv::Aarch64 => "x0",
        CallConv::Arm | CallConv::ArmHardFloat => "r0",
    }
}

/// Bytes in one general-purpose register for this calling convention.
///
/// This is a machine-model fact shared by ABI storage reconstruction and C
/// type spelling.  It must not be inferred from a register name (`rax` is the
/// canonical SSA parent even for i386).
pub fn machine_word_bytes(cc: CallConv) -> u8 {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64 => 8,
        CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => 4,
    }
}

/// The width of the widest integer result an ABI splits over two general-purpose
/// registers: exactly two machine words.
///
/// ILP32 conventions split an eight-byte `long long`; System V AMD64 splits a
/// sixteen-byte INTEGER-class value (`__int128`, or an aggregate whose two
/// eightbytes are both INTEGER) over `rax:rdx`. Deriving the width from the
/// machine word keeps one rule instead of a per-convention constant.
pub fn wide_integer_return_width(cc: CallConv) -> u8 {
    machine_word_bytes(cc).saturating_mul(2)
}

/// Low/high general-purpose registers for an integer result of exactly two
/// machine words.
///
/// The names are the canonical SSA spellings.  Returning `None` is deliberate:
/// a convention with no two-register integer result contract must not acquire
/// one, and any other width is a single register or a different storage class
/// entirely.
///
/// This is the register PAIR, not an alias set. [`return_registers`] lists other
/// spellings of ONE logical result; `rax:rdx` is two values that together carry
/// one, which is why it cannot be expressed by appending to that list.
pub fn wide_integer_return_pair(
    cc: CallConv,
    value_width: u8,
) -> Option<(&'static str, &'static str)> {
    if value_width != wide_integer_return_width(cc) {
        return None;
    }
    match cc {
        CallConv::Cdecl32 => Some(("rax", "rdx")),
        CallConv::Arm | CallConv::ArmHardFloat => Some(("r0", "r1")),
        CallConv::SysVAmd64 => Some(("rax", "rdx")),
        // Win64 returns any aggregate larger than one register through a hidden
        // pointer, so it has no register-pair result. AAPCS64 uses `x0:x1`, but
        // there are no fixtures returning a 16-byte aggregate on that target to
        // measure the change against; keep it fail-closed.
        CallConv::Win64 | CallConv::Aarch64 => None,
    }
}

/// Which half of a two-register integer result a register name denotes.
///
/// Sub-register spellings are folded onto their half: a 32-bit write to the
/// high register still writes the same half of the same logical value.
pub fn wide_integer_return_part(cc: CallConv, name: &str) -> Option<usize> {
    let base = ssa_base(name);
    let (low, high) = wide_integer_return_pair(cc, wide_integer_return_width(cc))?;
    let x86 = matches!(cc, CallConv::Cdecl32 | CallConv::SysVAmd64);
    if base == low || (x86 && ["eax", "ax", "al"].contains(&base)) {
        Some(0)
    } else if base == high || (x86 && ["edx", "dx", "dl"].contains(&base)) {
        Some(1)
    } else {
        None
    }
}

/// The class of one eight-byte chunk of a System V AMD64 aggregate.
///
/// The full ABI has more classes (X87, COMPLEX_X87, NO_CLASS); this models the
/// two that reach a register, and anything else is reported by refusing to
/// classify at all rather than by guessing one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eightbyte {
    /// Allocated from the general-purpose result bank (`rax`, then `rdx`).
    Integer,
    /// Allocated from the SSE result bank (`xmm0`, then `xmm1`).
    Sse,
}

/// How a calling convention hands a source-level result back to its caller.
///
/// This is the fact [`return_registers`] cannot express. That list is the set of
/// SPELLINGS of one logical result — `rax`/`eax`/`ax`/`al` are four names for
/// the same bits — so adding `rdx` to it would claim `rdx` is another name for
/// `rax`. A 16-byte INTEGER aggregate instead puts DIFFERENT bytes in each, and
/// a MEMORY-class aggregate puts none of them in a register at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReturnClass {
    /// One logical value in one bank: the existing scalar contract.
    #[default]
    Single,
    /// Two INTEGER eightbytes in the general-purpose result pair (`rax:rdx`).
    IntegerPair,
    /// One INTEGER and one SSE eightbyte, in the source order the two banks are
    /// consumed. `integer_first` distinguishes `{int; double;}` (`rax` then
    /// `xmm0`) from `{double; int;}` (`xmm0` then `rax`).
    SplitBanks { integer_first: bool },
    /// MEMORY: the caller allocates the object and passes its address in a
    /// hidden first INTEGER argument register; the callee returns that address
    /// in the result register and every declared argument shifts one slot right.
    Memory,
}

/// Classify a System V AMD64 aggregate result from its size and eightbyte classes.
///
/// `eightbytes` must describe the object from offset zero in eight-byte steps.
/// An empty slice, or one disagreeing with `size`, is not classifiable and
/// yields `None` — a wrong class produces C that compiles and returns the wrong
/// bytes, so an unprovable shape must keep the caller's existing behaviour.
pub fn sysv_amd64_return_class(size: u64, eightbytes: &[Eightbyte]) -> Option<ReturnClass> {
    if size == 0 {
        return None;
    }
    // The ABI's own cutoff. Beyond it no field classification matters: the
    // object is MEMORY however its fields are typed.
    if size > 16 {
        return Some(ReturnClass::Memory);
    }
    if eightbytes.len() != usize::try_from(size.div_ceil(8)).ok()? {
        return None;
    }
    match eightbytes {
        [Eightbyte::Integer] | [Eightbyte::Sse] => Some(ReturnClass::Single),
        [Eightbyte::Integer, Eightbyte::Integer] => Some(ReturnClass::IntegerPair),
        [Eightbyte::Integer, Eightbyte::Sse] => Some(ReturnClass::SplitBanks {
            integer_first: true,
        }),
        [Eightbyte::Sse, Eightbyte::Integer] => Some(ReturnClass::SplitBanks {
            integer_first: false,
        }),
        // Two SSE eightbytes return in `xmm0:xmm1`, which the value model has no
        // second float result register for. Fail closed.
        _ => None,
    }
}

/// The integer argument registers, in ABI order — canonical (widest) names only.
///
/// Prefer [`argument_slots`] when matching a register NAME found in code: a 32-bit
/// write (`%edi = …`) sets the same parameter slot, and this list does not say so.
pub fn argument_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        CallConv::Win64 => &["rcx", "rdx", "r8", "r9"],
        CallConv::Cdecl32 => &[],
        CallConv::Aarch64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        CallConv::Arm => &["r0", "r1", "r2", "r3"],
        // Calls can mix the independent core and VFP allocation banks.  Keep
        // every register candidate as a use until a recovered callee
        // prototype can narrow the exact storage map; over-approximating uses
        // is safe, while omitting s0-s15 deletes real argument setup.
        CallConv::ArmHardFloat => &[
            "r0", "r1", "r2", "r3", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
            "s10", "s11", "s12", "s13", "s14", "s15",
        ],
    }
}

/// The SSE argument registers, in ABI order — whole-register names only.
///
/// This is a SECOND argument bank, not more entries in the first one, and the
/// distinction is the whole reason it exists. Under System V AMD64 the INTEGER
/// and SSE classes are allocated from two INDEPENDENT counters:
/// `f(int a, float b, int c, float d)` puts `a` in `rdi`, `c` in `rsi`, `b` in
/// `xmm0` and `d` in `xmm1`. A source parameter's POSITION is therefore not its
/// index in either bank, which is exactly what [`argument_slots`] — one flat
/// positional table — cannot express. Consumers that need a mixed signature's
/// storage must walk both banks with their own counters
/// (`types_recover::locked_sysv_amd64_parameter_storage`); consumers that only
/// need "is this register an argument register" may use either table directly.
///
/// Windows x64 differs and the difference is recorded rather than smoothed
/// over: it passes at most four SSE arguments, and from an index SHARED with
/// the integer bank, so `f(int, float)` puts the float in `xmm1`. Class-aware
/// mapping is deliberately not wired for it — there are no Windows fixtures in
/// `tests/decompiler_fixtures/` to measure such a change against.
pub fn sse_argument_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &[
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        ],
        CallConv::Win64 => &["xmm0", "xmm1", "xmm2", "xmm3"],
        CallConv::Cdecl32 | CallConv::Aarch64 | CallConv::Arm | CallConv::ArmHardFloat => &[],
    }
}

/// General-purpose registers an ordinary call may overwrite.
///
/// These are canonical storage names, not every sub-register spelling.  The
/// executable IR records only the result register as a value-producing DEF,
/// while program-level abstract interpreters also need to discard transient
/// facts held in every caller-saved register across the call boundary.
pub fn caller_saved_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        CallConv::Win64 => &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
        CallConv::Cdecl32 => &["rax", "rcx", "rdx"],
        CallConv::Aarch64 => &[
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x18", "x30",
        ],
        CallConv::Arm | CallConv::ArmHardFloat => &["r0", "r1", "r2", "r3", "r12", "lr"],
    }
}

/// Every spelling of each argument slot, in ABI order: the 64-bit name first, then
/// the narrower aliases that write the same logical parameter.
///
/// ONE table. It was previously written out in both `call_args` and `value_number`,
/// and they disagreed about more than formatting — `call_args` matched these names
/// literally while `value_number` had already renamed registers to `canon#version`,
/// so an argument arriving as `rdi#3` matched nothing and every call on that path
/// silently lost all of its arguments. Two copies of a fact are two chances to be
/// out of step with a third thing.
pub fn argument_slots(cc: CallConv) -> &'static [&'static [&'static str]] {
    match cc {
        CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Win64 => &[
            &["rcx", "ecx", "cx", "cl"],
            &["rdx", "edx", "dx", "dl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Cdecl32 => &[],
        CallConv::Aarch64 => &[
            &["x0", "w0"],
            &["x1", "w1"],
            &["x2", "w2"],
            &["x3", "w3"],
            &["x4", "w4"],
            &["x5", "w5"],
            &["x6", "w6"],
            &["x7", "w7"],
        ],
        CallConv::Arm | CallConv::ArmHardFloat => &[&["r0"], &["r1"], &["r2"], &["r3"]],
    }
}

/// Every spelling of the return register, widest first.
pub fn return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        // The SSE class returns in `xmm0`, and it is the ONLY place a `float`
        // or `double` result can arrive under either x86-64 convention. Listing
        // it here is what lets the naming pass call that value `ret` instead of
        // an anonymous `varN`; without it every float-returning function
        // rendered its recovered result into a dead variable and returned zero.
        // Ordered after the integer names deliberately: when a function writes
        // both, `rax` is the result and `xmm0` was scratch, and the naming pass
        // takes the first alias that is still unclaimed.
        CallConv::SysVAmd64 | CallConv::Win64 => &["rax", "eax", "ax", "al", "xmm0"],
        // SSA canonicalises EAX and its subregisters to the RAX parent name
        // even when decoding a 32-bit binary, so keep that logical spelling at
        // the head of the alias set as the decompiler's logical return value.
        // i386 returns floating point on the x87 stack, not in an SSE register:
        // `st0` is the bottom absolute slot `crate::ir::x87` lifts the stack
        // into, and at the depth of 1 the ABI permits at a return it IS
        // `%st(0)`. Listing it is what lets the naming pass call an x87 result
        // `ret` instead of an anonymous `varN` — the same hole `xmm0` had above
        // and `v0`/`d0`/`s0` had for AArch64, now closed for the third bank.
        // Ordered after the integer names for the same reason: when a function
        // writes both, `rax` is the result and the stack slot was scratch.
        CallConv::Cdecl32 => &["rax", "eax", "ax", "al", "st0"],
        // AAPCS64 returns an integer or pointer in `x0` and a scalar float or
        // double in `v0`, whose scalar views are spelled `d0` and `s0`. Listing
        // the float names is what lets the naming pass call that value `ret`
        // instead of an anonymous `varN` — the same reason `xmm0` is listed
        // above, and its absence here is why every float-returning AArch64
        // function returned its first argument. Ordered after the integer
        // names for the same reason: when a function writes both, `x0` is the
        // result and the vector register was scratch.
        CallConv::Aarch64 => &["x0", "w0", "v0", "d0", "s0"],
        // AAPCS hard-float returns scalar FP values in s0/d0. Keep those
        // storage alternatives visible to value numbering; prototype recovery
        // decides which class is the actual source result.
        CallConv::Arm | CallConv::ArmHardFloat => &["r0", "s0", "d0"],
    }
}

/// General-purpose storage aliases for one scalar result.
pub fn integer_return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        CallConv::Arm | CallConv::ArmHardFloat => &["r0"],
    }
}

/// Floating-point storage aliases for one scalar result.
pub fn float_return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["xmm0", "ymm0", "zmm0"],
        CallConv::Cdecl32 => &["st0", "xmm0"],
        CallConv::Aarch64 => &["v0", "q0", "d0", "s0", "h0", "b0"],
        CallConv::Arm | CallConv::ArmHardFloat => &["d0", "s0"],
    }
}

/// The non-aliasing ABI result bank containing `name`.
///
/// Integer and floating-point result storage must be tracked independently: a
/// write to `rax` does not overwrite `xmm0`, and a write to `r0` does not
/// overwrite `d0`. Returning the complete class lets reaching-definition
/// consumers use one machine-model owner instead of restating those tables.
pub fn return_register_class(cc: CallConv, name: &str) -> Option<&'static [&'static str]> {
    let base = ssa_base(name);
    for class in [integer_return_registers(cc), float_return_registers(cc)] {
        if class.contains(&base) {
            return Some(class);
        }
    }
    None
}

/// A value-numbered register's underlying name: `rdi#3` -> `rdi`.
///
/// Canonicalising here rather than at each call site is what keeps the slot tables
/// usable on both the value-numbered and the raw pipeline. Matching a versioned
/// name against a bare table is the bug this exists to prevent.
pub fn ssa_base(name: &str) -> &str {
    name.split_once('#').map_or(name, |(base, _)| base)
}

/// The argument slot a register name denotes, tolerating SSA versions and
/// sub-register spellings. `None` when the register is not an argument register.
pub fn argument_slot_of(cc: CallConv, name: &str) -> Option<usize> {
    let canon = ssa_base(name);
    argument_slots(cc)
        .iter()
        .position(|names| names.contains(&canon))
}

/// Length of the source-level fixed-parameter prefix proven by recovered storage.
///
/// SysV AMD64 allocates fixed general-purpose parameters consecutively through
/// `rdi, rsi, rdx, rcx, r8, r9`.  Definition-site liveness can miss an unused
/// parameter, but a later live register does not prove the missing parameter or
/// any register after it.  Stop at the first hole instead of turning unrelated
/// caller-saved residue into a fixed source signature.  Other conventions keep
/// their existing layouts: AAPCS hard-float has independent allocation banks,
/// and their recovery needs richer class-aware ordering than a single prefix.
pub(crate) fn fixed_parameter_prefix_len(cc: CallConv, recovered: &[VReg]) -> usize {
    if cc != CallConv::SysVAmd64 {
        return recovered.len();
    }

    let recovered_slots = recovered
        .iter()
        .filter_map(|register| match register {
            VReg::Phys(name) => argument_slot_of(cc, name),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    (0..argument_slots(cc).len())
        .take_while(|slot| recovered_slots.contains(slot))
        .count()
}

/// Whether a register name is the return register, tolerating the same spellings.
pub fn is_return_register(cc: CallConv, name: &str) -> bool {
    return_registers(cc).contains(&ssa_base(name))
}

/// The effects of any call under `cc`.
///
/// `args` is the INTEGER argument bank only, deliberately. Adding SysV's
/// `xmm0`-`xmm7` to this may-use set was tried on 2026-08-12 to keep float
/// argument setup alive through dead-code elimination, and measured: it gained
/// nothing (all 25 float-corpus improvements hold without it) and cost twelve
/// regressions in functions containing no SSE instruction at all —
/// `164_nested_tlv_walker`, `150_obfuscation_composite`, `10_cpp_runtime_shapes`
/// and `84_compound_literals`, every one of them at `gcc:O0` and every one of
/// them a caller. Eight undefined live-in registers per call is not a free
/// over-approximation.
///
/// The full argument-register set is listed as uses rather than a recovered arity: the
/// callee is usually unknown, and claiming a narrower set would let dead-code
/// elimination delete an argument setup that a real callee reads. Over-approximating
/// uses keeps code alive that might matter; under-approximating deletes code that
/// does.
pub fn call_effects(cc: CallConv) -> CallEffects {
    CallEffects {
        result: Some(VReg::phys(return_register(cc))),
        result_is_source_value: true,
        args: argument_registers(cc)
            .iter()
            .map(|n| VReg::phys(*n))
            .collect(),
        proven_args: Vec::new(),
        args_are_exact: false,
        is_tail_call: false,
    }
}

/// Scalar VFP parameter registers in AAPCS-VFP allocation order.
pub fn arm_hard_float_argument_slots() -> &'static [&'static [&'static str]] {
    &[
        &["s0"],
        &["s1"],
        &["s2"],
        &["s3"],
        &["s4"],
        &["s5"],
        &["s6"],
        &["s7"],
        &["s8"],
        &["s9"],
        &["s10"],
        &["s11"],
        &["s12"],
        &["s13"],
        &["s14"],
        &["s15"],
    ]
}

/// The register-view namespace a convention's result registers are spelled in,
/// or `None` for a convention whose architecture has no modelled sub-register
/// views (ARM32 has none).
fn result_view_arch(cc: CallConv) -> Option<regview::Arch> {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => Some(regview::Arch::X86_64),
        CallConv::Aarch64 => Some(regview::Arch::AArch64),
        CallConv::ArmHardFloat | CallConv::Arm | CallConv::Cdecl32 => None,
    }
}

/// Whether value-numbered register `base` reads storage a definition of
/// whole-register `candidate` would have to land on — the same name, or one of
/// its scalarised dword lanes.
///
/// A scalar 32-bit XMM transfer (`movd`/`movss`) lifts as a read or write of
/// exactly one lane, spelled `xmm0_d0`..`xmm0_d3`. Those lanes name real bits of
/// `xmm0`, but `crate::ir::regview::ssa_parent` deliberately declines to merge a
/// vector view with its parent, so a definition of `xmm0` does NOT reach a use
/// of `xmm0_d0`. Without this, a `call` immediately followed by `movd eax, xmm0`
/// (as in `dot_product_f32`, which calls a float-returning function and reads
/// its result that way) never matched the `"xmm0"` candidate: the read was
/// invisible, the caller fell through to the integer `rax` fallback, and the
/// call's real float result went unread while a DIFFERENT, never-defined value
/// reached the `return`.
///
/// The lane relation is asked of the shared register-view descriptor rather
/// than reconstructed from the spelling here. Sub-64-bit GP views are
/// deliberately NOT matched: `eax` and `al` reach a definition of `rax` through
/// the SSA parent rule and the parent's own read-modify-write lowering, so
/// re-deciding that here would move a call's result onto a partial register name
/// for no gain.
fn touches_result_candidate(arch: Option<regview::Arch>, base: &str, candidate: &str) -> bool {
    base == candidate || arch.is_some_and(|arch| regview::is_lane_of(arch, base, candidate))
}

/// Whether `base` names storage that a definition of whole-register `candidate`
/// would land on under `cc` — the same register, or one of its dword lanes.
/// SSA versions are tolerated on both sides.
///
/// The ARGUMENT-side counterpart of [`touches_result_candidate`], and it exists
/// for the same reason. A declaration says which ABI register holds a `float`
/// parameter; only the body says which of that register's SSA identities
/// carries it, because a function whose only parameter instruction is
/// `movd eax, xmm0` reads the lane `xmm0_d0` and never the name `xmm0`. Binding
/// the parameter to the canonical name there would leave every use of it
/// reading a value nothing defines.
pub fn touches_storage(cc: CallConv, base: &str, candidate: &str) -> bool {
    touches_result_candidate(result_view_arch(cc), ssa_base(base), ssa_base(candidate))
}

/// Which of `candidates` a call's result actually lands in, decided by what the
/// code AFTER the call reads first.
///
/// A convention with separate integer and floating-point result registers does
/// not say which one a given callee used — that is a property of the callee's
/// return type, which an instruction stream does not carry. What the caller
/// does say is which register it goes on to consume, and consuming a
/// caller-saved register that the call did not write would be reading garbage.
/// So first-read wins, a definition removes that candidate, and the integer
/// register is the fallback when nothing decides.
///
/// `candidates` is ordered float-first: on both x86-64 and AAPCS-VFP the
/// integer register is the one that is also used for other purposes, so it must
/// not win a tie.
///
/// The returned register is the EXACT name consumed, not the abstract
/// candidate: SSA versioning tracks `xmm0` and its dword lane `xmm0_d0` as
/// unrelated identities (see [`touches_result_candidate`]), so a call's
/// synthetic definition has to land on the precise spelling the next
/// instruction reads, or that read still resolves to an undefined live-in.
fn result_register_consumed_after(
    arch: Option<regview::Arch>,
    block: &crate::ir::types::LlirBlock,
    call_idx: usize,
    candidates: &[&'static str],
    fallback: &'static str,
) -> VReg {
    let mut candidates: Vec<&str> = candidates.to_vec();
    for instruction in &block.instrs[call_idx + 1..] {
        let (definition, uses) = def_uses(&instruction.op);
        for used in uses {
            let VReg::Phys(name) = used else {
                continue;
            };
            let base = ssa_base(&name);
            if candidates
                .iter()
                .any(|candidate| touches_result_candidate(arch, base, candidate))
            {
                return VReg::phys(base.to_string());
            }
        }
        if let Some(VReg::Phys(name)) = definition {
            let base = ssa_base(&name);
            candidates.retain(|candidate| !touches_result_candidate(arch, base, candidate));
            if candidates.is_empty() {
                break;
            }
        }
        if matches!(instruction.op, Op::Call { .. }) || instruction.op.is_return() {
            break;
        }
    }
    VReg::phys(fallback)
}

/// The `(candidates, fallback)` this convention's call results are chosen from,
/// or `None` when a single register carries every result.
fn result_register_candidates(cc: CallConv) -> Option<(&'static [&'static str], &'static str)> {
    match cc {
        // The SSE class returns in `xmm0`, the INTEGER and POINTER classes in
        // `rax`, and nothing in the instruction stream says which class this
        // callee's return type belongs to. Before this, every call was
        // annotated as returning `rax`, so a float-returning call defined a
        // register the caller never read and the value it DID read had no
        // definition at all — `dot_product_f32` assigned the call to one
        // variable and returned a different, undefined one.
        CallConv::SysVAmd64 | CallConv::Win64 => Some((&["xmm0", "rax"], "rax")),
        CallConv::ArmHardFloat => Some((&["s0", "d0", "r0"], "r0")),
        // i386 has the same split, with the x87 stack in place of `xmm0`: a
        // `double`-returning callee leaves its result in `%st(0)` and the
        // caller pops it with `fstpl`. Annotating every i386 call as returning
        // `rax` meant that `fstpl` read a stack slot nothing had defined —
        // `181_compensated_summation::summation_disagrees` compared two
        // undefined values. The stack is empty at the call by ABI (an
        // invariant `x87::plan_function` refuses to lift without), so the returned
        // value is always the bottom slot `st0`.
        CallConv::Cdecl32 => Some((&["st0", "rax"], "rax")),
        CallConv::Aarch64 | CallConv::Arm => None,
    }
}

/// Write the ABI's call effects onto every call in `lf`.
///
/// Idempotent, and it never overwrites effects a caller already set (a summarised or
/// known callee may describe itself more precisely than the convention's worst case).
pub fn annotate_calls(lf: &mut LlirFunction, cc: CallConv) {
    for block in &mut lf.blocks {
        for index in 0..block.instrs.len() {
            let mut effects = call_effects(cc);
            if let Some((candidates, fallback)) = result_register_candidates(cc) {
                effects.result = Some(result_register_consumed_after(
                    result_view_arch(cc),
                    block,
                    index,
                    candidates,
                    fallback,
                ));
            }
            let instr = &mut block.instrs[index];
            if let Op::Call { effects: slot, .. } = &mut instr.op {
                let tail_marker = slot.as_ref().is_some_and(|current| {
                    current.is_tail_call
                        && current.result.is_none()
                        && current.args.is_empty()
                        && !current.args_are_exact
                });
                if slot.is_some() && !tail_marker {
                    continue;
                }
                effects.is_tail_call = tail_marker;
                *slot = Some(effects.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CallTarget, LlirBlock, LlirInstr};

    fn call_at(va: u64) -> LlirInstr {
        LlirInstr {
            va,
            op: Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: None,
            },
        }
    }

    fn func(instrs: Vec<LlirInstr>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + 4 * instrs.len() as u64,
                instrs,
                succs: vec![],
            }],
        }
    }

    #[test]
    fn every_call_gets_the_conventions_effects() {
        let mut lf = func(vec![call_at(0x1000), call_at(0x1004)]);
        annotate_calls(&mut lf, CallConv::SysVAmd64);
        for instr in &lf.blocks[0].instrs {
            match &instr.op {
                Op::Call { effects, .. } => {
                    let e = effects.as_ref().expect("annotated");
                    assert_eq!(e.result, Some(VReg::phys("rax")));
                    assert_eq!(e.args.len(), 6);
                    assert_eq!(e.args[0], VReg::phys("rdi"));
                }
                other => panic!("expected a call, got {other:?}"),
            }
        }
    }

    #[test]
    fn hard_float_call_uses_both_banks_and_selects_consumed_vfp_result() {
        let mut lf = func(vec![
            call_at(0x1000),
            LlirInstr {
                va: 0x1004,
                op: Op::Intrinsic {
                    name: "vmov.f32".into(),
                    ins: vec![crate::ir::types::Value::Reg(VReg::phys("s0"))],
                    outs: vec![(VReg::phys("s14"), crate::ir::types::Width::W32)],
                    reads_mem: false,
                    writes_mem: false,
                },
            },
        ]);
        annotate_calls(&mut lf, CallConv::ArmHardFloat);

        let Op::Call {
            effects: Some(effects),
            ..
        } = &lf.blocks[0].instrs[0].op
        else {
            panic!("hard-float call was not annotated: {lf:#?}");
        };
        assert_eq!(effects.result, Some(VReg::phys("s0")));
        assert!(effects.args.contains(&VReg::phys("r0")));
        assert!(effects.args.contains(&VReg::phys("s0")));
        assert!(effects.args.contains(&VReg::phys("s15")));
    }

    /// `dot_product_f32` (`175_float_matrix_kernel`, `gcc -O0`): calls a
    /// float-returning function, then reads the result with `movd eax, xmm0`
    /// — a scalar 32-bit XMM transfer that touches only the `xmm0_d0` dword
    /// lane, not the whole `xmm0` register `def_uses` reports as the call's
    /// synthetic result. Before `touches_result_candidate` recognised the
    /// lane spelling, this call was annotated as returning in `rax` (the
    /// fallback), the real result in `xmm0_d0` was left completely
    /// undefined, and a different, never-assigned value reached `return`.
    #[test]
    fn sysv_call_result_recognises_scalar_xmm_dword_lane_consumption() {
        let mut lf = func(vec![
            call_at(0x11e4),
            LlirInstr {
                va: 0x11e9,
                op: Op::ZExt {
                    dst: VReg::phys("eax"),
                    src: crate::ir::types::Value::Reg(VReg::phys("xmm0_d0")),
                    from: crate::ir::types::Width::W32,
                    to: crate::ir::types::Width::W64,
                },
            },
        ]);
        annotate_calls(&mut lf, CallConv::SysVAmd64);

        let Op::Call {
            effects: Some(effects),
            ..
        } = &lf.blocks[0].instrs[0].op
        else {
            panic!("call was not annotated: {lf:#?}");
        };
        assert_eq!(
            effects.result,
            Some(VReg::phys("xmm0_d0")),
            "a post-call `movd eax, xmm0` must be recognised as consuming the \
             float result, not fall through to the integer `rax` fallback — and \
             the definition must land on the EXACT lane the read consumes \
             (`xmm0_d0`), since SSA versioning does not alias it to `xmm0`"
        );
    }

    #[test]
    fn the_result_register_and_arguments_follow_the_abi() {
        for (cc, ret, first_arg, argc) in [
            (CallConv::SysVAmd64, "rax", "rdi", 6),
            (CallConv::Win64, "rax", "rcx", 4),
            (CallConv::Aarch64, "x0", "x0", 8),
            (CallConv::Arm, "r0", "r0", 4),
        ] {
            let e = call_effects(cc);
            assert_eq!(e.result, Some(VReg::phys(ret)), "{cc:?} result");
            assert_eq!(e.args[0], VReg::phys(first_arg), "{cc:?} first arg");
            assert_eq!(e.args.len(), argc, "{cc:?} arg count");
        }
    }

    #[test]
    fn cdecl32_uses_the_canonical_accumulator_and_no_register_arguments() {
        let effects = call_effects(CallConv::Cdecl32);
        assert_eq!(effects.result, Some(VReg::phys("rax")));
        assert!(effects.args.is_empty());
        assert!(is_return_register(CallConv::Cdecl32, "eax#9"));
    }

    #[test]
    fn annotation_is_idempotent_and_does_not_overwrite() {
        let mut lf = func(vec![call_at(0x1000)]);
        annotate_calls(&mut lf, CallConv::SysVAmd64);
        // A caller that knows the callee may describe it more precisely; a second
        // pass must not flatten that back to the convention's worst case.
        if let Op::Call { effects, .. } = &mut lf.blocks[0].instrs[0].op {
            *effects = Some(CallEffects {
                result: Some(VReg::phys("rax")),
                result_is_source_value: true,
                args: vec![VReg::phys("rdi")],
                proven_args: Vec::new(),
                args_are_exact: true,
                is_tail_call: false,
            });
        }
        annotate_calls(&mut lf, CallConv::SysVAmd64);
        match &lf.blocks[0].instrs[0].op {
            Op::Call { effects, .. } => {
                assert_eq!(effects.as_ref().unwrap().args.len(), 1, "was overwritten");
            }
            other => panic!("expected a call, got {other:?}"),
        }
    }

    /// Every alias in a slot must map back to that slot, at every width. A missing
    /// alias means a `%edi = …` write is not recognised as setting parameter 0.
    #[test]
    fn every_alias_maps_to_its_own_slot() {
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
        ] {
            for (i, names) in argument_slots(cc).iter().enumerate() {
                for n in *names {
                    assert_eq!(argument_slot_of(cc, n), Some(i), "{cc:?} {n}");
                }
            }
        }
    }

    /// The canonical list and the alias table must agree on order and length, or a
    /// consumer of one disagrees with a consumer of the other about which parameter
    /// a register is.
    #[test]
    fn the_canonical_list_is_the_first_alias_of_each_slot() {
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
        ] {
            let canon = argument_registers(cc);
            let slots = argument_slots(cc);
            assert_eq!(canon.len(), slots.len(), "{cc:?}");
            for (i, names) in slots.iter().enumerate() {
                assert_eq!(names.first(), Some(&canon[i]), "{cc:?} slot {i}");
            }
        }
    }

    /// SSA versions must not defeat the lookup. This is the bug that lost every
    /// call argument on the value-numbered pipeline.
    #[test]
    fn an_ssa_version_does_not_hide_a_slot() {
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "rdi#3"), Some(0));
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "edi#17"), Some(0));
        assert_eq!(argument_slot_of(CallConv::Aarch64, "w7#2"), Some(7));
        assert!(is_return_register(CallConv::SysVAmd64, "eax#9"));
        assert!(!is_return_register(CallConv::SysVAmd64, "rbx#1"));
        assert_eq!(ssa_base("rdi#3"), "rdi");
        assert_eq!(ssa_base("rdi"), "rdi");
    }

    /// Win64 does not pass its first argument in `rdi`; a table that said otherwise
    /// would silently mis-order every Windows call.
    #[test]
    fn the_conventions_do_not_share_a_first_argument() {
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "rdi"), Some(0));
        assert_eq!(argument_slot_of(CallConv::Win64, "rdi"), None);
        assert_eq!(argument_slot_of(CallConv::Win64, "rcx"), Some(0));
        assert_eq!(argument_slot_of(CallConv::SysVAmd64, "rcx"), Some(3));
    }

    #[test]
    fn sysv_recovered_fixed_parameters_stop_at_the_first_register_hole() {
        let recovered = vec![
            VReg::phys("rdi"),
            VReg::phys("rsi"),
            VReg::phys("r8"),
            VReg::phys("r9"),
        ];

        assert_eq!(
            fixed_parameter_prefix_len(CallConv::SysVAmd64, &recovered),
            2
        );
        assert_eq!(
            fixed_parameter_prefix_len(CallConv::Win64, &recovered),
            recovered.len()
        );
    }

    /// The alias list means "other spellings of ONE value". `rdx` is a second
    /// value, so putting it there would make every `rdx` in every System V
    /// function look like the function's result — which is why the register pair
    /// is a separate fact and this assertion guards the distinction.
    #[test]
    fn the_second_result_register_is_never_an_alias_of_the_first() {
        assert!(!return_registers(CallConv::SysVAmd64).contains(&"rdx"));
        assert!(!is_return_register(CallConv::SysVAmd64, "rdx"));
        assert!(!is_return_register(CallConv::SysVAmd64, "edx"));
        assert_eq!(
            wide_integer_return_pair(CallConv::SysVAmd64, 16),
            Some(("rax", "rdx"))
        );
        // Eight bytes is ONE register on an LP64 target, not a pair.
        assert_eq!(wide_integer_return_pair(CallConv::SysVAmd64, 8), None);
    }

    /// Sub-register spellings and SSA versions must land on the same half.
    #[test]
    fn each_half_of_a_two_register_result_absorbs_its_own_spellings() {
        for (name, part) in [
            ("rax", Some(0)),
            ("eax", Some(0)),
            ("al", Some(0)),
            ("rdx#7", Some(1)),
            ("edx", Some(1)),
            ("rsi", None),
            ("xmm0", None),
        ] {
            assert_eq!(
                wide_integer_return_part(CallConv::SysVAmd64, name),
                part,
                "{name}"
            );
        }
        // ILP32 keeps the contract it already had, one machine word down.
        assert_eq!(
            wide_integer_return_pair(CallConv::Cdecl32, 8),
            Some(("rax", "rdx"))
        );
        assert_eq!(wide_integer_return_pair(CallConv::Cdecl32, 16), None);
        assert_eq!(
            wide_integer_return_pair(CallConv::Arm, 8),
            Some(("r0", "r1"))
        );
        // Neither convention has a modelled register-pair result.
        for cc in [CallConv::Win64, CallConv::Aarch64] {
            assert_eq!(
                wide_integer_return_pair(cc, wide_integer_return_width(cc)),
                None,
                "{cc:?}"
            );
            assert_eq!(wide_integer_return_part(cc, "rdx"), None, "{cc:?}");
        }
    }

    /// Each row is a different ABI contract, and treating them uniformly still
    /// produces C that compiles.
    #[test]
    fn the_sysv_return_class_table_separates_every_contract() {
        use Eightbyte::{Integer, Sse};

        assert_eq!(
            sysv_amd64_return_class(8, &[Integer]),
            Some(ReturnClass::Single)
        );
        assert_eq!(
            sysv_amd64_return_class(16, &[Integer, Integer]),
            Some(ReturnClass::IntegerPair)
        );
        assert_eq!(
            sysv_amd64_return_class(16, &[Integer, Sse]),
            Some(ReturnClass::SplitBanks {
                integer_first: true
            })
        );
        assert_eq!(
            sysv_amd64_return_class(16, &[Sse, Integer]),
            Some(ReturnClass::SplitBanks {
                integer_first: false
            })
        );
        // Past the cutoff the field classes stop mattering entirely.
        assert_eq!(
            sysv_amd64_return_class(32, &[]),
            Some(ReturnClass::Memory)
        );
        assert_eq!(sysv_amd64_return_class(17, &[]), Some(ReturnClass::Memory));
        // `xmm0:xmm1` has no second float result register in this model.
        assert_eq!(sysv_amd64_return_class(16, &[Sse, Sse]), None);
        // A class list that does not describe the stated size is not evidence.
        assert_eq!(sysv_amd64_return_class(16, &[Integer]), None);
        assert_eq!(sysv_amd64_return_class(8, &[]), None);
        assert_eq!(sysv_amd64_return_class(0, &[]), None);
    }

    /// The return register is the widest spelling, and the alias list leads with it.
    #[test]
    fn the_return_register_leads_its_alias_list() {
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
        ] {
            assert_eq!(
                return_registers(cc).first(),
                Some(&return_register(cc)),
                "{cc:?}"
            );
        }
    }

    /// AAPCS64 returns a scalar float or double in `v0`, whose scalar views are
    /// spelled `s0` and `d0`. Omitting them made every float-returning AArch64
    /// function render its result into a dead variable and return `x0` — which
    /// on an identity-shaped body is the first ARGUMENT.
    /// `181_compensated_summation:compensation_of_step` (`gcc -O2`) recovered
    /// as `return arg0;` for exactly this reason.
    #[test]
    fn aarch64_float_results_are_return_storage() {
        for name in ["d0", "s0", "v0"] {
            assert!(
                is_return_register(CallConv::Aarch64, name),
                "{name} is AAPCS64 result storage"
            );
        }
        // The integer name still leads, so a function writing both keeps `x0`
        // as its result and the vector register as scratch.
        assert_eq!(return_registers(CallConv::Aarch64).first(), Some(&"x0"));
        // `v1`/`d1` are ARGUMENT storage, never a result.
        for name in ["d1", "s1", "v1"] {
            assert!(!is_return_register(CallConv::Aarch64, name), "{name}");
        }
    }
}
