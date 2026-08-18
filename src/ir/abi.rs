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

pub mod result_projection;
mod return_spelling;
// Re-exported at their original `crate::ir::abi::` paths: the split is a
// file boundary, not an API change, so no caller moves.
pub use return_spelling::{
    hfa_return_definition, hfa_return_members, hfa_return_tag, indirect_return_bytes,
    indirect_return_definition, indirect_return_tag, split_bank_return_definition,
    split_bank_return_order, split_bank_return_tag, sse_pair_return_definition,
    sse_pair_return_high_bytes, sse_pair_return_tag, synthesised_return_definition,
};

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
        // AAPCS64 (IHI 0055, "Result return"): a Composite Type that is not an
        // HFA/HVA and is no larger than 16 bytes comes back in the same
        // registers a by-value ARGUMENT of that type would occupy, which for a
        // result is `x0` then `x1` — the object copied as if stored to memory,
        // so a size that is not a multiple of eight leaves the tail of `x1`
        // unspecified rather than moving the object elsewhere.
        //
        // `x1` is BOTH the second result register and the second argument
        // register, which is why omitting this arm did not merely drop a half:
        // a caller that read the high half read its own second argument back
        // instead (`198_aggregate_return_edges:aarch64:*:agr198_trio_roundtrip`
        // stored `seed` into the third member of a `{int32_t a,b,c;}`).
        //
        // Win64 returns any aggregate larger than one register through a hidden
        // pointer, so it has no register-pair result at all. There is no
        // Windows lane in `tests/decompiler_fixtures/` to measure a change
        // against; keep it fail-closed.
        CallConv::Aarch64 => Some(("x0", "x1")),
        CallConv::Win64 => None,
    }
}

/// Which half of a two-register integer result a register name denotes.
///
/// Sub-register spellings are folded onto their half: a 32-bit write to the
/// high register still writes the same half of the same logical value.
///
/// Only the x86 narrow views are listed, and the asymmetry with AArch64 is the
/// register model rather than an omission: `al` and `ax` PRESERVE their
/// parent's upper bits, so `regview::ssa_parent` declines them and this is the
/// only place that can relate them to `rax`. `w1` ZERO-EXTENDS, so SSA
/// canonicalises it to `x1` before any caller here sees it. Listing `w0`/`w1`
/// anyway was tried on 2026-08-18 and moved zero cells:
/// `198_aggregate_return_edges:aarch64:*:agr198_trio_roundtrip` reads its
/// third member through exactly that spelling and passes without them.
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
    /// Two SSE eightbytes in the SSE result PAIR (`xmm0:xmm1`) — one value in
    /// two floating-point registers, which is a different contract from a
    /// scalar `double` (`xmm0` alone) and from [`Self::SplitBanks`].
    ///
    /// `high_bytes` is how much of the SECOND eightbyte the object actually
    /// occupies, and it is a fact about the OBJECT rather than about the
    /// registers: `{float,float,float}` is twelve bytes, so `xmm1` carries four
    /// DEFINED bytes and four the callee never stored. A model that assumes
    /// both eightbytes are full reads a fourth member that does not exist,
    /// which is exactly what `197_homogeneous_float_aggregates`'s twelve-byte
    /// lane exists to catch. Only 4 and 8 are constructible: with every member
    /// a `float` or a `double`, a two-eightbyte all-SSE object is twelve or
    /// sixteen bytes and nothing else.
    SsePair { high_bytes: u8 },
    /// MEMORY: the caller allocates the object and passes its address in a
    /// hidden first INTEGER argument register; the callee returns that address
    /// in the result register and every declared argument shifts one slot right.
    Memory,
    /// AAPCS64's HOMOGENEOUS FLOATING-POINT AGGREGATE: 2-4 members, all of the
    /// SAME floating-point type, one member per consecutive SIMD register
    /// (`v0`..`v3`, spelled `s0`..`s3` or `d0`..`d3` at the member's width).
    ///
    /// Not [`Self::SsePair`] in another bank, and `197_homogeneous_float_aggregates`
    /// is what proves it. System V packs `{float,float,float}` into TWO
    /// registers at two floats apiece, so its high register is a partly
    /// occupied EIGHTBYTE and the class needs an occupancy. AAPCS64 gives each
    /// MEMBER a register of its own, so the same struct occupies `s0`,`s1`,`s2`
    /// with `s3` untouched: three registers, four bytes each, no partial
    /// occupancy anywhere. A model that reuses the pair reads member two out of
    /// the top half of member one's register.
    ///
    /// `members` is 2..=4 by construction. One member is a scalar `float` or
    /// `double` result, which already has a working single-register contract;
    /// five cannot be an HFA at all.
    HomogeneousFloat { member_bytes: u8, members: u8 },
    /// AAPCS64's INDIRECT result: the caller allocates `bytes` of storage and
    /// passes its address in the dedicated `x8`, which is NOT an argument
    /// register.
    ///
    /// Deliberately not [`Self::Memory`]. That variant carries System V's
    /// contract — hidden pointer in the FIRST ARGUMENT register, every declared
    /// argument shifted one slot right, and the buffer's address handed back in
    /// the result register. AAPCS64 shifts nothing, returns nothing, and uses a
    /// register the argument model never touches, so reusing `Memory` would
    /// relabel every argument of the call.
    ///
    /// The size is carried because AAPCS64 copies the result "as if" it were
    /// stored to memory and reloaded: a 20-byte object writes 20 bytes and
    /// leaves the tail of the last eightbyte unspecified, which is exactly the
    /// case `198_aggregate_return_edges`'s `agr198_five` exists to pin.
    IndirectBuffer { bytes: u16 },
}

/// The dedicated register a caller passes an indirect result's address in.
///
/// `None` for every convention whose over-wide result travels in an ordinary
/// ARGUMENT register instead — System V AMD64's hidden pointer is argument
/// zero, and modelling it here would claim the two contracts are one.
pub fn indirect_result_register(cc: CallConv) -> Option<&'static str> {
    match cc {
        // AAPCS64 (IHI 0055, "Result return"): "the caller shall reserve a
        // block of memory ... and shall pass its address in x8".  `x8` is the
        // Indirect Result Location Register (`XR`), outside `x0`-`x7`.
        CallConv::Aarch64 => Some("x8"),
        CallConv::SysVAmd64
        | CallConv::Win64
        | CallConv::Cdecl32
        | CallConv::Arm
        | CallConv::ArmHardFloat => None,
    }
}

/// The consecutive SIMD result registers an AAPCS64 HFA occupies, at the
/// member's own width.
///
/// A member is one whole register, so the spelling states the member's width:
/// four bytes is `s0`..`s3` and eight is `d0`..`d3`. These are NOT alias sets
/// and NOT a pair — they are four registers carrying four different members of
/// one value, which is why they can never join [`return_registers`].
pub fn hfa_return_registers(cc: CallConv, member_bytes: u8) -> &'static [&'static str] {
    match (cc, member_bytes) {
        (CallConv::Aarch64, 4) => &["s0", "s1", "s2", "s3"],
        (CallConv::Aarch64, 8) => &["d0", "d1", "d2", "d3"],
        _ => &[],
    }
}

/// Which HFA member register `name` is, for members past the FIRST.
///
/// Member zero is deliberately excluded. `s0`/`d0` is already a spelling of
/// "the result" under [`return_registers`], and claiming it here would take it
/// out of the AArch64 result-bank collapse that
/// `call_result_split::Splitter::result_storage` deliberately keeps (see the
/// `175_float_matrix_kernel` measurement recorded there). Members one to three
/// have no storage identity at all today, so giving them one is additive and
/// inert on every call that is not a proven HFA return.
///
/// The exact SPELLING is part of the answer, not just the index: `s1` and `d1`
/// are two views of `v1` that SSA tracks as unrelated identities, so a call
/// returning `{float x3}` must not have its member read back through `d1`.
pub fn hfa_return_member(cc: CallConv, name: &str) -> Option<&'static str> {
    let base = ssa_base(name);
    for member_bytes in [4u8, 8] {
        if let Some(register) = hfa_return_registers(cc, member_bytes)
            .iter()
            .skip(1)
            .find(|register| **register == base)
        {
            return Some(register);
        }
    }
    None
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
        // Two SSE eightbytes return in `xmm0:xmm1`. The occupancy of the SECOND
        // one is not implied by its class: the object's SIZE says how many of
        // its eight bytes the callee actually stored, and a twelve-byte
        // `{float,float,float}` leaves the top half of `xmm1` undefined. Only
        // the two occupancies a float/double member list can produce are
        // accepted; any other size is a shape this model has not seen and is
        // refused rather than rounded up to a full eightbyte.
        [Eightbyte::Sse, Eightbyte::Sse] => {
            let high_bytes = u8::try_from(size.checked_sub(8)?).ok()?;
            matches!(high_bytes, 4 | 8).then_some(ReturnClass::SsePair { high_bytes })
        }
        _ => None,
    }
}

/// The SECOND SSE result register, and every width spelling of it.
///
/// This is a register PAIR member, not an alias — the same distinction
/// [`wide_integer_return_pair`] draws for `rax:rdx`, and the reason `xmm1`
/// must never join [`return_registers`]: that list is spellings of ONE logical
/// result, and adding `xmm1` to it would let the naming pass call a scratch
/// `xmm1` the function's return value.
///
/// System V AMD64 only. Win64 returns every over-wide aggregate through a
/// hidden pointer, so it has no `xmm0:xmm1` result contract to model.
pub fn sse_pair_high_return_registers(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["xmm1", "ymm1", "zmm1"],
        CallConv::Win64
        | CallConv::Cdecl32
        | CallConv::Aarch64
        | CallConv::Arm
        | CallConv::ArmHardFloat => &[],
    }
}

/// Whether `name` denotes the high half of an `xmm0:xmm1` result, tolerating
/// SSA versions and the wider vector spellings of the same register.
pub fn is_sse_pair_high_return_register(cc: CallConv, name: &str) -> bool {
    sse_pair_high_return_registers(cc).contains(&ssa_base(name))
}

/// Each dword LANE of the `xmm0:xmm1` result pair, with the offset into the
/// returned object that its bits carry.
///
/// The lifters scalarise packed operations into 32-bit lanes
/// (`crate::ir::regview::packed_views`), and `regview::ssa_parent` declines the
/// vector bank outright, so a definition spelled `xmm0` does NOT reach a use
/// spelled `xmm0_d0`. A caller unpacking a returned `{float,float,float,float}`
/// reads its members through exactly these names — which is why modelling the
/// two whole registers is not enough on its own, and why each lane needs an
/// identity of its own rather than sharing its register's.
///
/// Only the lanes carrying object bytes are listed: the ABI puts one eightbyte
/// in each register, so bits 64..127 of `xmm0` and `xmm1` (lanes `_d2`, `_d3`)
/// are not part of the result at all and must not acquire one.
pub fn sse_pair_result_lanes(cc: CallConv) -> &'static [(&'static str, u8)] {
    match cc {
        CallConv::SysVAmd64 => &[
            ("xmm0_d0", 0),
            ("xmm0_d1", 4),
            ("xmm1_d0", 8),
            ("xmm1_d1", 12),
        ],
        CallConv::Win64
        | CallConv::Cdecl32
        | CallConv::Aarch64
        | CallConv::Arm
        | CallConv::ArmHardFloat => &[],
    }
}

/// The object offset a lane spelling carries, or `None` when the name is not a
/// lane of the SSE result pair. Tolerates SSA versions.
pub fn sse_pair_result_lane_offset(cc: CallConv, name: &str) -> Option<u8> {
    let base = ssa_base(name);
    sse_pair_result_lanes(cc)
        .iter()
        .find(|(lane, _)| *lane == base)
        .map(|(_, offset)| *offset)
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
///
/// This is the PER-CONVENTION answer. The convention-agnostic one — what the
/// AST passes that have no `CallConv` in scope match against, and which of
/// these names they project onto a bare machine `ret` — lives in
/// [`result_projection`], along with the census that keeps the two from
/// drifting apart the way they did until 2026-08-18.
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
///
/// Adding a spelling here without a matching decision in
/// [`result_projection`] is a compile-green, test-red change by design: the
/// census there fails until the new name is either projected onto a bare `ret`
/// or listed as deliberately unprojected with a reason.
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

/// The SSE argument-bank index a register name denotes, or `None` when the name
/// is not one of that bank's registers.
///
/// The counterpart of [`argument_slot_of`] for the OTHER System V bank. It
/// tolerates SSA versions and the dword LANE spellings the lifters scalarise
/// packed operations into (`crate::ir::regview::packed_views`): `xmm0_d0` is a
/// quarter of `xmm0`, so it denotes the same bank slot exactly as `edi` denotes
/// `rdi`'s. `regview::ssa_parent` declines to merge a lane with its parent, so
/// nothing else in the pipeline would relate the two names.
///
/// The lane arm is CONSISTENCY, not a measured gain, and saying so is the point:
/// deleting it moved zero cells across all 740 host lanes on 2026-08-17. It is
/// kept because [`crate::ir::types_recover`]'s `float_argument_bank_slot` — the
/// function that decides which live-ins become float parameters at all — accepts
/// the same lane spellings for a measured reason, and a gate that then discarded
/// what recovery had just admitted would be this function's own bug one spelling
/// further in. The reason no cell needs it today is that `float_live_in_slots`
/// already replaces a lane spelling with the whole register whenever the callee
/// reads the whole register anywhere, which every corpus callee does.
pub fn sse_argument_slot_of(cc: CallConv, name: &str) -> Option<usize> {
    let index = ssa_base(name)
        .strip_prefix("xmm")
        .map(|index| index.split_once("_d").map_or(index, |(whole, _)| whole))?
        .parse::<usize>()
        .ok()?;
    (index < sse_argument_registers(cc).len()).then_some(index)
}

/// Length of the source-level fixed-parameter prefix proven by recovered storage.
///
/// SysV AMD64 allocates fixed parameters consecutively out of TWO independent
/// banks — `rdi, rsi, rdx, rcx, r8, r9` for INTEGER and `xmm0`-`xmm7` for SSE.
/// Definition-site liveness can miss an unused parameter, but a later live
/// register does not prove the missing parameter or any register after it. Stop
/// at the first hole instead of turning unrelated caller-saved residue into a
/// fixed source signature. Other conventions keep their existing layouts: AAPCS
/// hard-float has independent allocation banks, and their recovery needs richer
/// class-aware ordering than a single prefix.
///
/// The hole is looked for in each bank SEPARATELY, because the two counters are
/// independent: `xmm0` is the first SSE parameter whether it is the signature's
/// first parameter or its fourth. Asking only the integer bank — which is what
/// this did until 2026-08-17 — silently discards every floating-point parameter
/// of a System V callee, so a caller was told the callee takes none. That is how
/// `197_homogeneous_float_aggregates`'s `hfa197_consume_pair2d(struct{double,
/// double})` reached its caller as `extern long hfa197_consume_pair2d(void)`
/// and was then CALLED with no arguments: its parameter occupies `xmm0:xmm1`
/// and neither register is in the integer table.
///
/// On a layout drawn purely from the integer bank this is the rule it replaced,
/// value for value: a parameter is retained exactly while its slot is inside
/// its own bank's contiguous prefix, and the first one that is not ends the
/// signature.
pub(crate) fn fixed_parameter_prefix_len(cc: CallConv, recovered: &[VReg]) -> usize {
    if cc != CallConv::SysVAmd64 {
        return recovered.len();
    }

    let bank_prefix = |slot_of: &dyn Fn(&str) -> Option<usize>, bank_size: usize| -> usize {
        let recovered_slots = recovered
            .iter()
            .filter_map(|register| match register {
                VReg::Phys(name) => slot_of(name),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        (0..bank_size)
            .take_while(|slot| recovered_slots.contains(slot))
            .count()
    };
    let integer_prefix = bank_prefix(&|name| argument_slot_of(cc, name), argument_slots(cc).len());
    let sse_prefix = bank_prefix(
        &|name| sse_argument_slot_of(cc, name),
        sse_argument_registers(cc).len(),
    );
    recovered
        .iter()
        .take_while(|register| {
            let VReg::Phys(name) = register else {
                return false;
            };
            argument_slot_of(cc, name).is_some_and(|slot| slot < integer_prefix)
                || sse_argument_slot_of(cc, name).is_some_and(|slot| slot < sse_prefix)
        })
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
        // AAPCS64 has the same two-bank split, and its absence here cost the
        // same thing one architecture over. Every AArch64 call was annotated as
        // returning `x0`, so a `double`-returning callee defined a register the
        // caller never read — and because AArch64's `v8`-`v15` are callee-SAVED,
        // `ast::float_gate::scalar_float_semantics_proof` then treats such a
        // call as an unmodelled float producer and shuts the WHOLE FUNCTION's
        // scalar-float lowering. That is why
        // `197_homogeneous_float_aggregates:aarch64:*:hfa197_scalar_control`
        // failed: a plain `double` return, no aggregate anywhere, every
        // `fcvtzs` rendered `/* asm: vcvt... */` with its destination
        // undefined, purely because the call before it was labelled `x0`.
        //
        // `v0` leads because the scalar views are what a caller actually reads
        // (`fmov d30, d0`), and the whole-register spelling is what a vector
        // consumer reads; the integer register is last for the same reason it
        // is last on System V — `x0` is the one that is also used for other
        // purposes, so it must not win a tie, and it remains the fallback when
        // nothing after the call decides.
        CallConv::Aarch64 => Some((&["v0", "d0", "s0", "x0"], "x0")),
        // Soft-float AAPCS returns every floating-point value in the CORE
        // registers, so there is no second bank to choose between.
        CallConv::Arm => None,
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

    /// AAPCS64's call result is chosen from the SAME first-read-wins evidence
    /// System V's is, and its absence is what made every AArch64 call look like
    /// an integer one.
    ///
    /// The instruction stream does not say which bank a callee returned in —
    /// that is a property of its return TYPE. What the caller says is which
    /// register it goes on to consume, and consuming a caller-saved register the
    /// call did not write would be reading garbage. So the float names lead and
    /// `x0` is both the last candidate and the fallback: when a function writes
    /// both, `x0` is the result and the vector register was scratch.
    ///
    /// Measured on `197_homogeneous_float_aggregates:aarch64:O0` (2026-08-18):
    /// `bl hfa197_make_scalar` followed by `fmov d31, d0`. Annotated `x0`, the
    /// `d0` read had no definition and `float_gate` shut the whole function's
    /// scalar-float lowering.
    #[test]
    fn aarch64_call_result_follows_the_bank_the_caller_reads() {
        let float_result = |consume: Op, expected: &str| {
            let mut lf = func(vec![
                call_at(0x1000),
                LlirInstr {
                    va: 0x1004,
                    op: consume,
                },
            ]);
            annotate_calls(&mut lf, CallConv::Aarch64);
            let Op::Call {
                effects: Some(effects),
                ..
            } = &lf.blocks[0].instrs[0].op
            else {
                panic!("AArch64 call was not annotated: {lf:#?}");
            };
            assert_eq!(effects.result, Some(VReg::phys(expected)));
        };

        // A `double`-returning callee: the caller reads `d0`.
        float_result(
            Op::Intrinsic {
                name: "vmov.f64".into(),
                ins: vec![crate::ir::types::Value::Reg(VReg::phys("d0"))],
                outs: vec![(VReg::phys("d31"), crate::ir::types::Width::W64)],
                reads_mem: false,
                writes_mem: false,
            },
            "d0",
        );
        // A `float`-returning callee reads the 32-bit view of the same
        // register, and the EXACT spelling is what the result must land on:
        // SSA tracks `s0` and `d0` as unrelated identities, so annotating the
        // other one leaves the read undefined.
        float_result(
            Op::Intrinsic {
                name: "vmov.f32".into(),
                ins: vec![crate::ir::types::Value::Reg(VReg::phys("s0"))],
                outs: vec![(VReg::phys("s29"), crate::ir::types::Width::W32)],
                reads_mem: false,
                writes_mem: false,
            },
            "s0",
        );
        // An integer-returning callee keeps `x0`, which is also the fallback
        // when nothing after the call decides.
        float_result(
            Op::Assign {
                dst: VReg::phys("x19"),
                src: crate::ir::types::Value::Reg(VReg::phys("x0")),
            },
            "x0",
        );

        // THE CANDIDATE LIST AND ITS ORDER. `v0` leads so a vector consumer is
        // matched, the scalar views follow, and `x0` is last so it never wins a
        // tie against a float read in the same instruction.
        assert_eq!(
            result_register_candidates(CallConv::Aarch64),
            Some((&["v0", "d0", "s0", "x0"][..], "x0"))
        );
        // Soft-float AAPCS returns floating-point values in the CORE registers,
        // so it has no second bank and must not acquire this choice.
        assert_eq!(result_register_candidates(CallConv::Arm), None);
        // Every listed candidate is a spelling this convention already agrees
        // is result storage; the choice is WHICH, never a new register.
        for candidate in ["v0", "d0", "s0", "x0"] {
            assert!(
                is_return_register(CallConv::Aarch64, candidate)
                    || float_return_registers(CallConv::Aarch64).contains(&candidate),
                "{candidate} is not AArch64 result storage"
            );
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

    /// The SSE bank has its own counter, so its hole is its own too.
    ///
    /// Until this was true, a System V callee whose parameters live in `xmm`
    /// registers reported a prefix of ZERO — no parameters at all — because the
    /// only table consulted was the integer one. That is what made
    /// `hfa197_consume_pair2d(struct {double; double;})` reach its caller as
    /// `extern long hfa197_consume_pair2d(void)`.
    #[test]
    fn the_sse_argument_bank_has_its_own_hole() {
        let prefix = |registers: &[&str]| {
            let recovered = registers
                .iter()
                .map(|name| VReg::phys(*name))
                .collect::<Vec<_>>();
            fixed_parameter_prefix_len(CallConv::SysVAmd64, &recovered)
        };
        // A 16-byte all-SSE aggregate by value: TWO SSE registers, ONE value,
        // and no integer register anywhere in the signature.
        assert_eq!(prefix(&["xmm0", "xmm1"]), 2);
        assert_eq!(prefix(&["xmm0"]), 1);
        // The two counters are independent, so a float parameter does not
        // interrupt the integer bank and vice versa.
        assert_eq!(prefix(&["rdi", "xmm0", "rsi"]), 3);
        assert_eq!(prefix(&["xmm0", "rdi", "xmm1"]), 3);
        // A hole in the SSE bank ends the signature exactly as an integer one
        // does: `xmm1` without `xmm0` proves no parameter.
        assert_eq!(prefix(&["xmm1"]), 0);
        assert_eq!(prefix(&["rdi", "xmm1"]), 1);
        // A dword LANE is a quarter of its register and therefore the same bank
        // slot; `regview::ssa_parent` relates them nowhere else.
        assert_eq!(prefix(&["xmm0_d0", "xmm1_d0"]), 2);
        assert_eq!(
            sse_argument_slot_of(CallConv::SysVAmd64, "xmm3_d1#4"),
            Some(3)
        );
        // Past the bank there is no slot at all: `xmm8` is never a parameter.
        assert_eq!(sse_argument_slot_of(CallConv::SysVAmd64, "xmm8"), None);
        assert_eq!(sse_argument_slot_of(CallConv::Win64, "xmm4"), None);
        assert_eq!(sse_argument_slot_of(CallConv::SysVAmd64, "rdi"), None);
        assert_eq!(sse_argument_slot_of(CallConv::Aarch64, "xmm0"), None);
        // And a purely integer layout keeps the rule this replaced, value for
        // value: the first hole ends the signature, order does not matter, and
        // a register from neither bank ends it too.
        assert_eq!(prefix(&["rdi", "rsi"]), 2);
        assert_eq!(prefix(&["rdi", "rdx"]), 1);
        assert_eq!(prefix(&["rsi"]), 0);
        assert_eq!(prefix(&["rdi", "rsi", "arg2"]), 2);
        assert_eq!(prefix(&["rdi", "rax"]), 1);
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
        // Win64 has no modelled register-pair result: every aggregate wider
        // than one register goes back through a hidden pointer.
        assert_eq!(
            wide_integer_return_pair(CallConv::Win64, wide_integer_return_width(CallConv::Win64)),
            None
        );
        assert_eq!(wide_integer_return_part(CallConv::Win64, "rdx"), None);
    }

    /// AAPCS64's pair, and the SPELLINGS a twelve-byte `{int32_t a,b,c;}`
    /// actually reaches its members through.
    ///
    /// `x1` is both the second result register and the second argument
    /// register, so the cost of not modelling the pair was not a dropped half:
    /// a caller read its own second argument back out of `x1` and stored it as
    /// the third member.
    #[test]
    fn aapcs64_returns_a_two_register_composite_in_x0_and_x1() {
        assert_eq!(
            wide_integer_return_pair(CallConv::Aarch64, 16),
            Some(("x0", "x1"))
        );
        // The guard is the width of the two-machine-word SPELLING the call
        // boundary uses for this class (`unsigned __int128`), not the size of
        // the source object: AAPCS64 puts a 9..=16 byte composite in the same
        // two registers whatever its tail padding. Eight bytes is one register
        // on an LP64 target and must stay one.
        assert_eq!(wide_integer_return_pair(CallConv::Aarch64, 8), None);
        assert_eq!(wide_integer_return_pair(CallConv::Aarch64, 12), None);
        for (name, part) in [
            ("x0", Some(0)),
            ("x0#3", Some(0)),
            ("x1", Some(1)),
            ("x1#12", Some(1)),
            ("x2", None),
            ("d0", None),
            ("rdx", None),
        ] {
            assert_eq!(
                wide_integer_return_part(CallConv::Aarch64, name),
                part,
                "{name}"
            );
        }
        // The narrow spellings are absent from that table on purpose, and this
        // is the fact that makes their absence safe rather than an oversight: a
        // `w` view ZERO-EXTENDS, so SSA canonicalises it to its `x` parent and
        // the third member of a twelve-byte trio arrives here already spelled
        // `x1`. The x86 low-byte views cannot do this — they preserve their
        // parent — which is why only they are enumerated above.
        assert_eq!(
            regview::ssa_parent(regview::Arch::AArch64, "w1"),
            Some("x1")
        );
        assert_eq!(
            regview::ssa_parent(regview::Arch::AArch64, "w0"),
            Some("x0")
        );
        assert_eq!(regview::ssa_parent(regview::Arch::X86_64, "al"), None);
        // `x1` is a PAIR MEMBER, never another spelling of the result: the
        // alias list must stay unable to claim it, exactly as it cannot claim
        // `rdx` under System V.
        assert!(!return_registers(CallConv::Aarch64).contains(&"x1"));
        assert!(!is_return_register(CallConv::Aarch64, "x1"));
        assert!(!is_return_register(CallConv::Aarch64, "w1"));
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
        assert_eq!(sysv_amd64_return_class(32, &[]), Some(ReturnClass::Memory));
        assert_eq!(sysv_amd64_return_class(17, &[]), Some(ReturnClass::Memory));
        // Two SSE eightbytes are `xmm0:xmm1`, and the SIZE — not the class
        // list — says how much of the second register the callee defined.
        assert_eq!(
            sysv_amd64_return_class(16, &[Sse, Sse]),
            Some(ReturnClass::SsePair { high_bytes: 8 })
        );
        assert_eq!(
            sysv_amd64_return_class(12, &[Sse, Sse]),
            Some(ReturnClass::SsePair { high_bytes: 4 })
        );
        // An occupancy no float/double member list can produce is refused
        // rather than rounded up to a full eightbyte.
        for size in [9, 10, 11, 13, 14, 15] {
            assert_eq!(
                sysv_amd64_return_class(size, &[Sse, Sse]),
                None,
                "{size} bytes acquired a full-eightbyte contract"
            );
        }
        // A class list that does not describe the stated size is not evidence.
        assert_eq!(sysv_amd64_return_class(16, &[Integer]), None);
        assert_eq!(sysv_amd64_return_class(8, &[]), None);
        assert_eq!(sysv_amd64_return_class(0, &[]), None);
    }

    /// The synthesised split-bank type must have the ABI contract it claims:
    /// its members' eightbyte classes, in order, must re-derive the same class.
    /// A definition that does not is a declaration returning the wrong bytes.
    #[test]
    fn the_split_bank_spelling_reclassifies_to_the_class_it_stands_for() {
        for (integer_first, eightbytes) in [
            (true, [Eightbyte::Integer, Eightbyte::Sse]),
            (false, [Eightbyte::Sse, Eightbyte::Integer]),
        ] {
            let tag = split_bank_return_tag(integer_first);
            let definition = split_bank_return_definition(integer_first);
            assert_eq!(split_bank_return_order(tag), Some(integer_first));
            assert!(definition.starts_with(&format!("{tag} {{")), "{definition}");
            // `unsigned long` is the INTEGER member and `double` the SSE one, so
            // their order in the definition IS the bank order.
            let integer_at = definition.find("unsigned long").expect("integer member");
            let sse_at = definition.find("double").expect("sse member");
            assert_eq!(integer_at < sse_at, integer_first, "{definition}");
            assert_eq!(
                sysv_amd64_return_class(16, &eightbytes),
                Some(ReturnClass::SplitBanks { integer_first })
            );
        }
        assert_eq!(split_bank_return_order("long"), None);
        assert_eq!(split_bank_return_order("unsigned __int128"), None);
    }

    /// The two SSE-pair spellings must differ in exactly one way: how many
    /// bytes of the HIGH register they move. Both are sixteen-byte objects that
    /// classify SSE,SSE, so both return in `xmm0:xmm1` — the register contract
    /// is shared and only the occupancy is not.
    /// The AAPCS64 HFA spellings: one member per register, and the count is
    /// what distinguishes them.
    ///
    /// The `trio3f` row is the one that proves this cannot be the SSE pair.
    /// `sse_pair_return_tag(4)` describes TWO sixteen-byte registers of which
    /// the second is half occupied; `hfa_return_tag(4, 3)` describes THREE
    /// four-byte members, each in a register of its own, with a fourth register
    /// untouched. Those are different objects and different storage.
    #[test]
    fn an_hfa_spelling_names_one_member_per_register() {
        for (member_bytes, members, member_type) in [
            (4u8, 2u8, "float"),
            (4, 3, "float"),
            (4, 4, "float"),
            (8, 2, "double"),
            (8, 3, "double"),
            (8, 4, "double"),
        ] {
            let tag = hfa_return_tag(member_bytes, members).expect("a modelled HFA shape");
            let definition =
                hfa_return_definition(member_bytes, members).expect("a modelled HFA shape");
            assert_eq!(hfa_return_members(tag), Some((member_bytes, members)));
            assert_eq!(
                synthesised_return_definition(tag).as_deref(),
                Some(definition)
            );
            assert!(definition.starts_with(&format!("{tag} {{")), "{definition}");
            // Exactly `members` members, all of the same type: that IS the
            // homogeneity the class asserts.
            assert_eq!(
                definition.matches(&format!("{member_type} __m")).count(),
                usize::from(members),
                "{definition}"
            );
        }
        // ONE member is a scalar result and FIVE has no register; neither is an
        // HFA, and neither gets a spelling.
        for members in [0u8, 1, 5, 8] {
            assert_eq!(hfa_return_tag(4, members), None, "{members}");
            assert_eq!(hfa_return_definition(8, members), None, "{members}");
        }
        // Only the two floating-point widths AArch64 has scalar views for.
        for member_bytes in [1u8, 2, 3, 5, 6, 7, 16] {
            assert_eq!(hfa_return_tag(member_bytes, 2), None, "{member_bytes}");
        }
        assert_eq!(hfa_return_members("double"), None);
        assert_eq!(hfa_return_members("struct __glaurung_split_is"), None);
        // A trio and a quad of the same member type are DIFFERENT spellings:
        // collapsing them would read a fourth member out of `s3`.
        assert_ne!(hfa_return_tag(4, 3), hfa_return_tag(4, 4));
        // ...as are the two widths at the same count.
        assert_ne!(hfa_return_tag(4, 2), hfa_return_tag(8, 2));
    }

    /// The HFA member registers, and the member-zero exclusion.
    #[test]
    fn hfa_member_registers_are_the_scalar_views_of_v0_to_v3() {
        assert_eq!(
            hfa_return_registers(CallConv::Aarch64, 4),
            &["s0", "s1", "s2", "s3"]
        );
        assert_eq!(
            hfa_return_registers(CallConv::Aarch64, 8),
            &["d0", "d1", "d2", "d3"]
        );
        // No other convention has this bank, and no other member width.
        assert!(hfa_return_registers(CallConv::Aarch64, 2).is_empty());
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert!(hfa_return_registers(cc, 4).is_empty(), "{cc:?}");
            assert!(hfa_return_registers(cc, 8).is_empty(), "{cc:?}");
        }

        // Members ONE onward have no storage identity anywhere else, which is
        // why they can acquire one here.
        for name in ["s1", "s2", "s3", "d1", "d2", "d3"] {
            assert_eq!(hfa_return_member(CallConv::Aarch64, name), Some(name));
            assert!(!is_return_register(CallConv::Aarch64, name), "{name}");
        }
        // SSA versions fold onto the same member.
        assert_eq!(hfa_return_member(CallConv::Aarch64, "s2#7"), Some("s2"));
        // MEMBER ZERO IS EXCLUDED. `s0`/`d0` is already a spelling of "the
        // result", and claiming it here would take it out of the AArch64
        // result-bank collapse in `call_result_split`.
        for name in ["s0", "d0", "v0", "x0"] {
            assert_eq!(hfa_return_member(CallConv::Aarch64, name), None, "{name}");
        }
        // Nothing outside the bank, and nothing on another convention.
        assert_eq!(hfa_return_member(CallConv::Aarch64, "x1"), None);
        assert_eq!(hfa_return_member(CallConv::ArmHardFloat, "s1"), None);
        assert_eq!(hfa_return_member(CallConv::SysVAmd64, "xmm1"), None);
    }

    /// The AAPCS64 indirect result spelling: a size, and the register it is NOT
    /// passed in.
    #[test]
    fn the_indirect_result_spelling_carries_the_buffer_size() {
        assert_eq!(indirect_result_register(CallConv::Aarch64), Some("x8"));
        // System V's hidden pointer is argument ZERO, not a dedicated register.
        // Claiming one here would say the two contracts are the same.
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert_eq!(indirect_result_register(cc), None, "{cc:?}");
        }
        // `x8` is not an argument register and not a result register, which is
        // the whole reason this class needs its own machinery.
        assert!(!argument_registers(CallConv::Aarch64).contains(&"x8"));
        assert!(!is_return_register(CallConv::Aarch64, "x8"));

        for bytes in [17u16, 20, 24, 32, 64, 4096] {
            let tag = indirect_return_tag(bytes).expect("a size past the register cutoff");
            let definition = indirect_return_definition(bytes).expect("the same");
            assert_eq!(indirect_return_bytes(&tag), Some(bytes));
            assert_eq!(
                synthesised_return_definition(&tag),
                Some(definition.clone())
            );
            assert!(definition.starts_with(&format!("{tag} {{")), "{definition}");
            // The size is the WHOLE contract: AAPCS64 copies the object as if
            // stored to memory, so no field recovery is required and none is
            // spelled. Twenty bytes is deliberately not a multiple of eight.
            assert!(
                definition.contains(&format!("__bytes[{bytes}]")),
                "{definition}"
            );
        }
        // At or below sixteen bytes the result is in REGISTERS and this
        // spelling would be actively wrong.
        for bytes in [0u16, 1, 8, 12, 16] {
            assert_eq!(indirect_return_tag(bytes), None, "{bytes}");
            assert_eq!(indirect_return_definition(bytes), None, "{bytes}");
            assert_eq!(
                indirect_return_bytes(&format!("struct __glaurung_indirect_{bytes}")),
                None,
                "{bytes}"
            );
        }
        assert_eq!(indirect_return_bytes("long"), None);
        assert_eq!(indirect_return_bytes("struct __glaurung_hfa_3f"), None);
        // Two sizes are two spellings: sharing one would copy the wrong number
        // of bytes back out of the buffer.
        assert_ne!(indirect_return_tag(20), indirect_return_tag(32));
    }

    #[test]
    fn the_sse_pair_spellings_differ_only_in_high_eightbyte_occupancy() {
        for (high_bytes, high_member) in [(8u8, "double __sse1"), (4, "float __sse1")] {
            let tag = sse_pair_return_tag(high_bytes).expect("a modelled occupancy");
            let definition = sse_pair_return_definition(high_bytes).expect("a modelled occupancy");
            assert_eq!(sse_pair_return_high_bytes(tag), Some(high_bytes));
            assert_eq!(
                synthesised_return_definition(tag).as_deref(),
                Some(definition)
            );
            assert!(definition.starts_with(&format!("{tag} {{")), "{definition}");
            // The low eightbyte is a full `double` in both: only the second
            // member carries the occupancy.
            assert!(definition.contains("double __sse0;"), "{definition}");
            assert!(definition.contains(high_member), "{definition}");
            // Both spellings are sixteen-byte SSE,SSE objects, hence
            // `xmm0:xmm1`. This is what makes the half spelling ABI-compatible
            // with the twelve-byte callee it stands for.
            assert_eq!(
                sysv_amd64_return_class(16, &[Eightbyte::Sse, Eightbyte::Sse]),
                Some(ReturnClass::SsePair { high_bytes: 8 })
            );
        }
        assert_ne!(sse_pair_return_tag(8), sse_pair_return_tag(4));
        for unmodelled in [0u8, 1, 2, 3, 5, 6, 7, 9, 16] {
            assert_eq!(sse_pair_return_tag(unmodelled), None, "{unmodelled}");
            assert_eq!(sse_pair_return_definition(unmodelled), None, "{unmodelled}");
        }
        assert_eq!(sse_pair_return_high_bytes("double"), None);
        assert_eq!(
            sse_pair_return_high_bytes("struct __glaurung_split_is"),
            None
        );
        assert_eq!(synthesised_return_definition("double"), None);
        // The split-bank tags keep their own definitions through the shared
        // entry point.
        for integer_first in [true, false] {
            assert_eq!(
                synthesised_return_definition(split_bank_return_tag(integer_first)).as_deref(),
                Some(split_bank_return_definition(integer_first))
            );
        }
    }

    /// `xmm1` is the high half of a result PAIR, not another spelling of the
    /// result. It must be recognisable as that half and must never appear in
    /// the alias list, where the naming pass would take a scratch `xmm1` for
    /// the function's return value.
    #[test]
    fn the_high_sse_result_register_is_a_pair_member_not_an_alias() {
        assert!(is_sse_pair_high_return_register(
            CallConv::SysVAmd64,
            "xmm1"
        ));
        assert!(is_sse_pair_high_return_register(
            CallConv::SysVAmd64,
            "xmm1#7"
        ));
        assert!(is_sse_pair_high_return_register(
            CallConv::SysVAmd64,
            "ymm1#7"
        ));
        assert!(!is_sse_pair_high_return_register(
            CallConv::SysVAmd64,
            "xmm0"
        ));
        assert!(!is_sse_pair_high_return_register(
            CallConv::SysVAmd64,
            "rax"
        ));
        assert!(!return_registers(CallConv::SysVAmd64).contains(&"xmm1"));
        assert!(!is_return_register(CallConv::SysVAmd64, "xmm1"));
        // No other convention has a modelled `xmm0:xmm1` result contract.
        for cc in [
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert!(
                sse_pair_high_return_registers(cc).is_empty(),
                "{cc:?} acquired a second SSE result register"
            );
            assert!(!is_sse_pair_high_return_register(cc, "xmm1"), "{cc:?}");
        }
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
