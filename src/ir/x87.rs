//! x87 floating-point lifting for the x86 lifter.
//!
//! i386 has no SSE in its baseline ABI, so **every** scalar float and double on
//! that lane is computed on the x87 stack. Until this module existed
//! `src/ir/lift_x86.rs` had no `fld`, `fstp`, `faddp` or `fistp` at all: a
//! `float`-taking function decompiled to `(void)` with its arithmetic reduced
//! to `/* asm: fld */` comments.
//!
//! # The register stack, and why this module is a pass rather than a table
//!
//! x87 is not a register file. `ST(i)` is *relative to the current top*: `fld`
//! pushes (TOP decrements), `fstp` pops, and the same textual `%st(1)` names
//! different physical storage at different points in the program. A per
//! instruction lifter — which is what `lift_one` is — cannot name the storage
//! an instruction touches without knowing the stack DEPTH at that point.
//!
//! So this module runs first, over a whole decoded window, and answers exactly
//! one question per instruction: **how deep is the stack here?** With a proven
//! depth `d`, `ST(i)` is the ABSOLUTE slot `d - 1 - i`, and the eight absolute
//! slots are lifted as eight ordinary physical registers `st0`..`st7`. SSA,
//! liveness, DCE and type recovery then process x87 with no special cases —
//! the same trick `lift_x86` already plays on packed XMM lanes.
//!
//! **`st0`..`st7` are ABSOLUTE slot names, not `%st(0)`..`%st(7)`.** `st0` is
//! the bottom of the stack, the first value pushed into an empty stack. The two
//! spellings coincide at depth 1, which is the only depth the ABI can observe:
//! the i386 cdecl convention requires the x87 stack to be EMPTY at every call
//! boundary except for a floating-point result left in `%st(0)`. That is why
//! [`crate::ir::abi::float_return_registers`] can name `st0` and be right.
//!
//! # What is proven, and what is refused
//!
//! [`plan_window`] and [`plan_function`] fail closed. They return `None` — and
//! every x87 instruction then keeps a conservative opaque lowering — whenever
//! they cannot prove what they need:
//!
//! * a depth that disagrees between two predecessors of the same instruction,
//! * an underflow, an overflow past eight slots, or an indirect branch that
//!   could reach an unknown depth,
//! * a **call reached at non-zero depth**, which the ABI forbids and which is
//!   the proof that no x87 value is ever live across a call (see
//!   `ast::float_gate::scalar_float_semantics_are_closed` — not a link, because
//!   that function is private to a child of `ast`, so no path names it here),
//! * any x87 mnemonic outside the supported set,
//! * any control-word traffic that is not the exact GCC truncation idiom.
//!
//! Guessing here is worse than refusing. A wrong depth renames every later slot
//! and would silently attach one variable's arithmetic to another's.
//!
//! # The 80-bit caveat, stated rather than hidden
//!
//! x87 computes internally in 80-bit extended precision. This module models a
//! slot as binary64. Every *transfer* is therefore exact — a binary32 load
//! widens exactly, a binary64 load or store is the identity — and only the
//! rounding of INTERMEDIATE results differs from hardware. That difference is
//! not papered over: it is the same difference the recompiled C carries, since
//! the fixture harness rebuilds our output with the same compiler for the same
//! target, where `double` arithmetic is again evaluated on the x87 stack
//! (`FLT_EVAL_METHOD == 2`). `181_compensated_summation` is the fixture that
//! can tell the difference, and it is in the measured set for exactly that
//! reason. A slot is NOT modelled as `long double`: `ScalarType` has no 80-bit
//! variant, and inventing one would be a much larger change than the arithmetic
//! it would buy.
//!
//! # Rounding mode
//!
//! `fistp` rounds according to the x87 control word, so it is a C truncating
//! cast only when RC is 11. GCC states that itself, by bracketing every
//! float-to-integer conversion with a save/modify/load/restore of the control
//! word. [`truncation_windows`] recognises exactly that idiom and nothing else;
//! an `fistp` whose rounding mode is not proven sends the whole window to the
//! opaque path rather than claiming a truncation it cannot justify.

use std::collections::HashMap;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::ir::types::{MemOp, Op, VReg, Value, Width};

/// The eight absolute x87 stack slots, bottom first. See the module docs: these
/// are NOT `%st(0)`..`%st(7)`.
const SLOT_NAMES: [&str; 8] = ["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"];

/// Whether `name` spells one of the absolute x87 stack slots.
///
/// The naming pass, the AST float guard and type recovery all need to recognise
/// this bank, and each of them asking the question its own way is how a bank
/// ends up half-known. One predicate, exported.
pub fn is_slot_name(name: &str) -> bool {
    SLOT_NAMES.contains(&name)
}

fn slot(index: u8) -> VReg {
    VReg::phys(SLOT_NAMES[index as usize])
}

/// Scratch registers this module introduces. Numbered well clear of the
/// `Temp(0..=128)` range `lift_x86` already uses for its own expansions.
const TEMP_MEM: u32 = 200;
const TEMP_WIDE: u32 = 201;
const TEMP_SWAP: u32 = 202;
const TEMP_RESULT: u32 = 203;

/// Whether this mnemonic is an x87 instruction.
///
/// Deliberately spelled as "every mnemonic whose name begins with `F`", plus
/// `wait`. Enumerating the ones we UNDERSTAND is [`effect`]'s job; this
/// predicate has the opposite duty — it must not miss one. `fxsave`, `frstor`,
/// `ffree` and `femms` all disturb x87 state, and every one of them would be
/// absent from a hand-written list of "floating-point instructions".
pub fn is_x87(mnemonic: Mnemonic) -> bool {
    if matches!(mnemonic, Mnemonic::Wait) {
        return true;
    }
    format!("{mnemonic:?}").starts_with('F')
}

/// What one x87 instruction does to the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Effect {
    /// Minimum depth the instruction needs before it executes.
    requires: u8,
    /// Change in depth: `+1` for a push, `-1` for a pop, `0` otherwise.
    delta: i8,
    /// Whether the instruction empties the stack outright, whatever the depth.
    /// `fninit` is the only one modelled, and `delta` does not apply to it.
    resets: bool,
}

impl Effect {
    const fn new(requires: u8, delta: i8) -> Self {
        Self {
            requires,
            delta,
            resets: false,
        }
    }

    /// `fninit`: the whole x87 state, stack included, returns to its power-on
    /// value.
    const fn reset() -> Self {
        Self {
            requires: 0,
            delta: 0,
            resets: true,
        }
    }
}

/// The register index of an `ST(i)` operand, or `None` when the operand is not
/// an x87 register.
fn st_index(instr: &Instruction, operand: u32) -> Option<u8> {
    if instr.op_kind(operand) != OpKind::Register {
        return None;
    }
    let register = instr.op_register(operand) as u32;
    let first = Register::ST0 as u32;
    (first..first + 8)
        .contains(&register)
        .then(|| (register - first) as u8)
}

/// The `ST(i)` an `fxch` exchanges the top with.
///
/// iced spells `fxch st(1)` with BOTH registers explicit — `(ST0, ST1)` — and a
/// bare `fxch` with neither, where the architecture supplies `ST(1)`. Reading
/// operand zero alone therefore saw `ST(0)` and lowered the exchange to a
/// no-op, which silently transposed the two operands of every `fsubr` after it.
fn exchange_index(instr: &Instruction) -> u8 {
    let explicit = (0..instr.op_count())
        .filter_map(|operand| st_index(instr, operand))
        .max();
    match explicit {
        Some(index) => index,
        None => 1,
    }
}

/// Whether the instruction's only explicit operand is memory.
fn is_memory_form(instr: &Instruction) -> bool {
    instr.op_count() == 1 && instr.op_kind(0) == OpKind::Memory
}

/// Byte size of the memory operand.
fn memory_bytes(instr: &Instruction) -> u8 {
    instr.memory_size().size() as u8
}

/// The stack effect of `instr`, or `None` when this module does not model it.
///
/// `None` is a whole-window refusal, not a per-instruction one: an unmodelled
/// stack effect makes every LATER depth wrong, so there is nothing sound to do
/// with the rest of the window.
fn effect(instr: &Instruction) -> Option<Effect> {
    use Mnemonic as M;
    let mnemonic = instr.mnemonic();
    Some(match mnemonic {
        // Pure no-ops on the stack.
        M::Wait | M::Fnop => Effect::new(0, 0),
        // `fninit` empties the stack. It has always lowered to `Op::Nop`, which
        // is right for the state this IR models, but its DEPTH effect was
        // invisible before there was a depth to affect.
        M::Fninit => Effect::reset(),
        // The control word is not the stack.
        M::Fldcw | M::Fnstcw => Effect::new(0, 0),
        // Pushes.
        M::Fldz | M::Fld1 => Effect::new(0, 1),
        M::Fld => {
            if is_memory_form(instr) {
                match memory_bytes(instr) {
                    4 | 8 => Effect::new(0, 1),
                    // `fldt` is a real 80-bit load; there is no exact binary64
                    // for it, so refuse rather than round.
                    _ => return None,
                }
            } else {
                Effect::new(st_index(instr, 0)? + 1, 1)
            }
        }
        M::Fild => {
            if is_memory_form(instr) && matches!(memory_bytes(instr), 2 | 4 | 8) {
                Effect::new(0, 1)
            } else {
                return None;
            }
        }
        // Stores.
        M::Fst | M::Fstp => {
            let popping = mnemonic == M::Fstp;
            let delta = if popping { -1 } else { 0 };
            if is_memory_form(instr) {
                match memory_bytes(instr) {
                    4 | 8 => Effect::new(1, delta),
                    _ => return None,
                }
            } else {
                Effect::new(st_index(instr, 0)? + 1, delta)
            }
        }
        M::Fist | M::Fistp | M::Fisttp => {
            let popping = mnemonic != M::Fist;
            if is_memory_form(instr) && matches!(memory_bytes(instr), 4 | 8) {
                Effect::new(1, if popping { -1 } else { 0 })
            } else {
                return None;
            }
        }
        // Arithmetic.
        M::Fadd | M::Fsub | M::Fsubr | M::Fmul | M::Fdiv | M::Fdivr => {
            if is_memory_form(instr) {
                match memory_bytes(instr) {
                    4 | 8 => Effect::new(1, 0),
                    _ => return None,
                }
            } else {
                Effect::new(register_pair(instr)?.0 + 1, 0)
            }
        }
        M::Faddp | M::Fsubp | M::Fsubrp | M::Fmulp | M::Fdivrp | M::Fdivp => {
            Effect::new(register_pair(instr)?.0 + 1, -1)
        }
        M::Fchs => Effect::new(1, 0),
        M::Fxch => Effect::new(exchange_index(instr) + 1, 0),
        // EFLAGS-setting comparisons. The status-word forms (`fcom`, `fucom`,
        // …) are deliberately absent: their result reaches the program only
        // through `fnstsw`/`sahf`, which is a separate model.
        M::Fcomi | M::Fucomi => Effect::new(st_index(instr, 1)? + 1, 0),
        M::Fcomip | M::Fucomip => Effect::new(st_index(instr, 1)? + 1, -1),
        _ => return None,
    })
}

/// The `(destination_slot_index, source_slot_index)` of a two-register x87
/// arithmetic instruction, as RELATIVE `ST(i)` indices.
///
/// Both encodings put the destination first, Intel-style. Note that the AT&T
/// text is NOT a guide here: `gas` and `objdump` swap `fsub`/`fsubr` and
/// `fdiv`/`fdivr` for the two-register forms, so the bytes `de e1` print as
/// `fsubp %st,%st(1)` while the opcode is Intel `FSUBRP ST(1), ST(0)`. iced
/// reports the Intel mnemonic, which is what [`lift`] applies, and
/// `att_and_intel_disagree_about_fsubp` pins that.
fn register_pair(instr: &Instruction) -> Option<(u8, u8)> {
    match instr.op_count() {
        // `faddp` with no operands is `FADDP ST(1), ST(0)`.
        0 => Some((1, 0)),
        2 => Some((st_index(instr, 0)?, st_index(instr, 1)?)),
        _ => None,
    }
}

/// The GCC float-to-integer idiom, found by exact window match.
///
/// GCC emits precisely this, identically at `-O0` and `-O2`, for every C cast
/// from a floating-point type to an integer one on i386:
///
/// ```text
///   fnstcw  M1               ; save the current control word
///   movzwl  M1, r32          ; load it
///   or      $0xc, rh8        ; set RC = 11 (round toward zero)
///   mov     r16, M2          ; park the modified word
///   fldcw   M2               ; install it
///   fistp   Mdst             ; the conversion, now truncating
///   fldcw   M1               ; restore
/// ```
///
/// Matching the whole window — including the restore — is what makes the claim
/// sound. Recognising the `fldcw` alone would say nothing about which bits were
/// set, and recognising the `fistp` alone would claim C semantics for what is,
/// under the default control word, a round-to-nearest `lrint`.
///
/// The immediate is checked, not assumed: `or $0xc, %ah` sets bits 8..15, so
/// the value ORed into the 16-bit word is `0x0c00`, and `0x0c00` IS the RC
/// field. An immediate that sets only one of the two RC bits selects round-down
/// or round-up and must not match.
struct TruncationWindows {
    /// Instruction indices whose `fist`/`fistp` is proven truncating.
    truncating: Vec<bool>,
    /// Indices of the `fldcw`/`fnstcw` accounted for by a matched window.
    accounted: Vec<bool>,
}

/// Find every GCC truncation window in `instrs`.
fn truncation_windows(instrs: &[Instruction]) -> TruncationWindows {
    let mut windows = TruncationWindows {
        truncating: vec![false; instrs.len()],
        accounted: vec![false; instrs.len()],
    };
    for start in 0..instrs.len() {
        if let Some((conversion, restore)) = window_at(instrs, start) {
            windows.truncating[conversion] = true;
            windows.accounted[start] = true;
            windows.accounted[start + 4] = true;
            windows.accounted[restore] = true;
        }
    }
    windows
}

/// `(index of the conversion, index of the restore)` when a window starts
/// at `start`.
fn window_at(instrs: &[Instruction], start: usize) -> Option<(usize, usize)> {
    let window = instrs.get(start..start + 7)?;
    let [save, load, set, park, install, conversion, restore] = window else {
        return None;
    };
    // fnstcw M1
    if save.mnemonic() != Mnemonic::Fnstcw || !is_memory_form(save) {
        return None;
    }
    // movzwl M1, r32 — the same slot, read back.
    if load.mnemonic() != Mnemonic::Movzx
        || load.op_kind(1) != OpKind::Memory
        || !same_memory_operand(save, load)
    {
        return None;
    }
    let scratch = load.op_register(0);
    // or $imm, <a view of the same register>, setting BOTH RC bits.
    if set.mnemonic() != Mnemonic::Or || set.op_kind(0) != OpKind::Register {
        return None;
    }
    if !same_register_family(set.op_register(0), scratch) {
        return None;
    }
    let mask = or_immediate_as_control_word_bits(set)?;
    if mask & 0x0c00 != 0x0c00 {
        return None;
    }
    // mov r16, M2
    if park.mnemonic() != Mnemonic::Mov
        || park.op_kind(0) != OpKind::Memory
        || park.op_kind(1) != OpKind::Register
        || !same_register_family(park.op_register(1), scratch)
        || park.memory_size().size() != 2
    {
        return None;
    }
    // fldcw M2 — the slot just parked to.
    if install.mnemonic() != Mnemonic::Fldcw
        || !is_memory_form(install)
        || !same_memory_operand(park, install)
    {
        return None;
    }
    // The conversion itself.
    if !matches!(conversion.mnemonic(), Mnemonic::Fist | Mnemonic::Fistp) {
        return None;
    }
    // fldcw M1 — the saved word, restored.
    if restore.mnemonic() != Mnemonic::Fldcw
        || !is_memory_form(restore)
        || !same_memory_operand(save, restore)
    {
        return None;
    }
    Some((start + 5, start + 6))
}

/// The canonical parent of a general-purpose register, so that `eax`, `ax` and
/// `ah` all compare equal.
///
/// Asked of the shared register-view descriptor rather than of iced: iced's
/// `RegisterExt::full_register` lives behind an optional feature this crate does
/// not enable, and `regview` is the table every other pass already agrees with.
/// `None` for anything that is not a modelled x86-64 view, which fails the
/// window match closed.
fn register_family(register: Register) -> Option<&'static str> {
    let name = format!("{register:?}").to_ascii_lowercase();
    crate::ir::regview::parent_of(
        crate::ir::regview::Arch::X86_64,
        &crate::ir::regview::canonical_name(&name),
    )
}

/// Whether two register operands are views of the same architectural register.
fn same_register_family(left: Register, right: Register) -> bool {
    match (register_family(left), register_family(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

/// The value an `or $imm, reg` ORs into the low 16 bits of its register's
/// parent, or `None` when the destination is not a 16-bit-or-narrower view.
///
/// `or $0xc, %ah` and `or $0xc00, %eax` are the same operation on the control
/// word; only the second states the shift in the immediate.
fn or_immediate_as_control_word_bits(instr: &Instruction) -> Option<u32> {
    let immediate: u32 = match instr.op_kind(1) {
        OpKind::Immediate8 => u32::from(instr.immediate8()),
        OpKind::Immediate8to16 => (instr.immediate8to16() as u16).into(),
        OpKind::Immediate8to32 => instr.immediate8to32() as u32,
        OpKind::Immediate16 => u32::from(instr.immediate16()),
        OpKind::Immediate32 => instr.immediate32(),
        _ => return None,
    };
    let register = instr.op_register(0);
    if matches!(
        register,
        Register::AH | Register::BH | Register::CH | Register::DH
    ) {
        Some((immediate & 0xff) << 8)
    } else {
        Some(immediate & 0xffff)
    }
}

/// Whether two instructions name the same effective address.
fn same_memory_operand(left: &Instruction, right: &Instruction) -> bool {
    left.memory_base() == right.memory_base()
        && left.memory_index() == right.memory_index()
        && left.memory_index_scale() == right.memory_index_scale()
        && left.memory_displacement64() == right.memory_displacement64()
        && left.memory_segment() == right.memory_segment()
}

/// The x87 stack state proven at one program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotState {
    /// Number of live slots BEFORE this instruction executes.
    depth: u8,
    /// Whether an `fist`/`fistp` here is proven to round toward zero.
    truncating: bool,
}

/// Proven x87 stack states, keyed by instruction address.
///
/// Keyed by VA rather than by index because the two producers see the code
/// differently: [`plan_window`] has one flat byte range, while
/// [`plan_function`] has the basic blocks the CFG recovered, which need not be
/// contiguous or in address order. An address is the one name both agree on.
#[derive(Debug, Default)]
pub struct Depths {
    at: std::collections::BTreeMap<u64, SlotState>,
}

impl Depths {
    /// The proven state at `va`, or `None` when that address was never reached.
    pub fn state_at(&self, va: u64) -> Option<SlotState> {
        self.at.get(&va).copied()
    }
}

/// One basic block of a function, as [`plan_function`] needs to see it.
pub struct BlockWindow<'a> {
    /// Address of the block's first instruction.
    pub start_va: u64,
    /// The block's bytes.
    pub bytes: &'a [u8],
    /// Start addresses of the block's CFG successors.
    pub succs: &'a [u64],
}

/// Resolve the x87 stack depth over one flat decoded window.
///
/// This is the entry point for callers that hold raw bytes and no CFG — the
/// public `lift_bytes` API and the symbolic-execution helpers. It recovers the
/// basic blocks from the branch targets inside the window itself.
///
/// `None` means "do not lift x87 here", either because there is none or because
/// something is not proven. See the module docs for the complete refusal list.
pub fn plan_window(bytes: &[u8], start_va: u64, bits: u32) -> Option<Depths> {
    if !may_contain_x87(bytes) {
        return None;
    }
    let instrs = decode_window(bytes, start_va, bits);
    let (blocks, succs) = split_into_blocks(instrs)?;
    resolve(&blocks, &succs, 0)
}

/// Resolve the x87 stack depth over a function's recovered basic blocks.
///
/// x87 depth is a whole-function property: `dot_product_f32` pushes its
/// accumulator with `fldz` in the entry block and consumes it with `faddp` in
/// the loop body, so a per-block analysis starting each block at depth zero
/// would underflow and refuse the very shape the corpus is full of. The CFG the
/// rest of the decompiler already recovered is what makes the cross-block
/// answer available.
pub fn plan_function(windows: &[BlockWindow<'_>], bits: u32, entry_va: u64) -> Option<Depths> {
    if !windows.iter().any(|window| may_contain_x87(window.bytes)) {
        return None;
    }
    let index_of_va: HashMap<u64, usize> = windows
        .iter()
        .enumerate()
        .map(|(index, window)| (window.start_va, index))
        .collect();
    let entry = *index_of_va.get(&entry_va)?;
    let blocks: Vec<Vec<Instruction>> = windows
        .iter()
        .map(|window| decode_window(window.bytes, window.start_va, bits))
        .collect();
    let succs: Vec<Vec<usize>> = windows
        .iter()
        .map(|window| {
            window
                .succs
                .iter()
                .filter_map(|target| index_of_va.get(target).copied())
                .collect()
        })
        .collect();
    resolve(&blocks, &succs, entry)
}

/// Whether `bytes` could possibly contain an x87 instruction.
///
/// Every x87 opcode's first byte is in the escape range `d8`..`df`, and `fwait`
/// is `9b`; no other encoding reaches this module. So a window containing none
/// of those bytes has no x87 in it, whatever the operands say — a NECESSARY
/// condition, cheap to check, and false positives cost only a decode.
///
/// This exists because [`plan_function`] runs on every x86 function the
/// decompiler lifts, and without it every one of them would pay a second full
/// decode of its whole body to discover it has no floating point at all.
fn may_contain_x87(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|byte| *byte == 0x9b || (0xd8..=0xdf).contains(byte))
}

fn decode_window(bytes: &[u8], start_va: u64, bits: u32) -> Vec<Instruction> {
    let mut decoder = iced_x86::Decoder::new(bits, bytes, iced_x86::DecoderOptions::NONE);
    decoder.set_ip(start_va);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            break;
        }
        out.push(instr);
    }
    out
}

/// Recover the basic blocks of one flat window from its own branch targets.
///
/// Leaders are the first instruction, every in-window branch target, and every
/// instruction following a control transfer. `None` for a window containing an
/// indirect branch, whose successors — and therefore the depth at them — are
/// not knowable from the bytes.
#[allow(clippy::type_complexity)]
fn split_into_blocks(instrs: Vec<Instruction>) -> Option<(Vec<Vec<Instruction>>, Vec<Vec<usize>>)> {
    let index_of_va: HashMap<u64, usize> = instrs
        .iter()
        .enumerate()
        .map(|(index, instr)| (instr.ip(), index))
        .collect();
    let mut leaders: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    leaders.insert(0);
    for (index, instr) in instrs.iter().enumerate() {
        match instr.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                if let Some(&target) = index_of_va.get(&instr.near_branch_target()) {
                    leaders.insert(target);
                }
                leaders.insert(index + 1);
            }
            FlowControl::Return | FlowControl::Exception => {
                leaders.insert(index + 1);
            }
            FlowControl::IndirectBranch => return None,
            _ => {}
        }
    }
    leaders.retain(|&leader| leader < instrs.len());
    let starts: Vec<usize> = leaders.iter().copied().collect();
    let block_of: HashMap<usize, usize> = starts
        .iter()
        .enumerate()
        .map(|(block, &start)| (start, block))
        .collect();
    let mut blocks: Vec<Vec<Instruction>> = Vec::with_capacity(starts.len());
    let mut succs: Vec<Vec<usize>> = Vec::with_capacity(starts.len());
    for (position, &start) in starts.iter().enumerate() {
        let end = starts.get(position + 1).copied().unwrap_or(instrs.len());
        blocks.push(instrs[start..end].to_vec());
        let last = end - 1;
        let fallthrough = block_of.get(&end).copied();
        let taken = index_of_va
            .get(&instrs[last].near_branch_target())
            .and_then(|target| block_of.get(target))
            .copied();
        succs.push(match instrs[last].flow_control() {
            FlowControl::Return | FlowControl::Exception => Vec::new(),
            FlowControl::UnconditionalBranch => taken.into_iter().collect(),
            FlowControl::ConditionalBranch => taken.into_iter().chain(fallthrough).collect(),
            _ => fallthrough.into_iter().collect(),
        });
    }
    Some((blocks, succs))
}

/// The shared fixed point: propagate a depth of zero from `entry` and check
/// that every program point has exactly one.
fn resolve(blocks: &[Vec<Instruction>], succs: &[Vec<usize>], entry: usize) -> Option<Depths> {
    if !blocks
        .iter()
        .flatten()
        .any(|instr| is_x87(instr.mnemonic()))
    {
        return None;
    }
    // Every x87 instruction must be one we model. An unmodelled stack effect
    // makes every later depth wrong, so there is no partial answer to give.
    if blocks
        .iter()
        .flatten()
        .any(|instr| is_x87(instr.mnemonic()) && effect(instr).is_none())
    {
        return None;
    }
    // The truncation idiom is straight-line code, so it is matched inside a
    // block and never across one.
    let windows: Vec<TruncationWindows> = blocks
        .iter()
        .map(|block| truncation_windows(block))
        .collect();
    for (block, instrs) in blocks.iter().enumerate() {
        for (index, instr) in instrs.iter().enumerate() {
            // Control-word traffic outside a recognised window leaves the
            // rounding mode unknown for every instruction after it.
            if matches!(instr.mnemonic(), Mnemonic::Fldcw | Mnemonic::Fnstcw)
                && !windows[block].accounted[index]
            {
                return None;
            }
            if matches!(instr.mnemonic(), Mnemonic::Fist | Mnemonic::Fistp)
                && !windows[block].truncating[index]
            {
                return None;
            }
        }
    }

    let mut entry_depth: Vec<Option<u8>> = vec![None; blocks.len()];
    let mut at: std::collections::BTreeMap<u64, SlotState> = std::collections::BTreeMap::new();
    let mut work = vec![(entry, 0u8)];
    while let Some((block, incoming)) = work.pop() {
        match entry_depth[block] {
            // A disagreement between predecessors means the depth is not a
            // property of the program point. Refuse.
            Some(seen) if seen != incoming => return None,
            Some(_) => continue,
            None => entry_depth[block] = Some(incoming),
        }
        let mut depth = incoming;
        for (index, instr) in blocks[block].iter().enumerate() {
            let flow = instr.flow_control();
            // The i386 ABI requires the x87 stack to be empty at a call
            // boundary. Enforcing it is what proves no x87 value is live across
            // a call, which `ast::scalar_float_semantics_are_closed` relies on
            // to keep lowering float arithmetic through the PC-thunk call every
            // PIC function makes.
            if matches!(flow, FlowControl::Call | FlowControl::IndirectCall) && depth != 0 {
                return None;
            }
            if is_x87(instr.mnemonic()) {
                let effect = effect(instr)?;
                if depth < effect.requires {
                    return None;
                }
                at.insert(
                    instr.ip(),
                    SlotState {
                        depth,
                        truncating: windows[block].truncating[index],
                    },
                );
                let next = if effect.resets {
                    0
                } else {
                    let next = i16::from(depth) + i16::from(effect.delta);
                    if !(0..=8).contains(&next) {
                        return None;
                    }
                    next as u8
                };
                depth = next;
            } else if matches!(flow, FlowControl::Call | FlowControl::IndirectCall)
                && call_returns_on_the_stack(&blocks[block], index, depth)
            {
                depth += 1;
            }
        }
        for &successor in &succs[block] {
            work.push((successor, depth));
        }
    }
    Some(Depths { at })
}

/// Whether the call at `index` leaves a floating-point result on the stack.
///
/// The instruction stream does not carry the callee's return type, so this is
/// decided by demand: walk the straight-line code after the call, tracking what
/// the x87 instructions do to the stack, and ask whether any of them needs a
/// value that is not there. Nothing else can supply one — the ABI guarantees
/// the stack was empty when the call was made — so an instruction that needs a
/// deeper stack than the caller had is stating that the callee returned a
/// `float` or `double`.
///
/// The walk cannot stop at the FIRST x87 instruction, which is what it did
/// until `181_compensated_summation::summation_disagrees` at `-O2` showed why:
///
/// ```text
///   call kahan_sum_f64      ; leaves its result in %st(0)
///   fldl 0x18(%esp)         ; pushes — needs nothing, so demands nothing
///   fucomip %st(1),%st      ; HERE is where the missing value is noticed
/// ```
///
/// A push in between hides the demand. Reading only the `fldl`, the call looked
/// like it returned an integer, the `fucomip` then underflowed, and the whole
/// function fell back to opaque comments — while the same function at `-O0`,
/// whose reload follows the call directly, lifted correctly.
fn call_returns_on_the_stack(instrs: &[Instruction], index: usize, incoming: u8) -> bool {
    let mut depth = incoming;
    for instr in &instrs[index + 1..] {
        if !is_x87(instr.mnemonic()) {
            if instr.flow_control() != FlowControl::Next {
                return false;
            }
            continue;
        }
        let Some(effect) = effect(instr) else {
            return false;
        };
        if depth < effect.requires {
            return true;
        }
        depth = if effect.resets {
            0
        } else {
            match u8::try_from(i16::from(depth) + i16::from(effect.delta)) {
                Ok(next) if next <= 8 => next,
                // Out of range with no value from the call, so the call cannot
                // be what makes the window consistent.
                _ => return false,
            }
        };
    }
    false
}

/// The ops for one x87 instruction at a proven stack state.
///
/// `None` when the instruction is not modelled — the caller then leaves it on
/// the opaque path rather than inventing semantics.
pub fn lift_instruction(instr: &Instruction, state: SlotState) -> Option<Vec<Op>> {
    if !is_x87(instr.mnemonic()) {
        return None;
    }
    lift_at(instr, state.depth, state.truncating)
}

/// Load a memory operand as a binary64 value in `dst`.
///
/// A binary32 operand is widened through the same `cvtss2sd` the SSE lifter
/// emits, so one AST lowering serves both producers.
fn load_as_double(instr: &Instruction, dst: VReg, ops: &mut Vec<Op>) -> Option<()> {
    let bytes = memory_bytes(instr);
    let mut addr = memory_operand(instr);
    addr.size = bytes;
    match bytes {
        8 => ops.push(Op::Load { dst, addr }),
        4 => {
            let raw = VReg::Temp(TEMP_MEM);
            ops.push(Op::Load {
                dst: raw.clone(),
                addr,
            });
            ops.push(Op::Intrinsic {
                name: "cvtss2sd".into(),
                ins: vec![Value::Reg(raw)],
                outs: vec![(dst, Width::W64)],
                reads_mem: false,
                writes_mem: false,
            });
        }
        _ => return None,
    }
    Some(())
}

/// The effective address of the instruction's memory operand.
///
/// A private copy of `lift_x86::mem_op_of`'s body would be a second thing to
/// keep in step, so the shared one is used; only the size is overridden, which
/// x87 needs because a slot is binary64 whatever the operand's width.
fn memory_operand(instr: &Instruction) -> MemOp {
    crate::ir::lift_x86::mem_op_of(instr)
}

/// Lift one x87 instruction at a proven depth.
fn lift_at(instr: &Instruction, depth: u8, truncating: bool) -> Option<Vec<Op>> {
    use Mnemonic as M;
    let effect = effect(instr)?;
    if depth < effect.requires {
        return None;
    }
    // `ST(i)` at this depth.
    let relative = |i: u8| slot(depth - 1 - i);
    let top = || slot(depth.wrapping_sub(1));
    let mut ops: Vec<Op> = Vec::new();
    let mnemonic = instr.mnemonic();
    match mnemonic {
        M::Wait | M::Fnop | M::Fninit => ops.push(Op::Nop),
        M::Fldcw => {
            // The control word is read from memory. Spelling the load keeps the
            // memory dependency real: the value comes from the slot `fnstcw`
            // wrote, and dropping the read would leave that store looking dead.
            let raw = VReg::Temp(TEMP_MEM);
            let mut addr = memory_operand(instr);
            addr.size = 2;
            ops.push(Op::Load {
                dst: raw.clone(),
                addr,
            });
            ops.push(Op::Intrinsic {
                name: "x87.fldcw".into(),
                ins: vec![Value::Reg(raw)],
                outs: vec![],
                reads_mem: false,
                writes_mem: false,
            });
        }
        M::Fnstcw => {
            let raw = VReg::Temp(TEMP_MEM);
            let mut addr = memory_operand(instr);
            addr.size = 2;
            ops.push(Op::Intrinsic {
                name: "x87.fnstcw".into(),
                ins: vec![],
                outs: vec![(raw.clone(), Width::W16)],
                reads_mem: false,
                writes_mem: false,
            });
            ops.push(Op::Store {
                addr,
                src: Value::Reg(raw),
            });
        }
        M::Fldz | M::Fld1 => {
            let bits = if mnemonic == M::Fldz {
                0.0f64.to_bits()
            } else {
                1.0f64.to_bits()
            };
            ops.push(Op::Intrinsic {
                name: "vmov.f64".into(),
                ins: vec![Value::Const(bits as i64)],
                outs: vec![(slot(depth), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            });
        }
        M::Fld => {
            if is_memory_form(instr) {
                load_as_double(instr, slot(depth), &mut ops)?;
            } else {
                let source = relative(st_index(instr, 0)?);
                ops.push(Op::Assign {
                    dst: slot(depth),
                    src: Value::Reg(source),
                });
            }
        }
        M::Fild => {
            let bytes = memory_bytes(instr);
            let mut addr = memory_operand(instr);
            addr.size = bytes;
            let raw = VReg::Temp(TEMP_MEM);
            ops.push(Op::Load {
                dst: raw.clone(),
                addr,
            });
            // A 16-bit integer has no `cvtsi2sd` spelling of its own; widening
            // it to 32 bits first is exact and reuses the modelled conversion.
            let source = if bytes == 2 {
                let wide = VReg::Temp(TEMP_WIDE);
                ops.push(Op::SExt {
                    dst: wide.clone(),
                    src: Value::Reg(raw),
                    from: Width::W16,
                    to: Width::W32,
                });
                wide
            } else {
                raw
            };
            ops.push(Op::Intrinsic {
                name: if bytes == 8 {
                    "cvtsi2sd.q".into()
                } else {
                    "cvtsi2sd.l".into()
                },
                ins: vec![Value::Reg(source)],
                outs: vec![(slot(depth), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            });
        }
        M::Fst | M::Fstp => {
            if is_memory_form(instr) {
                let bytes = memory_bytes(instr);
                let mut addr = memory_operand(instr);
                addr.size = bytes;
                let value = if bytes == 4 {
                    let narrowed = VReg::Temp(TEMP_RESULT);
                    ops.push(Op::Intrinsic {
                        name: "cvtsd2ss".into(),
                        ins: vec![Value::Reg(top())],
                        outs: vec![(narrowed.clone(), Width::W32)],
                        reads_mem: false,
                        writes_mem: false,
                    });
                    narrowed
                } else {
                    top()
                };
                ops.push(Op::Store {
                    addr,
                    src: Value::Reg(value),
                });
            } else {
                let index = st_index(instr, 0)?;
                // `fstp %st(0)` is a pure discard, and `fst %st(0)` a no-op.
                // Emitting `st0 = st0` for either would create a self-referential
                // definition for copy propagation to chase.
                if index == 0 {
                    ops.push(Op::Nop);
                } else {
                    ops.push(Op::Assign {
                        dst: relative(index),
                        src: Value::Reg(top()),
                    });
                }
            }
        }
        M::Fist | M::Fistp | M::Fisttp => {
            // `fisttp` truncates by definition; `fist`/`fistp` only under a
            // control word the depth pass has proven. Neither is reached otherwise.
            if mnemonic != M::Fisttp && !truncating {
                return None;
            }
            let bytes = memory_bytes(instr);
            let mut addr = memory_operand(instr);
            addr.size = bytes;
            let converted = VReg::Temp(TEMP_RESULT);
            ops.push(Op::Intrinsic {
                name: "cvttsd2si".into(),
                ins: vec![Value::Reg(top())],
                outs: vec![(
                    converted.clone(),
                    if bytes == 8 { Width::W64 } else { Width::W32 },
                )],
                reads_mem: false,
                writes_mem: false,
            });
            ops.push(Op::Store {
                addr,
                src: Value::Reg(converted),
            });
        }
        M::Fadd
        | M::Fsub
        | M::Fsubr
        | M::Fmul
        | M::Fdiv
        | M::Fdivr
        | M::Faddp
        | M::Fsubp
        | M::Fsubrp
        | M::Fmulp
        | M::Fdivp
        | M::Fdivrp => {
            let (name, reversed) = arithmetic_name(mnemonic);
            let (destination, left, right) = if is_memory_form(instr) {
                let loaded = VReg::Temp(TEMP_WIDE);
                load_as_double(instr, loaded.clone(), &mut ops)?;
                (top(), top(), loaded)
            } else {
                let (destination_index, source_index) = register_pair(instr)?;
                (
                    relative(destination_index),
                    relative(destination_index),
                    relative(source_index),
                )
            };
            let (left, right) = if reversed {
                (right, left)
            } else {
                (left, right)
            };
            ops.push(Op::Intrinsic {
                name: name.into(),
                ins: vec![Value::Reg(left), Value::Reg(right)],
                outs: vec![(destination, Width::W64)],
                reads_mem: false,
                writes_mem: false,
            });
        }
        M::Fchs => {
            ops.push(Op::Intrinsic {
                name: "vneg.f64".into(),
                ins: vec![Value::Reg(top())],
                outs: vec![(top(), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            });
        }
        M::Fxch => {
            let index = exchange_index(instr);
            if index == 0 {
                ops.push(Op::Nop);
            } else {
                let other = relative(index);
                let scratch = VReg::Temp(TEMP_SWAP);
                ops.push(Op::Assign {
                    dst: scratch.clone(),
                    src: Value::Reg(top()),
                });
                ops.push(Op::Assign {
                    dst: top(),
                    src: Value::Reg(other.clone()),
                });
                ops.push(Op::Assign {
                    dst: other,
                    src: Value::Reg(scratch),
                });
            }
        }
        M::Fcomi | M::Fucomi | M::Fcomip | M::Fucomip => {
            let left = Value::Reg(relative(st_index(instr, 0)?));
            let right = Value::Reg(relative(st_index(instr, 1)?));
            // `fcomi` reports UNORDERED with ZF=PF=CF=1 exactly as `comisd`
            // does, so it shares that flag model rather than restating it.
            ops.extend(crate::ir::lift_x86::float_compare_flag_ops(left, right));
        }
        _ => return None,
    }
    Some(ops)
}

/// The modelled intrinsic name for an x87 arithmetic mnemonic, and whether the
/// opcode subtracts (or divides) in the reverse order.
///
/// The names are the SSE lifter's, deliberately: `addsd` already lowers to a C
/// `+` on a binary64 pair, which is what this is. One lowering, two producers.
fn arithmetic_name(mnemonic: Mnemonic) -> (&'static str, bool) {
    use Mnemonic as M;
    match mnemonic {
        M::Fadd | M::Faddp => ("addsd", false),
        M::Fmul | M::Fmulp => ("mulsd", false),
        M::Fsub | M::Fsubp => ("subsd", false),
        M::Fsubr | M::Fsubrp => ("subsd", true),
        M::Fdiv | M::Fdivp => ("divsd", false),
        M::Fdivr | M::Fdivrp => ("divsd", true),
        _ => unreachable!("arithmetic_name is only called for the mnemonics above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::lift_x86::lift_bytes;
    use crate::ir::types::LlirInstr;
    use iced_x86::{Decoder, DecoderOptions};

    /// Every encoding in these tests was produced by `as --32`, never derived
    /// from an opcode table by hand. The x87 encoding space is exactly where a
    /// hand-derived byte is most likely to be plausible and wrong.
    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder = Decoder::new(32, bytes, DecoderOptions::NONE);
        decoder.set_ip(0x1000);
        let mut out = Vec::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            assert!(!instr.is_invalid(), "test encoding failed to decode");
            out.push(instr);
        }
        out
    }

    fn lift32(bytes: &[u8]) -> Vec<LlirInstr> {
        lift_bytes(bytes, 0x1000, 32)
    }

    /// The proven stack states of a flat 32-bit window.
    fn plan32(bytes: &[u8]) -> Option<Depths> {
        plan_window(bytes, 0x1000, 32)
    }

    /// The proven depth at the instruction with index `index` in `decoded`.
    fn depth_of(depths: &Depths, decoded: &[Instruction], index: usize) -> Option<u8> {
        depths
            .state_at(decoded[index].ip())
            .map(|state| state.depth)
    }

    /// Ops of a single instruction lifted at a stated depth, with no plan.
    fn at_depth(bytes: &[u8], depth: u8) -> Vec<Op> {
        let decoded = decode(bytes);
        assert_eq!(decoded.len(), 1, "expected exactly one instruction");
        lift_at(&decoded[0], depth, false).expect("instruction should be modelled")
    }

    fn phys(name: &str) -> Value {
        Value::Reg(VReg::phys(name))
    }

    /// The load/store forms, at the two depths that make the absolute-slot
    /// naming visible.
    #[test]
    fn a_load_pushes_the_next_absolute_slot() {
        // flds 0x4(%esp) — a binary32 load widens through the SSE lifter's own
        // `cvtss2sd`, so one AST lowering serves both producers.
        let ops = at_depth(&[0xd9, 0x44, 0x24, 0x04], 0);
        assert!(
            matches!(&ops[0], Op::Load { dst, addr } if *dst == VReg::Temp(TEMP_MEM) && addr.size == 4),
            "{ops:?}"
        );
        assert!(
            matches!(&ops[1], Op::Intrinsic { name, outs, .. }
                if name == "cvtss2sd" && outs == &[(VReg::phys("st0"), Width::W64)]),
            "{ops:?}"
        );
        // The same instruction at depth 2 defines slot 2, not slot 0.
        let deeper = at_depth(&[0xd9, 0x44, 0x24, 0x04], 2);
        assert!(
            matches!(&deeper[1], Op::Intrinsic { outs, .. }
                if outs == &[(VReg::phys("st2"), Width::W64)]),
            "{deeper:?}"
        );
    }

    #[test]
    fn a_binary64_load_needs_no_conversion() {
        // fldl 0x8(%esp)
        let ops = at_depth(&[0xdd, 0x44, 0x24, 0x08], 1);
        assert_eq!(ops.len(), 1, "{ops:?}");
        assert!(
            matches!(&ops[0], Op::Load { dst, addr } if *dst == VReg::phys("st1") && addr.size == 8),
            "{ops:?}"
        );
    }

    #[test]
    fn an_integer_load_is_the_modelled_signed_conversion() {
        // fildl 0x4(%esp) — int32 -> double
        let ops = at_depth(&[0xdb, 0x44, 0x24, 0x04], 0);
        assert!(
            matches!(&ops[1], Op::Intrinsic { name, outs, .. }
                if name == "cvtsi2sd.l" && outs == &[(VReg::phys("st0"), Width::W64)]),
            "{ops:?}"
        );
        // fildll 0x4(%esp) — int64 -> double
        let wide = at_depth(&[0xdf, 0x6c, 0x24, 0x04], 0);
        assert!(
            matches!(&wide[1], Op::Intrinsic { name, .. } if name == "cvtsi2sd.q"),
            "{wide:?}"
        );
    }

    #[test]
    fn the_stack_constants_are_exact_float_immediates() {
        // fldz / fld1
        let zero = at_depth(&[0xd9, 0xee], 0);
        assert_eq!(
            zero,
            vec![Op::Intrinsic {
                name: "vmov.f64".into(),
                ins: vec![Value::Const(0)],
                outs: vec![(VReg::phys("st0"), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            }]
        );
        let one = at_depth(&[0xd9, 0xe8], 1);
        assert!(
            matches!(&one[0], Op::Intrinsic { ins, outs, .. }
                if ins == &[Value::Const(0x3ff0_0000_0000_0000)]
                    && outs == &[(VReg::phys("st1"), Width::W64)]),
            "{one:?}"
        );
    }

    #[test]
    fn a_binary32_store_rounds_through_the_modelled_narrowing() {
        // fstps 0x4(%esp) at depth 1
        let ops = at_depth(&[0xd9, 0x5c, 0x24, 0x04], 1);
        assert!(
            matches!(&ops[0], Op::Intrinsic { name, ins, outs, .. }
                if name == "cvtsd2ss"
                    && ins == &[phys("st0")]
                    && outs == &[(VReg::Temp(TEMP_RESULT), Width::W32)]),
            "{ops:?}"
        );
        assert!(
            matches!(&ops[1], Op::Store { addr, src }
                if addr.size == 4 && *src == Value::Reg(VReg::Temp(TEMP_RESULT))),
            "{ops:?}"
        );
    }

    /// `fstp %st(1)` drops the SECOND element and keeps the top — the net
    /// effect of "ST(1) := ST(0); pop". Reading it as "discard the top" is the
    /// single easiest way to mis-model x87, and `truncate_toward_zero` at `-O2`
    /// is built out of it.
    #[test]
    fn fstp_st1_keeps_the_top_and_drops_the_one_below() {
        let ops = at_depth(&[0xdd, 0xd9], 2);
        assert_eq!(
            ops,
            vec![Op::Assign {
                dst: VReg::phys("st0"),
                src: phys("st1"),
            }]
        );
        // ...and the depth really does fall by one, so the survivor is `st0`.
        let effect = effect(&decode(&[0xdd, 0xd9])[0]).expect("modelled");
        assert_eq!(effect, Effect::new(2, -1));
    }

    #[test]
    fn fstp_st0_is_a_pure_discard() {
        assert_eq!(at_depth(&[0xdd, 0xd8], 1), vec![Op::Nop]);
    }

    /// AT&T and Intel disagree about which of `fsubp`/`fsubrp` an opcode is,
    /// and this lifter follows iced, which is Intel. `de e1` prints as
    /// `fsubp %st,%st(1)` in `objdump` but IS `FSUBRP ST(1), ST(0)`, whose
    /// result is `ST(0) - ST(1)`.
    #[test]
    fn att_and_intel_disagree_about_fsubp() {
        let de_e1 = decode(&[0xde, 0xe1]);
        assert_eq!(de_e1[0].mnemonic(), Mnemonic::Fsubrp);
        // At depth 2: dst is ST(1) = st0, and the operands are reversed.
        let ops = lift_at(&de_e1[0], 2, false).expect("modelled");
        assert_eq!(
            ops,
            vec![Op::Intrinsic {
                name: "subsd".into(),
                // ST(0) - ST(1)  ==  st1 - st0
                ins: vec![phys("st1"), phys("st0")],
                outs: vec![(VReg::phys("st0"), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            }]
        );

        let de_ea = decode(&[0xde, 0xea]);
        assert_eq!(de_ea[0].mnemonic(), Mnemonic::Fsubp);
        // At depth 3: dst is ST(2) = st0, operands in order.
        let ops = lift_at(&de_ea[0], 3, false).expect("modelled");
        assert_eq!(
            ops,
            vec![Op::Intrinsic {
                name: "subsd".into(),
                // ST(2) - ST(0)  ==  st0 - st2
                ins: vec![phys("st0"), phys("st2")],
                outs: vec![(VReg::phys("st0"), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            }]
        );
    }

    /// The memory forms are NOT swapped by the assembler, so `fsubrs m` really
    /// is `m - ST(0)`.
    #[test]
    fn a_reverse_memory_subtract_puts_memory_on_the_left() {
        // fsubrs 0x4(%esp) at depth 1
        let ops = at_depth(&[0xd8, 0x6c, 0x24, 0x04], 1);
        assert!(
            matches!(&ops[2], Op::Intrinsic { name, ins, outs, .. }
                if name == "subsd"
                    && ins == &[Value::Reg(VReg::Temp(TEMP_WIDE)), phys("st0")]
                    && outs == &[(VReg::phys("st0"), Width::W64)]),
            "{ops:?}"
        );
        // ...while the plain form has the stack top on the left.
        let plain = at_depth(&[0xd8, 0x64, 0x24, 0x04], 1);
        assert!(
            matches!(&plain[2], Op::Intrinsic { ins, .. }
                if ins == &[phys("st0"), Value::Reg(VReg::Temp(TEMP_WIDE))]),
            "{plain:?}"
        );
    }

    #[test]
    fn faddp_accumulates_into_the_slot_below_and_pops() {
        // faddp %st,%st(1) at depth 2
        let ops = at_depth(&[0xde, 0xc1], 2);
        assert_eq!(
            ops,
            vec![Op::Intrinsic {
                name: "addsd".into(),
                ins: vec![phys("st0"), phys("st1")],
                outs: vec![(VReg::phys("st0"), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            }]
        );
    }

    #[test]
    fn fxch_swaps_two_absolute_slots() {
        // fxch %st(1) at depth 2
        let ops = at_depth(&[0xd9, 0xc9], 2);
        assert_eq!(
            ops,
            vec![
                Op::Assign {
                    dst: VReg::Temp(TEMP_SWAP),
                    src: phys("st1"),
                },
                Op::Assign {
                    dst: VReg::phys("st1"),
                    src: phys("st0"),
                },
                Op::Assign {
                    dst: VReg::phys("st0"),
                    src: Value::Reg(VReg::Temp(TEMP_SWAP)),
                },
            ]
        );
    }

    #[test]
    fn fchs_is_the_modelled_float_negation() {
        let ops = at_depth(&[0xd9, 0xe0], 1);
        assert!(
            matches!(&ops[0], Op::Intrinsic { name, ins, outs, .. }
                if name == "vneg.f64"
                    && ins == &[phys("st0")]
                    && outs == &[(VReg::phys("st0"), Width::W64)]),
            "{ops:?}"
        );
    }

    /// `fcomi` reports UNORDERED as ZF=PF=CF=1, exactly as `comisd` does, so it
    /// must produce the same flag ops — including the NaN term. A model that
    /// treated it as an integer compare would be right on ordered inputs and
    /// silently wrong on every NaN.
    #[test]
    fn fcomi_shares_the_comisd_flag_model() {
        let ops = at_depth(&[0xdb, 0xf1], 2);
        let expected = crate::ir::lift_x86::float_compare_flag_ops(phys("st1"), phys("st0"));
        assert_eq!(ops, expected);
        assert!(
            ops.iter().any(|op| matches!(op, Op::Bin { dst, .. } if *dst == VReg::Flag(crate::ir::types::Flag::P))),
            "the unordered term must be present: {ops:?}"
        );
        // The popping form has the same flags and one less slot after it.
        assert_eq!(effect(&decode(&[0xdf, 0xf1])[0]), Some(Effect::new(2, -1)));
    }

    // -- the stack-depth plan -------------------------------------------------

    #[test]
    fn a_window_with_no_x87_has_no_plan() {
        // ret
        assert!(plan32(&[0xc3]).is_none());
    }

    /// `truncate_toward_zero` at `-O2`, byte for byte from
    /// `gcc -m32 -O2 -shared -fPIC tests/decompiler_fixtures/src/173_float_int_conversions.c`,
    /// with the PIC thunk call retargeted into the window. It exercises the
    /// whole model at once: a call at depth 0, two pushes, `fcomi`, the
    /// `fstp %st(1)` idiom, a conditional branch whose two arms must agree, and
    /// the control-word window.
    fn truncate_toward_zero_o2() -> Vec<u8> {
        vec![
            // @0
            0xd9, 0x80, 0x0c, 0xe0, 0xff, 0xff, // flds -0x1ff4(%eax)
            // @6
            0xd9, 0x44, 0x24, 0x0c, // flds 0xc(%esp)
            // @10
            0xdb, 0xf1, // fcomi %st(1),%st
            // @12
            0xdd, 0xd9, // fstp %st(1)
            // @14
            0x72, 0x0e, // jb @30
            // @16
            0xd9, 0x80, 0x10, 0xe0, 0xff, 0xff, // flds -0x1ff0(%eax)
            // @22
            0xdf, 0xf1, // fcomip %st(1),%st
            // @24
            0x77, 0x09, // ja @35
            // @26
            0xdd, 0xd8, // fstp %st(0)
            // @28
            0xeb, 0x02, // jmp @32
            // @30
            0xdd, 0xd8, // fstp %st(0)
            // @32
            0x31, 0xc0, // xor %eax,%eax
            // @34
            0xc3, // ret
            // @35 — the truncation window
            0xd9, 0x7c, 0x24, 0x06, // fnstcw 0x6(%esp)
            0x0f, 0xb7, 0x44, 0x24, 0x06, // movzwl 0x6(%esp),%eax
            0x80, 0xcc, 0x0c, // or $0xc,%ah
            0x66, 0x89, 0x44, 0x24, 0x04, // mov %ax,0x4(%esp)
            0xd9, 0x6c, 0x24, 0x04, // fldcw 0x4(%esp)
            0xdb, 0x1c, 0x24, // fistpl (%esp)
            0xd9, 0x6c, 0x24, 0x06, // fldcw 0x6(%esp)
            0xc3, // ret
        ]
    }

    #[test]
    fn the_o2_conversion_body_resolves_every_depth() {
        let bytes = truncate_toward_zero_o2();
        let decoded = decode(&bytes);
        let depths = plan32(&bytes).expect("the -O2 conversion body must be provable");
        // Every x87 instruction got a depth.
        for (index, instr) in decoded.iter().enumerate() {
            if is_x87(instr.mnemonic()) {
                assert!(
                    depth_of(&depths, &decoded, index).is_some(),
                    "no depth for {instr} at index {index}"
                );
            }
        }
        // The two `fstp %st(0)` arms are reached at depth 1 and empty the stack.
        let discards: Vec<u8> = decoded
            .iter()
            .enumerate()
            .filter(|(_, instr)| {
                instr.mnemonic() == Mnemonic::Fstp && st_index(instr, 0) == Some(0)
            })
            .map(|(index, _)| depth_of(&depths, &decoded, index).expect("reached"))
            .collect();
        assert_eq!(discards, vec![1, 1]);
    }

    #[test]
    fn the_gcc_truncation_window_proves_a_c_cast() {
        let bytes = truncate_toward_zero_o2();
        let decoded = decode(&bytes);
        let depths = plan32(&bytes).expect("provable");
        let conversion = decoded
            .iter()
            .position(|instr| instr.mnemonic() == Mnemonic::Fistp)
            .expect("the body converts");
        let state = depths
            .state_at(decoded[conversion].ip())
            .expect("the conversion is reached");
        assert!(state.truncating, "the control-word window must prove RC=11");
        let ops = lift_instruction(&decoded[conversion], state)
            .expect("lifted as a truncating conversion");
        assert!(
            matches!(&ops[0], Op::Intrinsic { name, ins, outs, .. }
                if name == "cvttsd2si"
                    && ins == &[phys("st0")]
                    && outs == &[(VReg::Temp(TEMP_RESULT), Width::W32)]),
            "{ops:?}"
        );
    }

    /// An `fistp` under a control word we have not proven is NOT a C cast — it
    /// rounds to nearest, which disagrees with `(int)` for every value with a
    /// fractional part. The whole window is refused rather than claiming one.
    #[test]
    fn an_unguarded_conversion_refuses_the_whole_window() {
        // flds 0x4(%esp) ; fistpl (%esp) ; ret
        let bytes = [
            0xd9, 0x44, 0x24, 0x04, //
            0xdb, 0x1c, 0x24, //
            0xc3,
        ];
        assert!(
            plan32(&bytes).is_none(),
            "an fistp with no proven rounding mode must not be lifted"
        );
        // ...and every x87 instruction in it becomes a conservative opaque that
        // declares its memory footprint, not an effect-free `Op::Unknown`.
        let lifted = lift32(&bytes);
        assert!(
            lifted.iter().any(|instruction| matches!(&instruction.op,
                Op::Intrinsic { name, reads_mem: true, writes_mem: true, .. }
                    if name == "x87.fistp")),
            "{lifted:?}"
        );
    }

    /// Setting only ONE of the two RC bits selects round-down or round-up, not
    /// truncation. The immediate is checked, not assumed.
    #[test]
    fn a_partial_rounding_control_immediate_does_not_match() {
        let mut bytes = truncate_toward_zero_o2();
        // `or $0xc,%ah` -> `or $0x4,%ah`: RC = 01, round toward -inf.
        let position = bytes
            .windows(3)
            .position(|window| window == [0x80, 0xcc, 0x0c])
            .expect("the window is in the fixture bytes");
        bytes[position + 2] = 0x04;
        assert!(plan32(&bytes).is_none());
    }

    /// A `float`-returning callee leaves its result in `%st(0)`, and nothing in
    /// the instruction stream says so. The demand for a value that cannot
    /// otherwise exist is what says it.
    #[test]
    fn a_call_that_returns_a_double_pushes_a_slot() {
        // call +0 ; add $0x10,%esp ; fstpl -0x18(%ebp) ; ret
        // (the -O0 shape from 181_compensated_summation::summation_disagrees)
        let bytes = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //
            0x83, 0xc4, 0x10, //
            0xdd, 0x5d, 0xe8, //
            0xc3,
        ];
        let decoded = decode(&bytes);
        let depths = plan32(&bytes).expect("provable");
        assert_eq!(
            depth_of(&depths, &decoded, 2),
            Some(1),
            "the fstpl must see a full stack"
        );
        // A push between the call and the demand must not hide it: this is the
        // `-O2` shape of the same function, where the reload of the OTHER
        // summand comes first and only the compare notices the missing value.
        let hidden = [
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0xdd, 0x44, 0x24, 0x18, // fldl 0x18(%esp)
            0xdf, 0xe9, // fucomip %st(1),%st
            0xdd, 0xd8, // fstp %st(0)
            0xc3, // ret
        ];
        let decoded = decode(&hidden);
        let depths = plan32(&hidden).expect("provable");
        assert_eq!(
            depth_of(&depths, &decoded, 1),
            Some(1),
            "the call's result must be on the stack before the reload"
        );
        assert_eq!(depth_of(&depths, &decoded, 2), Some(2));

        // An integer-returning call is left alone: nothing demands a slot.
        let integer = [
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0xd9, 0xee, // fldz
            0xc3, // ret
        ];
        let decoded = decode(&integer);
        let depths = plan32(&integer).expect("provable");
        assert_eq!(depth_of(&depths, &decoded, 1), Some(0));
    }

    /// The i386 ABI requires the x87 stack to be empty at a call boundary. That
    /// refusal is not defensive tidiness: `ast::scalar_float_semantics_are_closed`
    /// treats the slot bank as caller-saved BECAUSE of it.
    #[test]
    fn a_value_live_across_a_call_is_refused() {
        // fldz ; call +0 ; fstpl -0x18(%ebp) ; ret
        let bytes = [
            0xd9, 0xee, //
            0xe8, 0x00, 0x00, 0x00, 0x00, //
            0xdd, 0x5d, 0xe8, //
            0xc3,
        ];
        assert!(plan32(&bytes).is_none());
    }

    #[test]
    fn disagreeing_predecessors_are_refused() {
        let bytes = [
            0xd9, 0xee, // fldz          (depth 0 -> 1)
            0x75, 0x02, // jne +2        (skips the second fldz)
            0xd9, 0xee, // fldz          (depth 1 -> 2)
            0xdd, 0x5d, 0xf8, // fstpl -0x8(%ebp)
            0xc3, // ret
        ];
        // Reached at 1 from the jump and at 2 by fallthrough: not a property of
        // the program point, so the whole window is refused.
        assert!(plan32(&bytes).is_none());
    }

    #[test]
    fn an_unmodelled_x87_instruction_refuses_the_whole_window() {
        for (name, bytes) in [
            ("fsqrt", vec![0xd9u8, 0xfa, 0xc3]),
            ("fabs", vec![0xd9, 0xe1, 0xc3]),
            // fcom %st(1): reports through the status word, not EFLAGS.
            ("fcom", vec![0xd8, 0xd1, 0xc3]),
            // fldt (%esp): a real 80-bit load, with no exact binary64 for it.
            ("fldt", vec![0xdb, 0x2c, 0x24, 0xc3]),
        ] {
            assert!(
                plan32(&bytes).is_none(),
                "{name} must not be lifted on thin semantics"
            );
        }
    }

    #[test]
    fn a_stack_overflow_is_refused() {
        // Nine pushes into eight slots.
        let mut bytes = vec![0xd9u8, 0xee].repeat(9);
        bytes.push(0xc3);
        assert!(plan32(&bytes).is_none());
    }

    /// End to end through `lift_bytes`: the accumulator loop of
    /// `175_float_matrix_kernel::dot_product_f32` at `-O2`.
    #[test]
    fn a_dot_product_loop_lifts_to_real_arithmetic() {
        let bytes = [
            0xd9, 0xee, // fldz
            0xd9, 0x04, 0x83, // flds (%ebx,%eax,4)
            0xd8, 0x0c, 0x82, // fmuls (%edx,%eax,4)
            0x83, 0xc0, 0x01, // add $0x1,%eax
            0xde, 0xc1, // faddp %st,%st(1)
            0xc3, // ret
        ];
        let lifted = lift32(&bytes);
        let names: Vec<&str> = lifted
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Intrinsic { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec!["vmov.f64", "cvtss2sd", "cvtss2sd", "mulsd", "addsd"]
        );
        // The accumulator is the bottom slot throughout, which is what makes it
        // the ABI's return register at the `ret`.
        assert!(
            lifted.iter().any(|instruction| matches!(&instruction.op,
                Op::Intrinsic { name, outs, .. }
                    if name == "addsd" && outs == &[(VReg::phys("st0"), Width::W64)])),
            "{lifted:?}"
        );
        assert!(
            !lifted
                .iter()
                .any(|instruction| matches!(instruction.op, Op::Unknown { .. })),
            "nothing should be left opaque: {lifted:?}"
        );
    }

    /// x86-64 shares this lifter, and the plan is architecture-neutral by
    /// construction. Nothing about a 64-bit window changes the stack model.
    #[test]
    fn the_same_plan_serves_64_bit_windows() {
        // fldz ; fstpl (%rsp) ; ret
        let bytes = [0xd9, 0xee, 0xdd, 0x1c, 0x24, 0xc3];
        let lifted = lift_bytes(&bytes, 0x1000, 64);
        assert!(
            lifted.iter().any(|instruction| matches!(&instruction.op,
                Op::Store { src: Value::Reg(VReg::Phys(name)), .. } if name == "st0")),
            "{lifted:?}"
        );
    }
}
