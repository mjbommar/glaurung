//! The S4 gate: run a lowered C function and the same function lifted from its
//! binary on the same interpreter, from the same inputs, and compare.
//!
//! `roadmap.md` section 6 states the gate exactly this way, and the shape of it
//! is what makes it worth having: **one interpreter, one domain, two front
//! ends**. Nothing here re-implements C semantics to check the lowering against
//! --- if it did, the check would only prove the two implementations agree with
//! each other. The reference is the compiled binary, which is the artefact the
//! decompiler is judged against.
//!
//! # What a disagreement can mean
//!
//! Three different things, and they must not be conflated:
//!
//! * the lowering is wrong;
//! * the *lifter* is wrong (the corpus exists because it is, in places);
//! * the C is genuinely ambiguous --- unspecified evaluation order, undefined
//!   overflow --- and the compiler picked a different reading than
//!   [`super::expr`] does.
//!
//! So a divergence is reported with both sides' values rather than asserted
//! away, and a run where either side did not reach `Return` is
//! [`Verdict::Inconclusive`], never a pass.

use crate::exec::{Budget, Concrete, Domain, Machine, Outcome};
use crate::ir::types::{Endian, LlirFunction, VReg, Width};

use super::func::{ARG_REGS, RESULT_REG};
use super::LoweredFunction;

/// What one (function, input vector) cell of the differential says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Both sides returned and the masked results are equal.
    Match { result: u64 },
    /// Both sides returned and disagree.
    Diverged { lowered: u64, lifted: u64 },
    /// At least one side did not reach a `Return`; no claim is made.
    Inconclusive { lowered: String, lifted: String },
}

/// The outcome of running one function under the interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// How execution ended.
    pub outcome: Outcome,
    /// The result register, masked to the declared result width. `None` when
    /// the function did not return normally.
    pub result: Option<u64>,
    /// Instructions retired.
    pub steps: u64,
}

impl Run {
    /// A short description of a non-returning outcome, for a report.
    pub fn detail(&self) -> String {
        match &self.outcome {
            Outcome::Returned => "returned".to_string(),
            Outcome::CalledOut(target) => format!("called out to {target:x?}"),
            Outcome::Halted(halt) => format!("halted: {halt:?}"),
            Outcome::BudgetExhausted => "budget exhausted".to_string(),
            Outcome::NoBlock(va) => format!("no block at {va:#x}"),
        }
    }
}

/// Mask a 64-bit register to a declared result width.
fn mask(value: u128, width: Option<Width>) -> u64 {
    match width {
        None => 0,
        Some(w) if w.bits() >= 64 => value as u64,
        Some(w) => (value as u64) & ((1u64 << w.bits()) - 1),
    }
}

/// Copy an ELF's `PT_LOAD` segments into a machine's memory at their virtual
/// addresses.
///
/// Without this the lifted side runs against an all-zero address space, and
/// that is not a hypothetical: at `-O2` clang vectorises a loop into `movdqa`
/// of an `.rodata` constant plus a `jmp` through an `.rodata` jump table, so a
/// function whose semantics the lifter models perfectly still returns the wrong
/// answer --- or lands on `Outcome::NoBlock` at the table's own address. Two
/// fixtures diverged for exactly that reason before this existed, and both read
/// as lifter defects until the segments were mapped.
///
/// `p_memsz` beyond `p_filesz` is `.bss`, which is already zero in a memory
/// that reads unwritten bytes as zero, so only the file-backed part is copied.
pub fn load_image<D: Domain>(machine: &mut Machine<D>, data: &[u8]) {
    let Ok(header) = crate::formats::elf::headers::parse_header(data) else {
        return;
    };
    let Ok(segments) = crate::formats::elf::segments::SegmentTable::parse(data, &header) else {
        return;
    };
    for segment in segments.load_segments() {
        let base = segment.header.p_vaddr;
        for (index, byte) in segment.data.iter().enumerate() {
            let value = machine.dom.constant(Width::W8, u128::from(*byte));
            machine.mem.store(
                &mut machine.dom,
                base + index as u64,
                &value,
                1,
                Endian::Little,
            );
        }
    }
}

/// Run an `LlirFunction` with `args` in the SysV integer argument registers.
///
/// `stack_pointer` is written to `rsp` so a lifted prologue's `push`/`[rbp-8]`
/// land in mapped-looking memory; the lowered function has no stack of its own
/// and ignores it. `image`, when given, is the ELF the function was lifted from
/// and is mapped first --- see [`load_image`].
pub fn run_with_args_on_image(
    func: &LlirFunction,
    args: &[u64],
    result_width: Option<Width>,
    stack_pointer: u64,
    max_steps: u64,
    image: Option<&[u8]>,
) -> Run {
    let mut machine = Machine::new(Concrete);
    if let Some(data) = image {
        load_image(&mut machine, data);
    }
    let sp = machine.dom.constant(Width::W64, stack_pointer as u128);
    machine.regs.write(&mut machine.dom, &VReg::phys("rsp"), sp);
    let bp = machine.dom.constant(Width::W64, stack_pointer as u128);
    machine.regs.write(&mut machine.dom, &VReg::phys("rbp"), bp);
    for (index, value) in args.iter().enumerate() {
        let Some(name) = ARG_REGS.get(index) else {
            break;
        };
        let v = machine.dom.constant(Width::W64, *value as u128);
        machine.regs.write(&mut machine.dom, &VReg::phys(*name), v);
    }
    let mut budget = Budget::new(max_steps);
    let outcome = machine.run_function(func, &mut budget);
    let result = match outcome {
        Outcome::Returned => {
            let raw = machine.regs.read(&mut machine.dom, &VReg::phys(RESULT_REG));
            Some(mask(raw, result_width))
        }
        _ => None,
    };
    Run {
        outcome,
        result,
        steps: budget.spent(),
    }
}

/// Run an `LlirFunction` with no image mapped. The lowered side, which touches
/// only its own frame, needs nothing else.
pub fn run_with_args(
    func: &LlirFunction,
    args: &[u64],
    result_width: Option<Width>,
    stack_pointer: u64,
    max_steps: u64,
) -> Run {
    run_with_args_on_image(func, args, result_width, stack_pointer, max_steps, None)
}

/// The stack pointer both sides start from. Far from the lowered function's
/// frame ([`super::build::FRAME_BASE`]) so a lifted function that scribbles on
/// its stack cannot land on a lowered local even in a shared address space.
pub const STACK_POINTER: u64 = 0x7fff_ffff_0000;

/// Compare one lowered function against its lifted counterpart on one input
/// vector.
pub fn compare(
    lowered: &LoweredFunction,
    lifted: &LlirFunction,
    image: &[u8],
    args: &[u64],
    max_steps: u64,
) -> Verdict {
    let width = lowered.result_width();
    let ours = run_with_args(&lowered.func, args, width, STACK_POINTER, max_steps);
    let theirs = run_with_args_on_image(lifted, args, width, STACK_POINTER, max_steps, Some(image));
    match (ours.result, theirs.result) {
        (Some(a), Some(b)) if a == b => Verdict::Match { result: a },
        (Some(a), Some(b)) => Verdict::Diverged {
            lowered: a,
            lifted: b,
        },
        _ => Verdict::Inconclusive {
            lowered: ours.detail(),
            lifted: theirs.detail(),
        },
    }
}

/// The argument values the differential sweeps.
///
/// Fixed and deterministic, and deliberately small in magnitude: a loop fixture
/// driven by a large `n` exhausts the instruction budget, and a budget
/// exhaustion is an inconclusive cell, not evidence. The set still covers the
/// boundaries that matter for width and signedness --- zero, one, negative one,
/// both signs of a 32-bit extreme --- because those are where a lowering that
/// got extension wrong stops agreeing.
pub const PROBE_VALUES: [u64; 12] = [
    0,
    1,
    2,
    7,
    0xffff_ffff_ffff_ffff, // -1
    0xffff_ffff_ffff_fff9, // -7
    0x0000_0000_7fff_ffff, // INT32_MAX
    0x0000_0000_8000_0000, // INT32_MIN as unsigned / 2^31
    0x0000_0000_0000_00ff,
    0x0000_0000_0001_0001,
    10,
    0x0000_0000_dead_beef,
];

/// Deterministic input vectors for a function of `arity` parameters.
///
/// One vector per probe value with every parameter set to it, plus the
/// "staggered" vectors that give each parameter a different probe --- an
/// all-equal sweep cannot tell `a - b` from `b - a`.
pub fn vectors(arity: usize) -> Vec<Vec<u64>> {
    if arity == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for value in PROBE_VALUES {
        out.push(vec![value; arity]);
    }
    for offset in 1..PROBE_VALUES.len() {
        out.push(
            (0..arity)
                .map(|i| PROBE_VALUES[(i * offset + offset) % PROBE_VALUES.len()])
                .collect(),
        );
    }
    // A one-parameter function's staggered vectors repeat its all-equal ones,
    // which would count the same experiment twice in the sweep's totals.
    out.sort();
    out.dedup();
    out
}
