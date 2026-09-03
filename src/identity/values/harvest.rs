//! Bounded concrete execution over one LLIR function, recording what it
//! computes.
//!
//! # What runs
//!
//! `crate::exec`'s concrete interpreter, unmodified. This module drives it
//! rather than calling [`crate::exec::Machine::run_function`], for three
//! reasons that loop cannot serve:
//!
//! 1. `run_function` stops at a call (`Outcome::CalledOut`). A value
//!    fingerprint has to run *past* one, so the loop here handles
//!    [`Flow::Call`] itself: a registered SimProcedure summary if the machine
//!    has one (those already return `Flow::Next` from `step`), otherwise a
//!    deterministic sentinel in the return register -- see
//!    [`super::seeds::callee_sentinel`].
//! 2. Nothing is recorded unless something watches every step. The loop reads
//!    each instruction's definition back out of the register file after the
//!    step, which is the register half of vSim's Table II, and reads a store's
//!    source before it, which is the memory half.
//! 3. Under-constrained execution needs uninitialised memory to read as a
//!    *fresh* value, and `crate::exec::Memory` reads unwritten bytes as zero.
//!    The loop pre-faults every load's effective address before the step: real
//!    bytes when the address is initialised image data, the seed's trial
//!    scalar otherwise.
//!
//! None of that required a change to `src/exec/`.
//!
//! # Determinism
//!
//! Every input to a run is a constant in [`super::seeds`] or a fact about the
//! bytes. The budget counts retired instructions, not milliseconds. Two runs
//! of the same function produce the same [`Harvest`], in this process and the
//! next one.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::exec::{Budget, Concrete, Domain, Flow, Halt, Machine};
use crate::ir::types::{CallTarget, Endian, LlirBlock, LlirFunction, MemOp, Op, VReg, Width};
use crate::ir::use_def::def_uses;

use super::seeds::{callee_sentinel, fresh_value, SEEDED_X86_64_REGISTERS, STACK_BASE};
use super::settings::ValueSettings;

/// What the harvester needs to know about the image the function came from.
///
/// Everything is a closure so the unit tests can build a context over
/// hand-written LLIR with no image and no disk, exactly as
/// `crate::identity::cfr::GraphContext` does.
pub struct ValueContext<'a> {
    pub settings: ValueSettings,
    /// Rules F1/F2: does this VA lie inside the image's mapped memory?
    pub is_mapped_address: &'a dyn Fn(u64) -> bool,
    /// Initialised image data: `size` bytes at a VA, as an integer in `endian`.
    /// `None` when the address is not backed by file bytes.
    pub image_word: &'a dyn Fn(u64, u8, Endian) -> Option<u128>,
    /// Stub address to external name, for calls that leave the image. An
    /// external symbol is a stable interface across builds; an internal callee
    /// address is not, which is why only these are named.
    pub external_names: &'a BTreeMap<u64, String>,
}

fn nothing_is_mapped(_address: u64) -> bool {
    false
}

fn no_image_word(_address: u64, _size: u8, _endian: Endian) -> Option<u128> {
    None
}

static NO_MAPPING: fn(u64) -> bool = nothing_is_mapped;
static NO_WORD: fn(u64, u8, Endian) -> Option<u128> = no_image_word;

/// A context with no image behind it: nothing mapped, nothing initialised, no
/// call target named. What the unit tests build against.
pub fn bare_context(settings: ValueSettings) -> ValueContext<'static> {
    static NO_NAMES: std::sync::OnceLock<BTreeMap<u64, String>> = std::sync::OnceLock::new();
    ValueContext {
        settings,
        is_mapped_address: &NO_MAPPING,
        image_word: &NO_WORD,
        external_names: NO_NAMES.get_or_init(BTreeMap::new),
    }
}

/// Why one seed's run stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Reached a return.
    Returned,
    /// Retired [`ValueSettings::max_steps`] instructions.
    BudgetExhausted,
    /// The interpreter halted: an unsupported intrinsic, a residual
    /// `Op::Unknown`, an address that would not concretize.
    Halted(Halt),
    /// Control transferred to a VA with no block in this function -- a tail
    /// call, or a dispatch the CFG did not resolve.
    NoBlock(u64),
}

impl RunOutcome {
    /// A one-word label for a cost and coverage table.
    pub fn label(&self) -> &'static str {
        match self {
            RunOutcome::Returned => "returned",
            RunOutcome::BudgetExhausted => "budget",
            RunOutcome::Halted(_) => "halted",
            RunOutcome::NoBlock(_) => "no-block",
        }
    }
}

/// One value the run produced, before filtering and before normalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The VA of the instruction that produced it. Used only by the per-site
    /// cap; never part of a fingerprint, because an address is exactly the
    /// kind of fact two builds disagree about.
    pub site: u64,
    /// The value as the machine produced it, zero-extended into 64 bits.
    pub raw: u64,
    /// The width the machine produced it at. Normalisation sign-extends from
    /// here and then discards it.
    pub width: Width,
}

/// Everything one seed's run recorded.
#[derive(Debug, Clone)]
pub struct Harvest {
    pub observations: Vec<Observation>,
    /// Set `A` of vSim's Algorithm 1: every effective address the run used.
    pub addresses: BTreeSet<u64>,
    pub outcome: RunOutcome,
    /// Instructions retired.
    pub steps: u64,
}

/// How a block's instruction loop ended.
enum BlockExit {
    /// Fell off the end with no terminator.
    FellThrough,
    Jump(u64),
    Branch {
        target: u64,
        taken: bool,
    },
    Return,
}

/// The width to normalise a definition at, or 64 bits when the register file
/// cannot say (a lifter temporary carries no width; see `VReg::width`).
fn definition_width(machine: &Machine<Concrete>, register: &VReg) -> Width {
    machine.regs.width(register).unwrap_or(Width::W64)
}

/// Seed the register file for one run.
fn seed_registers(machine: &mut Machine<Concrete>, settings: ValueSettings, seed: u8) {
    for name in SEEDED_X86_64_REGISTERS {
        let role = settings.role_seeds.then_some(name);
        let value = u128::from(fresh_value(seed, role));
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys(name), value);
    }
    for name in ["rsp", "rbp"] {
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys(name), u128::from(STACK_BASE));
    }
}

/// Make `[address, address + size)` readable before the interpreter loads it.
///
/// Initialised image data wins -- vSim starts with read-only sections mapped --
/// and otherwise the slot becomes the seed's trial scalar, which is the
/// concrete stand-in for symbolising those bytes.
fn prefault(
    machine: &mut Machine<Concrete>,
    context: &ValueContext<'_>,
    address: u64,
    operand: &MemOp,
    fresh: u64,
) {
    if operand.size == 0 || machine.mem.is_initialized(address, operand.size) {
        return;
    }
    let word =
        (context.image_word)(address, operand.size, operand.endian).unwrap_or(u128::from(fresh));
    machine.mem.store(
        &mut machine.dom,
        address,
        &word,
        operand.size,
        operand.endian,
    );
}

/// Record set `A` for a memory operand, pre-faulting it when it is about to be
/// read. Returns nothing: a non-concretizing address is simply not recorded,
/// and the interpreter will halt on it a moment later.
fn note_memory(
    machine: &mut Machine<Concrete>,
    context: &ValueContext<'_>,
    operand: &MemOp,
    is_load: bool,
    fresh: u64,
    harvest: &mut Harvest,
) {
    let evaluated = machine.eval_addr(operand);
    let Some(address) = machine.dom.as_u64(&evaluated) else {
        return;
    };
    harvest.addresses.insert(address);
    if is_load {
        prefault(machine, context, address, operand, fresh);
    }
}

/// Record what one instruction produced: the value a store wrote, or the value
/// its definition now holds.
fn record_effect(
    machine: &mut Machine<Concrete>,
    op: &Op,
    site: u64,
    stored: Option<(u64, Width)>,
    harvest: &mut Harvest,
) {
    if let Some((raw, width)) = stored {
        harvest.observations.push(Observation { site, raw, width });
        return;
    }
    let Some(definition) = def_uses(op).0 else {
        return;
    };
    let width = definition_width(machine, &definition);
    let value = machine.regs.read(&mut machine.dom, &definition);
    if let Some(raw) = machine.dom.as_u64(&value) {
        harvest.observations.push(Observation { site, raw, width });
    }
}

/// Run one seed's bounded execution of `function`.
pub fn run_seed(function: &LlirFunction, context: &ValueContext<'_>, seed: u8) -> Harvest {
    let settings = context.settings;
    let fresh = fresh_value(seed, None);
    let mut machine = Machine::new(Concrete);
    seed_registers(&mut machine, settings, seed);

    let blocks: HashMap<u64, &LlirBlock> =
        function.blocks.iter().map(|b| (b.start_va, b)).collect();
    let mut budget = Budget::new(u64::from(settings.max_steps));
    let mut harvest = Harvest {
        observations: Vec::new(),
        addresses: BTreeSet::new(),
        outcome: RunOutcome::Returned,
        steps: 0,
    };

    let mut current = function.entry_va;
    let outcome = 'run: loop {
        let Some(block) = blocks.get(&current) else {
            break RunOutcome::NoBlock(current);
        };
        machine.pc = current;

        let mut index = 0usize;
        let exit = 'block: {
            while index < block.instrs.len() {
                if !budget.tick() {
                    break 'run RunOutcome::BudgetExhausted;
                }
                let instruction = &block.instrs[index];
                let op = &instruction.op;

                // An `Op::Undef` is a *definition* of an unmodelled value. The
                // interpreter poisons the register and halts on the first read,
                // which is right for an emulator and wrong here:
                // under-constrained execution wants a fresh value, not a stop.
                // Substituting one is the substitution the memory pre-fault
                // already makes, applied to a register.
                if let Op::Undef { dst, .. } = op {
                    let width = definition_width(&machine, dst);
                    let value = if width.bits() <= 1 {
                        u128::from(fresh & 1)
                    } else {
                        u128::from(fresh)
                    };
                    machine.regs.write(&mut machine.dom, dst, value);
                    index += 1;
                    continue;
                }

                // Pre-step: effective addresses (set A), and the value a store
                // is about to write, which cannot be read back afterwards.
                let mut stored: Option<(u64, Width)> = None;
                match op {
                    Op::Load { addr, .. } | Op::CondLoad { addr, .. } => {
                        note_memory(&mut machine, context, addr, true, fresh, &mut harvest);
                    }
                    Op::Store { addr, src } | Op::CondStore { addr, src, .. } => {
                        note_memory(&mut machine, context, addr, false, fresh, &mut harvest);
                        let width = Width::from_bytes(u16::from(addr.size));
                        let value = machine.read(src, width);
                        if let Some(raw) = machine.dom.as_u64(&value) {
                            stored = Some((raw, width));
                        }
                    }
                    _ => {}
                }

                let flow = machine.step(op);
                if !matches!(flow, Flow::Halt(_) | Flow::Call(_)) {
                    record_effect(&mut machine, op, instruction.va, stored, &mut harvest);
                }

                match flow {
                    Flow::Next => index += 1,
                    Flow::Call(target) => {
                        let callee = callee_name(context, op, target);
                        let sentinel = callee_sentinel(seed, &callee);
                        machine.regs.write(
                            &mut machine.dom,
                            &VReg::phys("rax"),
                            u128::from(sentinel),
                        );
                        harvest.observations.push(Observation {
                            site: instruction.va,
                            raw: sentinel,
                            width: Width::W64,
                        });
                        index += 1;
                    }
                    Flow::Jump(target) => break 'block BlockExit::Jump(target),
                    Flow::Branch { target, taken } => {
                        break 'block BlockExit::Branch { target, taken }
                    }
                    Flow::Return => break 'block BlockExit::Return,
                    Flow::Halt(halt) => break 'run RunOutcome::Halted(halt),
                }
            }
            BlockExit::FellThrough
        };

        match exit {
            // Blocks are contiguous, so falling off the end falls through --
            // exactly what `Machine::run_function` does.
            BlockExit::FellThrough => current = block.end_va,
            BlockExit::Jump(target) => current = target,
            BlockExit::Branch { target, taken } => {
                current = if taken { target } else { block.end_va };
            }
            BlockExit::Return => break RunOutcome::Returned,
        }
    };

    harvest.outcome = outcome;
    harvest.steps = budget.spent();
    harvest
}

/// What to key a call's sentinel on.
///
/// An external name is a stable interface: `memcpy` is `memcpy` in every build
/// of every version. An internal callee's address is not stable and its symbol
/// may not exist at all in a stripped binary, so it collapses to one token --
/// as does an indirect call, whose target this scheme does not try to resolve.
fn callee_name(context: &ValueContext<'_>, op: &Op, target: Option<u64>) -> String {
    if let Some(address) = target {
        if let Some(name) = context.external_names.get(&address) {
            return name.clone();
        }
    }
    match op {
        Op::Call {
            target: CallTarget::Direct(_),
            ..
        } => "internal".to_string(),
        _ => "indirect".to_string(),
    }
}
