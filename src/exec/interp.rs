//! The interpreter — one `step()`/`run_block()` written **once** over the
//! [`Domain`] trait. Instantiated with [`Concrete`](crate::exec::Concrete) it is
//! the emulator; instantiated with the (future) symbolic domain it is the
//! symbolic executor. See
//! `docs/design/execution-engine/02-architecture/value-domain-trait.md`.
//!
//! Phase-1 scope: registers, arithmetic/logic, width changes, select, memory
//! load/store, intra-block control flow, and multi-block `run_function` with a
//! budget. `Call`/`Return` surface as control [`Flow`]/[`Outcome`] for the caller
//! to drive (SimProcedures land in Phase 3); `Intrinsic` dispatches to a
//! registered [`HelperRegistry`] helper or halts; `Unknown` should not appear
//! after lifting (Phase-0 lowering).

use std::collections::HashMap;

use crate::exec::budget::Budget;
use crate::exec::domain::{BranchDecision, Domain};
use crate::exec::helpers::HelperRegistry;
use crate::exec::memory::Memory;
use crate::exec::simproc::SimProcRegistry;
use crate::exec::state::{RegArch, RegFile};
use crate::ir::types::{BinOp, CallTarget, LlirBlock, LlirFunction, MemOp, Op, VReg, Value, Width};

/// Why execution stopped without normal control flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    /// An `Op::Intrinsic` with no registered helper was reached.
    UnsupportedIntrinsic(String),
    /// A residual `Op::Unknown` was reached (should not happen post-lift).
    ResidualUnknown(String),
    /// A symbolic condition asked the concrete engine to fork (cannot happen).
    UnexpectedFork,
    /// A jump/call/load address could not be concretized.
    UnresolvedAddress,
    /// The instruction budget was exhausted.
    BudgetExhausted,
}

/// Why whole-function execution ([`Machine::run_function`]) stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Reached an `Op::Return`.
    Returned,
    /// Execution halted (unsupported intrinsic, residual unknown, …).
    Halted(Halt),
    /// The instruction budget was exhausted.
    BudgetExhausted,
    /// Control transferred to a VA with no corresponding block.
    NoBlock(u64),
    /// Reached a `Call`; Phase 1 has no call/SimProcedure handling yet
    /// (Phase 3), so the caller decides what to do. Carries the resolved
    /// target VA if known.
    CalledOut(Option<u64>),
}

/// The outcome of executing one op or a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    /// Continue with the next instruction (fall through).
    Next,
    /// Unconditional jump to a VA.
    Jump(u64),
    /// Conditional branch: `taken` selects the target vs. fall-through.
    Branch { target: u64, taken: bool },
    /// A call to a (possibly unresolved) target VA.
    Call(Option<u64>),
    /// Function return.
    Return,
    /// Execution halted.
    Halt(Halt),
}

/// A machine: value domain + register file + memory + program counter.
pub struct Machine<D: Domain> {
    pub dom: D,
    pub regs: RegFile<D>,
    pub mem: Memory<D>,
    pub pc: u64,
    /// Registered intrinsic helpers (default: x86-64 set).
    pub helpers: HelperRegistry<D>,
    /// Registered call summaries (SimProcedures), keyed by target VA.
    pub simprocs: SimProcRegistry<D>,
    /// Virtual timestamp counter backing `rdtsc` (deterministic — no host time).
    tsc: u64,
}

impl<D: Domain + Default> Default for Machine<D> {
    fn default() -> Self {
        Self::new(D::default())
    }
}

// A machine clones when its domain does (e.g. `Symbolic`/`Concrete`) — the basis
// for forking symbolic states. The register file, memory, and helper registry
// are cloneable for any domain.
impl<D: Domain + Clone> Clone for Machine<D> {
    fn clone(&self) -> Self {
        Self {
            dom: self.dom.clone(),
            regs: self.regs.clone(),
            mem: self.mem.clone(),
            pc: self.pc,
            helpers: self.helpers.clone(),
            simprocs: self.simprocs.clone(),
            tsc: self.tsc,
        }
    }
}

fn value_width(v: &Value) -> Option<Width> {
    match v {
        Value::Reg(r) => r.width(),
        Value::Const(_) => None,
        Value::Addr(_) => Some(Width::W64),
    }
}

/// Operation width: prefer the destination's width, else the first operand with
/// a known width, else 64 bits. (Resolves the Q1 "temp width" gap pragmatically;
/// see STATUS.md.)
fn op_width(dst: &VReg, operands: &[&Value]) -> Width {
    dst.width()
        .or_else(|| operands.iter().find_map(|v| value_width(v)))
        .unwrap_or(Width::W64)
}

impl<D: Domain> Machine<D> {
    pub fn new(dom: D) -> Self {
        Self::new_with_arch(dom, RegArch::X86_64)
    }

    /// A machine with a specific ISA register layout + default helper set.
    pub fn new_with_arch(dom: D, arch: RegArch) -> Self {
        let helpers = match arch {
            RegArch::X86_64 => HelperRegistry::default_x86_64(),
            RegArch::AArch64 => HelperRegistry::default_aarch64(),
        };
        Self {
            dom,
            regs: RegFile::with_arch(arch),
            mem: Memory::new(),
            pc: 0,
            helpers,
            simprocs: SimProcRegistry::empty(),
            tsc: 0,
        }
    }

    /// Advance and return the virtual timestamp counter (deterministic; used by
    /// `rdtsc`). Each read bumps it by a fixed stride.
    pub fn next_tsc(&mut self) -> u64 {
        self.tsc = self.tsc.wrapping_add(100);
        self.tsc
    }

    /// Compute a memory operand's effective address as a domain value
    /// (`base + index*scale + disp`). Unlike [`Machine::effective_addr`] (which
    /// concretizes to a `u64`), this keeps the address symbolic when the domain
    /// is — used by the symbolic explorer to concretize symbolic addresses.
    pub(crate) fn eval_addr(&mut self, mo: &MemOp) -> D::Val {
        let w = Width::W64;
        let mut acc = self.dom.constant(w, mo.disp as u128);
        if let Some(b) = &mo.base {
            let bv = self.regs.read(&mut self.dom, b);
            acc = self.dom.binop(BinOp::Add, &acc, &bv, w);
        }
        if let Some(i) = &mo.index {
            let iv = self.regs.read(&mut self.dom, i);
            let scaled = if mo.scale > 1 {
                let s = self.dom.constant(w, mo.scale as u128);
                self.dom.binop(BinOp::Mul, &iv, &s, w)
            } else {
                iv
            };
            acc = self.dom.binop(BinOp::Add, &acc, &scaled, w);
        }
        acc
    }

    /// Read a value at the given width.
    pub(crate) fn read(&mut self, v: &Value, w: Width) -> D::Val {
        match v {
            Value::Reg(r) => self.regs.read(&mut self.dom, r),
            // i64 immediate: `as u128` sign-extends to 128 bits, then the domain
            // reduces it to `w` (so a -1 imm becomes all-ones at width `w`).
            Value::Const(c) => self.dom.constant(w, *c as u128),
            Value::Addr(a) => self.dom.constant(Width::W64, *a as u128),
        }
    }

    /// Effective address of a memory operand: base + index*scale + disp.
    /// Segment overrides are ignored for now (Phase-later: fs/gs bases).
    fn effective_addr(&mut self, m: &MemOp) -> Option<u64> {
        let mut ea: u64 = 0;
        if let Some(b) = &m.base {
            let v = self.regs.read(&mut self.dom, b);
            ea = ea.wrapping_add(self.dom.as_u64(&v)?);
        }
        if let Some(i) = &m.index {
            let v = self.regs.read(&mut self.dom, i);
            let idx = self.dom.as_u64(&v)?;
            ea = ea.wrapping_add(idx.wrapping_mul(m.scale.max(1) as u64));
        }
        Some(ea.wrapping_add(m.disp as u64))
    }

    /// Execute one op, returning the resulting control [`Flow`].
    pub fn step(&mut self, op: &Op) -> Flow {
        match op {
            Op::Nop => Flow::Next,
            Op::Assign { dst, src } => {
                let w = op_width(dst, &[src]);
                let v = self.read(src, w);
                self.regs.write(&mut self.dom, dst, v);
                Flow::Next
            }
            Op::CondAssign { dst, cond, src } => {
                let c = self.regs.read(&mut self.dom, cond);
                if let BranchDecision::Taken = self.dom.as_branch(&c) {
                    let w = op_width(dst, &[src]);
                    let v = self.read(src, w);
                    self.regs.write(&mut self.dom, dst, v);
                }
                Flow::Next
            }
            Op::Bin { dst, op, lhs, rhs } => {
                let w = op_width(dst, &[lhs, rhs]);
                let a = self.read(lhs, w);
                let b = self.read(rhs, w);
                let r = self.dom.binop(*op, &a, &b, w);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Un { dst, op, src } => {
                let w = op_width(dst, &[src]);
                let a = self.read(src, w);
                let r = self.dom.unop(*op, &a, w);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Cmp { dst, op, lhs, rhs } => {
                // Comparison width comes from the operands (dst is a 1-bit flag).
                let w = value_width(lhs)
                    .or_else(|| value_width(rhs))
                    .unwrap_or(Width::W64);
                let a = self.read(lhs, w);
                let b = self.read(rhs, w);
                let r = self.dom.cmp(*op, &a, &b, w);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::ZExt { dst, src, from, to } => {
                let v = self.read(src, *from);
                let r = self.dom.zext(&v, *from, *to);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::SExt { dst, src, from, to } => {
                let v = self.read(src, *from);
                let r = self.dom.sext(&v, *from, *to);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Trunc { dst, src, from, to } => {
                let v = self.read(src, *from);
                let r = self.dom.trunc(&v, *to);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Extract { dst, src, hi, lo } => {
                let w = value_width(src).unwrap_or(Width(*hi));
                let v = self.read(src, w);
                let r = self.dom.extract(&v, *hi, *lo);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Concat { dst, hi, lo } => {
                let hw = value_width(hi).unwrap_or(Width::W8);
                let lw = value_width(lo).unwrap_or(Width::W8);
                let h = self.read(hi, hw);
                let l = self.read(lo, lw);
                let r = self.dom.concat(&h, &l, hw, lw);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Ite {
                dst,
                cond,
                t,
                e,
                width,
            } => {
                let c = self.regs.read(&mut self.dom, cond);
                let tv = self.read(t, *width);
                let ev = self.read(e, *width);
                let r = self.dom.ite(&c, &tv, &ev, *width);
                self.regs.write(&mut self.dom, dst, r);
                Flow::Next
            }
            Op::Load { dst, addr } => {
                let Some(ea) = self.effective_addr(addr) else {
                    return Flow::Halt(Halt::UnresolvedAddress);
                };
                let v = self.mem.load(&mut self.dom, ea, addr.size, addr.endian);
                self.regs.write(&mut self.dom, dst, v);
                Flow::Next
            }
            Op::Store { addr, src } => {
                let Some(ea) = self.effective_addr(addr) else {
                    return Flow::Halt(Halt::UnresolvedAddress);
                };
                let w = Width::from_bytes(addr.size as u16);
                let v = self.read(src, w);
                self.mem
                    .store(&mut self.dom, ea, &v, addr.size, addr.endian);
                Flow::Next
            }
            Op::Jump { target } => Flow::Jump(*target),
            Op::CondJump {
                cond,
                target,
                inverted,
            } => {
                let c = self.regs.read(&mut self.dom, cond);
                match self.dom.as_branch(&c) {
                    BranchDecision::Taken => Flow::Branch {
                        target: *target,
                        taken: !*inverted,
                    },
                    BranchDecision::NotTaken => Flow::Branch {
                        target: *target,
                        taken: *inverted,
                    },
                    BranchDecision::Fork => Flow::Halt(Halt::UnexpectedFork),
                }
            }
            Op::Call { target } => {
                let resolved = match target {
                    CallTarget::Direct(a) => Some(*a),
                    CallTarget::Indirect(v) => {
                        let val = self.read(v, Width::W64);
                        self.dom.as_u64(&val)
                    }
                };
                // A modeled call (SimProcedure) is replaced by its summary and
                // execution continues; an unmodeled call surfaces to the caller.
                if let Some(va) = resolved {
                    if let Some(sp) = self.simprocs.get(va) {
                        return match sp(self) {
                            Ok(()) => Flow::Next,
                            Err(halt) => Flow::Halt(halt),
                        };
                    }
                }
                Flow::Call(resolved)
            }
            Op::Return => Flow::Return,
            Op::Intrinsic {
                name, ins, outs, ..
            } => match self.helpers.get(name) {
                Some(helper) => match helper(self, ins, outs) {
                    Ok(()) => Flow::Next,
                    Err(halt) => Flow::Halt(halt),
                },
                None => Flow::Halt(Halt::UnsupportedIntrinsic(name.clone())),
            },
            Op::Unknown { mnemonic } => Flow::Halt(Halt::ResidualUnknown(mnemonic.clone())),
        }
    }

    /// Run every instruction in `block` in order, stopping at the first op that
    /// produces a non-`Next` flow (a terminator or a halt). If the block falls
    /// off the end without a terminator, returns [`Flow::Next`].
    pub fn run_block(&mut self, block: &LlirBlock) -> Flow {
        for ins in &block.instrs {
            match self.step(&ins.op) {
                Flow::Next => continue,
                other => return other,
            }
        }
        Flow::Next
    }

    /// Execute an [`LlirFunction`] from its entry, following intra-function
    /// control flow until it returns, halts, calls out, runs off the CFG, or
    /// exhausts `budget`. Blocks are contiguous (a block's `end_va` is the start
    /// of its fall-through successor), which is how taken/not-taken edges and
    /// straight-line fall-through are resolved.
    pub fn run_function(&mut self, lf: &LlirFunction, budget: &mut Budget) -> Outcome {
        let blocks: HashMap<u64, &LlirBlock> = lf.blocks.iter().map(|b| (b.start_va, b)).collect();
        let mut cur = lf.entry_va;
        loop {
            let Some(block) = blocks.get(&cur) else {
                return Outcome::NoBlock(cur);
            };
            self.pc = cur;

            let mut flow = Flow::Next;
            for ins in &block.instrs {
                if !budget.tick() {
                    return Outcome::BudgetExhausted;
                }
                flow = self.step(&ins.op);
                if !matches!(flow, Flow::Next) {
                    break;
                }
            }

            match flow {
                // Fell off the end with no terminator → fall through.
                Flow::Next => cur = block.end_va,
                Flow::Jump(t) => cur = t,
                Flow::Branch { target, taken } => {
                    cur = if taken { target } else { block.end_va };
                }
                Flow::Call(t) => return Outcome::CalledOut(t),
                Flow::Return => return Outcome::Returned,
                Flow::Halt(h) => return Outcome::Halted(h),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::concrete::Concrete;
    use crate::ir::types::{BinOp, CmpOp, Flag, LlirInstr};

    fn block(ops: Vec<Op>) -> LlirBlock {
        LlirBlock {
            start_va: 0x1000,
            end_va: 0x1000 + ops.len() as u64 * 4,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(i, op)| LlirInstr {
                    va: 0x1000 + i as u64 * 4,
                    op,
                })
                .collect(),
            succs: vec![],
        }
    }

    fn machine() -> Machine<Concrete> {
        Machine::new(Concrete)
    }

    #[test]
    fn prototype_sequence_through_interpreter() {
        // rax = 0xff; ebx = rax + 1 (32-bit); zf = (ebx == 0x100)
        let mut m = machine();
        let flow = m.run_block(&block(vec![
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(0xff),
            },
            Op::Bin {
                dst: VReg::phys("ebx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(1),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::phys("ebx")),
                rhs: Value::Const(0x100),
            },
        ]));
        assert_eq!(flow, Flow::Next);
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("ebx")), 0x100);
        assert_eq!(m.regs.read(&mut m.dom, &VReg::Flag(Flag::Z)), 1);
        // writing ebx must have zeroed the upper half of rbx
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rbx")), 0x100);
    }

    #[test]
    fn conditional_branch_taken_and_inverted() {
        // zf set, JE (not inverted) → taken
        let mut m = machine();
        let one = m.dom.constant(Width::W1, 1);
        m.regs.write(&mut m.dom, &VReg::Flag(Flag::Z), one);
        let f = m.step(&Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target: 0x2000,
            inverted: false,
        });
        assert_eq!(
            f,
            Flow::Branch {
                target: 0x2000,
                taken: true
            }
        );
        // JNE (inverted) on zf=1 → not taken
        let f2 = m.step(&Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target: 0x2000,
            inverted: true,
        });
        assert_eq!(
            f2,
            Flow::Branch {
                target: 0x2000,
                taken: false
            }
        );
    }

    #[test]
    fn memory_store_load_round_trip_via_ops() {
        // [rsp-8] = rax (64-bit), then rcx = [rsp-8]
        let mut m = machine();
        let rsp = m.dom.constant(Width::W64, 0x7000);
        m.regs.write(&mut m.dom, &VReg::phys("rsp"), rsp);
        let rax = m.dom.constant(Width::W64, 0xcafe_f00d_1234_5678);
        m.regs.write(&mut m.dom, &VReg::phys("rax"), rax);
        let store = Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 1, -8, 8),
            src: Value::Reg(VReg::phys("rax")),
        };
        let load = Op::Load {
            dst: VReg::phys("rcx"),
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 1, -8, 8),
        };
        assert_eq!(m.step(&store), Flow::Next);
        assert_eq!(m.step(&load), Flow::Next);
        assert_eq!(
            m.regs.read(&mut m.dom, &VReg::phys("rcx")),
            0xcafe_f00d_1234_5678
        );
    }

    #[test]
    fn return_and_intrinsic_flows() {
        let mut m = machine();
        assert_eq!(m.step(&Op::Return), Flow::Return);
        // An intrinsic with no registered helper halts cleanly.
        assert_eq!(
            m.step(&Op::opaque("vfmadd231ps")),
            Flow::Halt(Halt::UnsupportedIntrinsic("vfmadd231ps".into()))
        );
    }

    #[test]
    fn direct_call_resolves_target() {
        let mut m = machine();
        assert_eq!(
            m.step(&Op::Call {
                target: CallTarget::Direct(0x4040),
            }),
            Flow::Call(Some(0x4040))
        );
    }

    fn func(blocks: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        let mut out = Vec::new();
        for (start, ops, succs) in blocks {
            let end = start + ops.len() as u64 * 4;
            out.push(LlirBlock {
                start_va: start,
                end_va: end,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(i, op)| LlirInstr {
                        va: start + i as u64 * 4,
                        op,
                    })
                    .collect(),
                succs,
            });
        }
        let entry = out[0].start_va;
        LlirFunction {
            entry_va: entry,
            blocks: out,
        }
    }

    #[test]
    fn run_function_executes_a_countdown_loop() {
        // sum = 0; i = 3;
        // loop:  sum = sum + i;  i = i - 1;  cmp i,0;  jne loop
        // end:   return
        // Blocks are laid out contiguously (4 bytes/op) so fall-through == end_va.
        // B0 @0x1000: sum=0; i=3                       (2 ops → end 0x1008)
        // B1 @0x1008: sum=sum+i; i=i-1; cmp i,0; jne 0x1008  (4 ops → end 0x1018)
        // B2 @0x1018: ret
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Assign {
                        dst: VReg::phys("rax"), // sum
                        src: Value::Const(0),
                    },
                    Op::Assign {
                        dst: VReg::phys("rcx"), // i
                        src: Value::Const(3),
                    },
                ],
                vec![0x1008],
            ),
            (
                0x1008,
                vec![
                    Op::Bin {
                        dst: VReg::phys("rax"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Reg(VReg::phys("rcx")),
                    },
                    Op::Bin {
                        dst: VReg::phys("rcx"),
                        op: BinOp::Sub,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Const(1),
                    },
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Const(0),
                    },
                    // jne loop: take the branch when Z is NOT set (inverted).
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1008,
                        inverted: true,
                    },
                ],
                vec![0x1008, 0x1018],
            ),
            (0x1018, vec![Op::Return], vec![]),
        ]);

        let mut m = machine();
        let mut budget = Budget::new(1000);
        let outcome = m.run_function(&lf, &mut budget);
        assert_eq!(outcome, Outcome::Returned);
        // 3 + 2 + 1 = 6
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rax")), 6);
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rcx")), 0);
    }

    #[test]
    fn run_function_budget_bounds_infinite_loop() {
        // B0 @0x2000: jmp 0x2000  (tight infinite loop)
        let lf = func(vec![(
            0x2000,
            vec![Op::Jump { target: 0x2000 }],
            vec![0x2000],
        )]);
        let mut m = machine();
        let mut budget = Budget::new(50);
        assert_eq!(m.run_function(&lf, &mut budget), Outcome::BudgetExhausted);
        assert!(budget.exhausted());
    }

    #[test]
    fn run_function_stops_at_call_and_return() {
        let called = func(vec![(
            0x3000,
            vec![Op::Call {
                target: CallTarget::Direct(0x9000),
            }],
            vec![],
        )]);
        let mut m = machine();
        let mut b = Budget::new(100);
        assert_eq!(
            m.run_function(&called, &mut b),
            Outcome::CalledOut(Some(0x9000))
        );

        let returns = func(vec![(0x3000, vec![Op::Return], vec![])]);
        let mut b2 = Budget::new(100);
        assert_eq!(m.run_function(&returns, &mut b2), Outcome::Returned);
    }

    /// Lift real x86-64 machine-code bytes and execute them as one block.
    /// Returns the machine and the terminating flow.
    fn run_x86_bytes(bytes: &[u8], bits: u32) -> (Machine<Concrete>, Flow) {
        use crate::ir::lift_x86;
        let instrs = lift_x86::lift_bytes(bytes, 0x1000, bits);
        let blk = LlirBlock {
            start_va: 0x1000,
            end_va: 0x1000 + bytes.len() as u64,
            instrs,
            succs: vec![],
        };
        let mut m = machine();
        let flow = m.run_block(&blk);
        (m, flow)
    }

    // Self-contained differential validation: real instruction encodings with
    // hand-computed expected register state, run through decode→lift→execute.
    // (Substitutes for the Unicorn oracle where Unicorn's C build is unavailable;
    // see docs/design/execution-engine/04-testing/differential-oracle.md.)

    #[test]
    fn validate_x86_32bit_arithmetic() {
        // mov eax,10 ; mov ecx,3 ; add eax,ecx ; sub eax,1   → eax = 12
        let bytes = [
            0xB8, 0x0A, 0x00, 0x00, 0x00, // mov eax, 10
            0xB9, 0x03, 0x00, 0x00, 0x00, // mov ecx, 3
            0x01, 0xC8, // add eax, ecx
            0x83, 0xE8, 0x01, // sub eax, 1
        ];
        let (mut m, flow) = run_x86_bytes(&bytes, 64);
        assert_eq!(flow, Flow::Next, "block should run to the end");
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rax")), 12);
        // 32-bit write zero-extends → full rax is exactly 12.
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("eax")), 12);
    }

    #[test]
    fn validate_x86_xor_self_zeroes() {
        // mov eax, 0xdeadbeef ; xor eax, eax  → rax = 0
        let bytes = [
            0xB8, 0xEF, 0xBE, 0xAD, 0xDE, // mov eax, 0xdeadbeef
            0x31, 0xC0, // xor eax, eax
        ];
        let (mut m, flow) = run_x86_bytes(&bytes, 64);
        assert_eq!(flow, Flow::Next);
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("rax")), 0);
    }

    #[test]
    fn validate_x86_8bit_wraparound() {
        // mov al, 0xff ; add al, 1   → al = 0x00 (8-bit wrap)
        let bytes = [
            0xB0, 0xFF, // mov al, 0xff
            0x04, 0x01, // add al, 1
        ];
        let (mut m, flow) = run_x86_bytes(&bytes, 64);
        assert_eq!(flow, Flow::Next);
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("al")), 0x00);
    }

    #[test]
    fn executes_a_real_lifted_function_end_to_end() {
        // End-to-end: discover + lift a real x86-64 function and run it through
        // the interpreter. We don't assert a specific result (no OS/calls/helpers
        // yet), only that the emulator makes progress and stops *gracefully* at a
        // recognised terminal state — i.e. it executes real lifted LLIR without
        // panicking. This is the Phase-1 "it runs on real binaries" milestone.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;

        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 16,
                max_blocks: 256,
                max_instructions: 20_000,
                timeout_ms: 2000,
            },
        );

        let mut ran = 0usize;
        for f in &funcs {
            let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) else {
                continue;
            };
            let mut m = machine();
            // Give it a sane, aligned stack pointer so push/pop/[rsp+d] land in
            // plausible (sparse, zero-filled) memory.
            let sp = m.dom.constant(Width::W64, 0x7fff_ffff_0000);
            m.regs.write(&mut m.dom, &VReg::phys("rsp"), sp);

            let mut budget = Budget::new(100_000);
            let outcome = m.run_function(&lf, &mut budget);

            // Any of these is a graceful stop; the point is no panic and progress.
            assert!(
                matches!(
                    outcome,
                    Outcome::Returned
                        | Outcome::CalledOut(_)
                        | Outcome::Halted(_)
                        | Outcome::BudgetExhausted
                        | Outcome::NoBlock(_)
                ),
                "function @ {:#x} ended unexpectedly: {:?}",
                f.entry_point.value,
                outcome
            );
            assert!(
                budget.spent() > 0,
                "function @ {:#x} executed no instructions",
                f.entry_point.value
            );
            ran += 1;
        }
        assert!(ran > 0, "expected to lift+run at least one real function");
    }

    #[test]
    fn executes_a_real_lifted_arm64_function_end_to_end() {
        // Same as the x86-64 end-to-end test, but ARM64: discover + lift a real
        // AArch64 function and run it via an AArch64 machine. Asserts graceful
        // progress (no panic), proving the arch-agnostic interpreter + ARM64
        // register layout execute real lifted LLIR.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::exec::state::RegArch;
        use crate::ir::lift_function::lift_function_from_bytes;

        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 16,
                max_blocks: 256,
                max_instructions: 20_000,
                timeout_ms: 2000,
            },
        );

        let mut ran = 0usize;
        for f in &funcs {
            let Some(lf) = lift_function_from_bytes(&data, f, Arch::AArch64) else {
                continue;
            };
            let mut m = Machine::new_with_arch(Concrete, RegArch::AArch64);
            let sp = m.dom.constant(Width::W64, 0x7fff_ffff_0000);
            m.regs.write(&mut m.dom, &VReg::phys("sp"), sp);

            let mut budget = Budget::new(100_000);
            let outcome = m.run_function(&lf, &mut budget);
            assert!(
                matches!(
                    outcome,
                    Outcome::Returned
                        | Outcome::CalledOut(_)
                        | Outcome::Halted(_)
                        | Outcome::BudgetExhausted
                        | Outcome::NoBlock(_)
                ),
                "arm64 fn @ {:#x} ended unexpectedly: {:?}",
                f.entry_point.value,
                outcome
            );
            assert!(budget.spent() > 0);
            ran += 1;
        }
        assert!(ran > 0, "expected to lift+run at least one arm64 function");
    }

    #[test]
    fn sub_register_arithmetic_8bit() {
        // al = 0xff; al = al + 2  → wraps to 0x01 at 8 bits, upper bits of rax preserved
        let mut m = machine();
        let init = m.dom.constant(Width::W64, 0xaabbccdd_00000000);
        m.regs.write(&mut m.dom, &VReg::phys("rax"), init);
        m.step(&Op::Assign {
            dst: VReg::phys("al"),
            src: Value::Const(0xff),
        });
        m.step(&Op::Bin {
            dst: VReg::phys("al"),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("al")),
            rhs: Value::Const(2),
        });
        assert_eq!(m.regs.read(&mut m.dom, &VReg::phys("al")), 0x01);
        // upper bits preserved (al write doesn't disturb them)
        assert_eq!(
            m.regs.read(&mut m.dom, &VReg::phys("rax")),
            0xaabbccdd_00000001
        );
    }
}
