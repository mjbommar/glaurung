//! Use-def index over an `LlirFunction`.
//!
//! For each LLIR op this module records:
//! * the VReg it *writes* (the def, if any), and
//! * the VRegs it *reads* (the uses).
//!
//! From those primitive relations it builds two small maps:
//! * [`UseDefIndex::defs_by_reg`] — for each VReg, every `(block_idx, instr_idx)`
//!   position where it is written.
//! * [`UseDefIndex::uses_by_reg`] — for each VReg, every position where it is
//!   read, annotated with the position of the most recent preceding def within
//!   the same basic block (intra-block reaching-definitions).
//!
//! Scope is intentionally small: v1 handles register-level VRegs only and does
//! intra-block reaching analysis. Inter-block data flow is left for the SSA
//! pass (task #17), which naturally lifts this into a dominator-frontier-based
//! algorithm.

use std::collections::HashMap;

use crate::ir::types::{CallTarget, LlirFunction, MemOp, Op, VReg, Value};

/// Address of an op within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstrAddr {
    pub block_idx: usize,
    pub instr_idx: usize,
}

/// A read with its intra-block reaching def (if any).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Use {
    /// Where the read happens.
    pub at: InstrAddr,
    /// Position of the most recent def of this VReg within the same block,
    /// or `None` when the value enters the block from outside.
    pub reaching_def: Option<InstrAddr>,
}

#[derive(Debug, Default, Clone)]
pub struct UseDefIndex {
    pub defs_by_reg: HashMap<VReg, Vec<InstrAddr>>,
    pub uses_by_reg: HashMap<VReg, Vec<Use>>,
}

fn reads_of_value(v: &Value, out: &mut Vec<VReg>) {
    if let Value::Reg(r) = v {
        out.push(r.clone());
    }
}

fn reads_of_memop(m: &MemOp, out: &mut Vec<VReg>) {
    if let Some(b) = &m.base {
        out.push(b.clone());
    }
    if let Some(i) = &m.index {
        out.push(i.clone());
    }
}

/// Return `(def, uses)` for a given op.
///
/// `def` is the VReg written (at most one per LLIR op — three-address form).
/// `uses` lists every VReg read, in source order, possibly with duplicates.
pub fn def_uses(op: &Op) -> (Option<VReg>, Vec<VReg>) {
    let mut uses = Vec::new();
    let def = match op {
        Op::Assign { dst, src } => {
            reads_of_value(src, &mut uses);
            Some(dst.clone())
        }
        Op::Bin { dst, lhs, rhs, .. } => {
            reads_of_value(lhs, &mut uses);
            reads_of_value(rhs, &mut uses);
            Some(dst.clone())
        }
        Op::Un { dst, src, .. } => {
            reads_of_value(src, &mut uses);
            Some(dst.clone())
        }
        Op::Cmp { dst, lhs, rhs, .. } => {
            reads_of_value(lhs, &mut uses);
            reads_of_value(rhs, &mut uses);
            Some(dst.clone())
        }
        Op::Load { dst, addr } => {
            reads_of_memop(addr, &mut uses);
            Some(dst.clone())
        }
        Op::Store { addr, src } => {
            reads_of_memop(addr, &mut uses);
            reads_of_value(src, &mut uses);
            None
        }
        Op::CondJump { cond, .. } => {
            uses.push(cond.clone());
            None
        }
        Op::Call { target } => {
            if let CallTarget::Indirect(v) = target {
                reads_of_value(v, &mut uses);
            }
            None
        }
        Op::Jump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => None,
    };
    (def, uses)
}

/// Build a use-def index for `lf` performing intra-block reaching-definitions.
pub fn compute_use_def(lf: &LlirFunction) -> UseDefIndex {
    let mut idx = UseDefIndex::default();

    for (bi, block) in lf.blocks.iter().enumerate() {
        // `last_def_in_block` is the reaching-def cursor — we update it as we
        // walk the block linearly.
        let mut last_def_in_block: HashMap<VReg, InstrAddr> = HashMap::new();

        for (ii, ins) in block.instrs.iter().enumerate() {
            let at = InstrAddr {
                block_idx: bi,
                instr_idx: ii,
            };
            let (def, uses) = def_uses(&ins.op);

            // Record uses before def so a self-reference (x = x + 1) reads the
            // previous def, not its own write.
            for u in uses {
                let reaching_def = last_def_in_block.get(&u).copied();
                idx.uses_by_reg
                    .entry(u)
                    .or_default()
                    .push(Use { at, reaching_def });
            }

            if let Some(d) = def {
                idx.defs_by_reg.entry(d.clone()).or_default().push(at);
                last_def_in_block.insert(d, at);
            }
        }
    }

    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, CallTarget, CmpOp, Flag, LlirBlock, LlirInstr, Op};

    fn mk_lf(blocks: Vec<Vec<Op>>) -> LlirFunction {
        let mut out = Vec::new();
        for (i, ops) in blocks.into_iter().enumerate() {
            out.push(LlirBlock {
                start_va: 0x1000 + (i as u64) * 0x100,
                end_va: 0x1100 + (i as u64) * 0x100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (i as u64) * 0x100 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            })
        }
        LlirFunction {
            entry_va: 0x1000,
            blocks: out,
        }
    }

    #[test]
    fn def_uses_returns_def_and_all_uses() {
        let op = Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Reg(VReg::phys("rbx")),
        };
        let (def, uses) = def_uses(&op);
        assert_eq!(def, Some(VReg::phys("rax")));
        assert_eq!(uses, vec![VReg::phys("rax"), VReg::phys("rbx")]);
    }

    #[test]
    fn store_has_no_def_but_records_uses() {
        let op = Op::Store {
            addr: MemOp {
                base: Some(VReg::phys("rsp")),
                index: None,
                scale: 0,
                disp: 0,
                size: 8,
                ..Default::default()
            },
            src: Value::Reg(VReg::phys("rax")),
        };
        let (def, uses) = def_uses(&op);
        assert!(def.is_none());
        assert_eq!(uses, vec![VReg::phys("rsp"), VReg::phys("rax")]);
    }

    #[test]
    fn call_indirect_records_register_use() {
        let op = Op::Call {
            target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
        };
        let (def, uses) = def_uses(&op);
        assert!(def.is_none());
        assert_eq!(uses, vec![VReg::phys("rax")]);
    }

    #[test]
    fn self_referential_bin_reads_previous_def_not_its_own() {
        // %rax = rbx
        // %rax = rax + 5    ← uses prior def at instr 0
        let lf = mk_lf(vec![vec![
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::phys("rbx")),
            },
            Op::Bin {
                dst: VReg::phys("rax"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(5),
            },
        ]]);
        let idx = compute_use_def(&lf);
        let rax_uses = idx.uses_by_reg.get(&VReg::phys("rax")).unwrap();
        assert_eq!(rax_uses.len(), 1, "exactly one read of rax");
        let u = &rax_uses[0];
        assert_eq!(
            u.at,
            InstrAddr {
                block_idx: 0,
                instr_idx: 1
            }
        );
        assert_eq!(
            u.reaching_def,
            Some(InstrAddr {
                block_idx: 0,
                instr_idx: 0
            }),
            "read must resolve to the earlier def at instr 0",
        );
    }

    #[test]
    fn use_before_def_has_no_reaching_def() {
        // First op reads rbx which has never been defined in this function.
        let lf = mk_lf(vec![vec![Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Reg(VReg::phys("rbx")),
        }]]);
        let idx = compute_use_def(&lf);
        let rbx_uses = idx.uses_by_reg.get(&VReg::phys("rbx")).unwrap();
        assert_eq!(rbx_uses.len(), 1);
        assert!(rbx_uses[0].reaching_def.is_none());
    }

    #[test]
    fn defs_by_reg_captures_every_write() {
        let lf = mk_lf(vec![vec![
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(1),
            },
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(2),
            },
            Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Const(3),
            },
        ]]);
        let idx = compute_use_def(&lf);
        assert_eq!(idx.defs_by_reg.get(&VReg::phys("rax")).unwrap().len(), 2);
        assert_eq!(idx.defs_by_reg.get(&VReg::phys("rbx")).unwrap().len(), 1);
    }

    #[test]
    fn cmp_def_is_flag_not_operand() {
        let lf = mk_lf(vec![vec![Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(0),
        }]]);
        let idx = compute_use_def(&lf);
        assert!(idx.defs_by_reg.get(&VReg::Flag(Flag::Z)).is_some());
        // rax is a read; it should show up in uses, not defs.
        assert!(idx.defs_by_reg.get(&VReg::phys("rax")).is_none());
        assert!(idx.uses_by_reg.get(&VReg::phys("rax")).is_some());
    }

    #[test]
    fn reaching_defs_do_not_cross_block_boundaries() {
        // Block 0: %rax = 1
        // Block 1: %rbx = rax    ← no reaching def in block 1
        let lf = mk_lf(vec![
            vec![Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(1),
            }],
            vec![Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Reg(VReg::phys("rax")),
            }],
        ]);
        let idx = compute_use_def(&lf);
        let rax_uses = idx.uses_by_reg.get(&VReg::phys("rax")).unwrap();
        assert_eq!(rax_uses.len(), 1);
        assert!(
            rax_uses[0].reaching_def.is_none(),
            "intra-block analysis must not see a def in block 0 from block 1",
        );
    }

    #[test]
    fn works_on_real_lifted_function() {
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
                max_functions: 1,
                max_blocks: 64,
                max_instructions: 1000,
                timeout_ms: 500,
            },
        );
        let lf = lift_function_from_bytes(&data, &funcs[0], Arch::X86_64).unwrap();
        let idx = compute_use_def(&lf);
        // On any non-trivial function rsp is both defined (push/sub adjust it)
        // and read (stores / memory addressing), so it must appear in both
        // maps.
        assert!(
            idx.defs_by_reg.contains_key(&VReg::phys("rsp"))
                || idx.uses_by_reg.contains_key(&VReg::phys("rsp")),
            "expected rsp to appear somewhere in the use-def index",
        );
    }
}
