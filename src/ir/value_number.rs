//! SSA value numbering for the LLIR (Stage 2 of the value-model refactor —
//! docs/design/decompiler-refactors.md #1).
//!
//! Naming and typing key on the *physical register*, so a register reused for
//! two purposes (an argument spilled then reused as a scratch integer; the
//! return register used as an address-computation scratch and then as the
//! result) is one variable with one type — the source of the int↔pointer
//! conflicts and of the incorrect address folding an AST rewrite cannot avoid.
//!
//! This pass rewrites each physical register occurrence to a **value-tagged**
//! name `reg#version` using the already-computed [`SsaInfo`], so every SSA value
//! becomes a distinct variable. Version 0 is the implicit entry-def (a live-in
//! parameter), which stays the bare register so downstream argument/return
//! naming is unchanged; explicit definitions (version ≥ 1) and the uses that
//! read them get the tagged name. Temporaries and flags are left alone.
//!
//! This pass is pure (returns a rewritten copy) and is validated in isolation
//! before being threaded into the lowering pipeline.

use std::collections::HashSet;

use crate::ir::call_args::CallConv;
use crate::ir::types::{LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

/// The registers that carry a return value under `cc` (all width sub-names).
fn return_reg_names(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        CallConv::Arm => &["r0"],
    }
}

/// `(register, version)` pairs kept bare despite version ≥ 1 — the value a
/// return register holds at the end of the function (its highest version), so
/// downstream naming still maps it to `ret` rather than a scratch `varN`.
type KeepBare = HashSet<(String, u32)>;

/// Stack/frame base registers must keep their bare names so stack-slot
/// promotion (which pattern-matches `rbp`/`rsp`-relative addresses) still fires.
fn is_structural_reg(n: &str) -> bool {
    matches!(
        n,
        "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp" | "x29" | "w29" | "fp"
    )
}

/// The value-tagged name of a physical register at a given SSA version.
fn tag_phys(v: &mut VReg, version: u32, keep: &KeepBare) {
    if version == 0 {
        return; // entry-def / live-in — keep the bare register
    }
    if let VReg::Phys(n) = v {
        if is_structural_reg(n) || keep.contains(&(n.clone(), version)) {
            return;
        }
        *n = format!("{}#{}", n, version);
    }
}

/// Rewrite a `Value`'s register (if any) to the version at `use_vers[*ui]`,
/// advancing the use cursor exactly as [`def_uses`] enumerated it.
fn tag_value(v: &mut Value, use_vers: &[u32], ui: &mut usize, keep: &KeepBare) {
    if let Value::Reg(r) = v {
        if let Some(&ver) = use_vers.get(*ui) {
            tag_phys(r, ver, keep);
        }
        *ui += 1;
    }
}

fn tag_memop_uses(m: &mut crate::ir::types::MemOp, use_vers: &[u32], ui: &mut usize, keep: &KeepBare) {
    if let Some(b) = &mut m.base {
        if let Some(&ver) = use_vers.get(*ui) {
            tag_phys(b, ver, keep);
        }
        *ui += 1;
    }
    if let Some(idx) = &mut m.index {
        if let Some(&ver) = use_vers.get(*ui) {
            tag_phys(idx, ver, keep);
        }
        *ui += 1;
    }
}

/// Apply the def version and the ordered use versions to one op's registers.
/// The use order mirrors `use_def::def_uses` exactly (memory base before index,
/// operands left-to-right), so the SSA `use_versions` line up by index.
fn tag_op(op: &mut Op, def_ver: u32, use_vers: &[u32], keep: &KeepBare) {
    let mut ui = 0usize;
    match op {
        Op::Assign { dst, src } => {
            tag_value(src, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::CondAssign { dst, cond, src } => {
            // def_uses order: cond, then src.
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, keep);
            }
            ui = 1;
            tag_value(src, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Bin { dst, lhs, rhs, .. } => {
            tag_value(lhs, use_vers, &mut ui, keep);
            tag_value(rhs, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Un { dst, src, .. } => {
            tag_value(src, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Cmp { dst, lhs, rhs, .. } => {
            tag_value(lhs, use_vers, &mut ui, keep);
            tag_value(rhs, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Load { dst, addr } => {
            tag_memop_uses(addr, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Store { addr, src } => {
            tag_memop_uses(addr, use_vers, &mut ui, keep);
            tag_value(src, use_vers, &mut ui, keep);
        }
        Op::CondJump { cond, .. } => {
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, keep);
            }
        }
        Op::Call {
            target: crate::ir::types::CallTarget::Indirect(v),
        } => {
            tag_value(v, use_vers, &mut ui, keep);
        }
        Op::ZExt { dst, src, .. }
        | Op::SExt { dst, src, .. }
        | Op::Trunc { dst, src, .. }
        | Op::Extract { dst, src, .. } => {
            tag_value(src, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Concat { dst, hi, lo } => {
            tag_value(hi, use_vers, &mut ui, keep);
            tag_value(lo, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        Op::Ite { dst, cond, t, e, .. } => {
            // def_uses order: cond, then t, then e.
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, keep); // a flag in practice — no-op
            }
            ui = 1;
            tag_value(t, use_vers, &mut ui, keep);
            tag_value(e, use_vers, &mut ui, keep);
            tag_phys(dst, def_ver, keep);
        }
        // Multi-output intrinsics (`cpuid`, ...) don't fit the single-def SSA
        // model cleanly, so leave them untagged for now; a function that uses one
        // must be excluded before this pass is wired into lowering.
        Op::Intrinsic { .. }
        | Op::Jump { .. }
        | Op::Return
        | Op::Nop
        | Op::Unknown { .. }
        | Op::Call { .. } => {}
    }
}

/// Return a copy of `lf` with every physical register occurrence rewritten to
/// its SSA-value-tagged name. `cc` identifies the return registers whose final
/// (returned) value is kept bare so it still names `ret`.
pub fn value_number(lf: &LlirFunction, ssa: &crate::ir::ssa::SsaInfo, cc: CallConv) -> LlirFunction {
    let ret_names = return_reg_names(cc);
    // Keep the highest-versioned definition of each return register bare — at
    // `-O0` that is the value moved into the ABI return slot just before `ret`,
    // while lower versions are scratch reuse of the same register.
    let mut max_ret: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (bi, block) in lf.blocks.iter().enumerate() {
        for (ii, ins) in block.instrs.iter().enumerate() {
            if let (Some(VReg::Phys(n)), _) = def_uses(&ins.op) {
                if ret_names.contains(&n.as_str()) {
                    let v = ssa
                        .def_versions
                        .get(&InstrAddr {
                            block_idx: bi,
                            instr_idx: ii,
                        })
                        .copied()
                        .unwrap_or(0);
                    max_ret
                        .entry(n)
                        .and_modify(|m| *m = (*m).max(v))
                        .or_insert(v);
                }
            }
        }
    }
    let keep: KeepBare = max_ret.into_iter().collect();

    let mut out = lf.clone();
    for (bi, block) in out.blocks.iter_mut().enumerate() {
        for (ii, ins) in block.instrs.iter_mut().enumerate() {
            let addr = InstrAddr {
                block_idx: bi,
                instr_idx: ii,
            };
            let def_ver = ssa.def_versions.get(&addr).copied().unwrap_or(0);
            let (_, uses) = def_uses(&ins.op);
            let use_vers: Vec<u32> = (0..uses.len())
                .map(|k| ssa.use_versions.get(&(addr, k)).copied().unwrap_or(0))
                .collect();
            tag_op(&mut ins.op, def_ver, &use_vers, &keep);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

    fn mk(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn distinct_defs_of_a_register_get_distinct_tags() {
        // rbx = 1 ; rbx = 2 ; rcx = rbx  -> rbx#1, rbx#2, rcx#1 = rbx#2
        // (rbx is not a return register, so no version is kept bare here.)
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Const(1),
            },
            Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Const(2),
            },
            Op::Assign {
                dst: VReg::phys("rcx"),
                src: Value::Reg(VReg::phys("rbx")),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        let ops = &out.blocks[0].instrs;
        assert_eq!(ops[0].op, Op::Assign { dst: VReg::phys("rbx#1"), src: Value::Const(1) });
        assert_eq!(ops[1].op, Op::Assign { dst: VReg::phys("rbx#2"), src: Value::Const(2) });
        assert_eq!(
            ops[2].op,
            Op::Assign { dst: VReg::phys("rcx#1"), src: Value::Reg(VReg::phys("rbx#2")) }
        );
    }

    #[test]
    fn live_in_use_keeps_bare_register() {
        // rbx = rdi ; rdi = 5   -> rbx#1 = rdi (v0, bare) ; rdi#1 = 5
        // The parameter read (live-in rdi) stays bare; the reassignment is a new
        // distinct value.
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Assign {
                dst: VReg::phys("rdi"),
                src: Value::Const(5),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        let ops = &out.blocks[0].instrs;
        assert_eq!(
            ops[0].op,
            Op::Assign {
                dst: VReg::phys("rbx#1"),
                src: Value::Reg(VReg::phys("rdi")) // bare: the live-in parameter
            }
        );
        assert_eq!(
            ops[1].op,
            Op::Assign {
                dst: VReg::phys("rdi#1"),
                src: Value::Const(5)
            }
        );
    }

    #[test]
    fn address_chain_reuse_becomes_distinct_values() {
        // The exact reused-`rax` shape that made AST folding unsafe:
        //   rax = rax + rcx ; rax = load[rax] ; rbx = rbx + rax
        // Each rax def is a distinct value, so no folding can conflate them.
        use crate::ir::types::{BinOp, MemOp};
        let lf = mk(vec![
            Op::Bin {
                dst: VReg::phys("rbx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rbx")),
                rhs: Value::Reg(VReg::phys("rcx")),
            },
            Op::Load {
                dst: VReg::phys("rbx"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Bin {
                dst: VReg::phys("rdx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rdx")),
                rhs: Value::Reg(VReg::phys("rbx")),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        let ops = &out.blocks[0].instrs;
        // First rax def is version 1 (its lhs reads the live-in rax v0).
        match &ops[0].op {
            Op::Bin { dst, lhs, .. } => {
                assert_eq!(*dst, VReg::phys("rbx#1"));
                assert_eq!(*lhs, Value::Reg(VReg::phys("rbx"))); // live-in
            }
            other => panic!("{:?}", other),
        }
        match &ops[1].op {
            Op::Load { dst, addr } => {
                assert_eq!(*dst, VReg::phys("rbx#2"));
                assert_eq!(addr.base, Some(VReg::phys("rbx#1")));
            }
            other => panic!("{:?}", other),
        }
        match &ops[2].op {
            Op::Bin { rhs, .. } => assert_eq!(*rhs, Value::Reg(VReg::phys("rbx#2"))),
            other => panic!("{:?}", other),
        }
    }
}
