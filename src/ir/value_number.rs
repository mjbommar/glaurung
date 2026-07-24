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

/// Argument-passing registers in positional order (with width sub-names) per `cc`.
fn arg_slot_names(cc: CallConv) -> &'static [&'static [&'static str]] {
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
        CallConv::Arm => &[&["r0"], &["r1"], &["r2"], &["r3"]],
    }
}

/// The argument slots of `lf` that are genuine **live-in parameters**: a slot is
/// a parameter iff the *first touch* of its register (in program order) is a read,
/// not a write. A register in an argument slot that is written before it is read
/// is scratch reuse (e.g. an O2 function using `rdx`/`rcx` as temporaries) and
/// must NOT inflate the recovered arity.
///
/// Works on the value-numbered LLIR: register names may carry a `#version` tag,
/// which is stripped for slot matching, and it sees parameters whose only later
/// uses were dropped by structuring/DCE (the LLIR predates those passes). Mirrors
/// `naming::live_in_arg_slots` but authoritative for the signature arity + typing.
pub fn live_in_arg_slots_llir(
    lf: &LlirFunction,
    cc: CallConv,
) -> std::collections::HashSet<usize> {
    let mut slot_of: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (i, names) in arg_slot_names(cc).iter().enumerate() {
        for n in *names {
            slot_of.insert(n, i);
        }
    }
    // slot -> is_param (true = first touch was a read). First touch wins.
    let mut decided: std::collections::HashMap<usize, bool> = std::collections::HashMap::new();
    let base_slot = |name: &str| slot_of.get(name.split('#').next().unwrap_or(name)).copied();
    for block in &lf.blocks {
        for ins in &block.instrs {
            let (def, uses) = def_uses(&ins.op);
            // Reads first, then the def — a use and a def of the same slot in one
            // op (`rdx = rdx + 1`) counts as a read (the incoming value is used).
            for u in &uses {
                if let VReg::Phys(n) = u {
                    if let Some(slot) = base_slot(n) {
                        decided.entry(slot).or_insert(true);
                    }
                }
            }
            if let Some(VReg::Phys(n)) = &def {
                if let Some(slot) = base_slot(n) {
                    decided.entry(slot).or_insert(false);
                }
            }
        }
    }
    decided
        .into_iter()
        .filter_map(|(slot, is_param)| is_param.then_some(slot))
        .collect()
}

/// `(register, version)` pairs kept bare despite version ≥ 1 — the value a
/// return register holds when it reaches a `Return`, so downstream naming still
/// maps it to `ret` rather than a scratch `varN`.
type KeepBare = HashSet<(String, u32)>;

/// Remaps each reused lifter temporary `(Temp base, version)` to a fresh, unique
/// temporary id. A lifter reuses one `Temp` for many unrelated values within a
/// function; splitting them by SSA version makes each a single-def temporary, so
/// the single-use expression fold downstream can reassemble split address chains.
type TempRemap = std::collections::HashMap<(u32, u32), u32>;

/// Immutable context threaded through the tagging recursion.
struct VnCtx {
    keep: KeepBare,
    temps: TempRemap,
}

/// Stack/frame base registers must keep their bare names so stack-slot
/// promotion (which pattern-matches `rbp`/`rsp`-relative addresses) still fires.
fn is_structural_reg(n: &str) -> bool {
    matches!(
        n,
        "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp" | "x29" | "w29" | "fp"
    )
}

/// The value-tagged name of a register at a given SSA version. Physical
/// registers get a `reg#version` name (version 0 / structural / kept-bare stay
/// bare); reused temporaries are remapped to their split id.
fn tag_phys(v: &mut VReg, version: u32, ctx: &VnCtx) {
    match v {
        VReg::Phys(n) => {
            if version == 0 {
                return; // entry-def / live-in — keep the bare register
            }
            if is_structural_reg(n) || ctx.keep.contains(&(n.clone(), version)) {
                return;
            }
            *n = format!("{}#{}", n, version);
        }
        VReg::Temp(base) => {
            if let Some(&nid) = ctx.temps.get(&(*base, version)) {
                *base = nid;
            }
        }
        _ => {}
    }
}

/// Rewrite a `Value`'s register (if any) to the version at `use_vers[*ui]`,
/// advancing the use cursor exactly as [`def_uses`] enumerated it.
fn tag_value(v: &mut Value, use_vers: &[u32], ui: &mut usize, ctx: &VnCtx) {
    if let Value::Reg(r) = v {
        if let Some(&ver) = use_vers.get(*ui) {
            tag_phys(r, ver, ctx);
        }
        *ui += 1;
    }
}

fn tag_memop_uses(m: &mut crate::ir::types::MemOp, use_vers: &[u32], ui: &mut usize, ctx: &VnCtx) {
    if let Some(b) = &mut m.base {
        if let Some(&ver) = use_vers.get(*ui) {
            tag_phys(b, ver, ctx);
        }
        *ui += 1;
    }
    if let Some(idx) = &mut m.index {
        if let Some(&ver) = use_vers.get(*ui) {
            tag_phys(idx, ver, ctx);
        }
        *ui += 1;
    }
}

/// Apply the def version and the ordered use versions to one op's registers.
/// The use order mirrors `use_def::def_uses` exactly (memory base before index,
/// operands left-to-right), so the SSA `use_versions` line up by index.
fn tag_op(op: &mut Op, def_ver: u32, use_vers: &[u32], ctx: &VnCtx) {
    let mut ui = 0usize;
    match op {
        Op::Assign { dst, src } => {
            tag_value(src, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::CondAssign { dst, cond, src } => {
            // def_uses order: cond, then src.
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx);
            }
            ui = 1;
            tag_value(src, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Bin { dst, lhs, rhs, .. } => {
            tag_value(lhs, use_vers, &mut ui, ctx);
            tag_value(rhs, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Un { dst, src, .. } => {
            tag_value(src, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Cmp { dst, lhs, rhs, .. } => {
            tag_value(lhs, use_vers, &mut ui, ctx);
            tag_value(rhs, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Load { dst, addr } => {
            tag_memop_uses(addr, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Store { addr, src } => {
            tag_memop_uses(addr, use_vers, &mut ui, ctx);
            tag_value(src, use_vers, &mut ui, ctx);
        }
        Op::CondJump { cond, .. } => {
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx);
            }
        }
        Op::Call {
            target: crate::ir::types::CallTarget::Indirect(v),
        } => {
            tag_value(v, use_vers, &mut ui, ctx);
        }
        Op::ZExt { dst, src, .. }
        | Op::SExt { dst, src, .. }
        | Op::Trunc { dst, src, .. }
        | Op::Extract { dst, src, .. } => {
            tag_value(src, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Concat { dst, hi, lo } => {
            tag_value(hi, use_vers, &mut ui, ctx);
            tag_value(lo, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Ite { dst, cond, t, e, .. } => {
            // def_uses order: cond, then t, then e.
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx); // a flag in practice — no-op
            }
            ui = 1;
            tag_value(t, use_vers, &mut ui, ctx);
            tag_value(e, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
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
    // Keep bare exactly the return-register value that actually reaches a
    // `Return`: the last return-register def preceding each `Return` in its
    // block. At `-O0` that is the value the epilogue leaves in the ABI return
    // slot, so downstream naming maps it to `ret`. A "highest version" heuristic
    // is wrong when the same physical register is *also* reused for scratch —
    // e.g. 64-bit `rax` computing a loop address while the real return is the
    // 32-bit `eax` loaded just before `ret` — because the address def has the
    // higher version and would be kept bare, materialising the address as `ret`
    // (which then spills) instead of folding into its use.
    let mut keep: KeepBare = KeepBare::new();
    for (bi, block) in lf.blocks.iter().enumerate() {
        let mut last_ret_def: Option<(String, u32)> = None;
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
                    last_ret_def = Some((n.clone(), v));
                }
            }
            if matches!(ins.op, Op::Return) {
                if let Some(rd) = last_ret_def.take() {
                    keep.insert(rd);
                }
            }
        }
    }
    let temps = build_temp_remap(lf, ssa);
    let ctx = VnCtx { keep, temps };

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
            tag_op(&mut ins.op, def_ver, &use_vers, &ctx);
        }
    }
    out
}

/// Build the [`TempRemap`]: for every lifter temporary that is *reused* (has
/// more than one SSA version across the function), assign each `(base, version)`
/// a fresh, globally-unique temporary id. Temporaries with a single version are
/// left unchanged (identity), keeping their original ids to minimise churn.
///
/// This is a pure SSA renaming keyed off the same [`SsaInfo`] used for physical
/// registers: a use reading version `V` is remapped identically to the def that
/// produced `V`, so dataflow is preserved by construction.
fn build_temp_remap(lf: &LlirFunction, ssa: &crate::ir::ssa::SsaInfo) -> TempRemap {
    let mut versions_by_base: std::collections::HashMap<u32, HashSet<u32>> =
        std::collections::HashMap::new();
    let mut max_temp_id = 0u32;
    for (bi, block) in lf.blocks.iter().enumerate() {
        for (ii, ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx: bi,
                instr_idx: ii,
            };
            let (def, uses) = def_uses(&ins.op);
            if let Some(VReg::Temp(base)) = def {
                max_temp_id = max_temp_id.max(base);
                let v = ssa.def_versions.get(&addr).copied().unwrap_or(0);
                versions_by_base.entry(base).or_default().insert(v);
            }
            for (k, u) in uses.iter().enumerate() {
                if let VReg::Temp(base) = u {
                    max_temp_id = max_temp_id.max(*base);
                    let v = ssa.use_versions.get(&(addr, k)).copied().unwrap_or(0);
                    versions_by_base.entry(*base).or_default().insert(v);
                }
            }
        }
    }
    let mut remap = TempRemap::new();
    let mut next_id = max_temp_id + 1;
    for (base, versions) in &versions_by_base {
        if versions.len() <= 1 {
            for &v in versions {
                remap.insert((*base, v), *base);
            }
            continue;
        }
        // Reused: the lowest version keeps the original id, the rest get fresh
        // ids, so `Temp(base)` splits into distinct single-def temporaries.
        let mut vs: Vec<u32> = versions.iter().copied().collect();
        vs.sort_unstable();
        for (i, v) in vs.into_iter().enumerate() {
            if i == 0 {
                remap.insert((*base, v), *base);
            } else {
                remap.insert((*base, v), next_id);
                next_id += 1;
            }
        }
    }
    remap
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
    fn live_in_arg_slots_excludes_subregister_scratch() {
        use crate::ir::types::BinOp;
        // The -O2 shape that fools an AST-based analysis:
        //   rax = rdi + 1   ; reads rdi  (slot 0 -> parameter)
        //   edx = rsi - 2   ; writes edx (a sub-register of rdx / slot 2) FIRST
        //   r8  = rdx * 4   ; reads rdx  (slot 2) — but it was already written
        // rdi/rsi are parameters; rdx is scratch (its 32-bit view was written
        // before any read) and must NOT be a parameter.
        let lf = mk(vec![
            Op::Bin {
                op: BinOp::Add,
                dst: VReg::phys("rax"),
                lhs: Value::Reg(VReg::phys("rdi")),
                rhs: Value::Const(1),
            },
            Op::Bin {
                op: BinOp::Sub,
                dst: VReg::phys("edx"),
                lhs: Value::Reg(VReg::phys("rsi")),
                rhs: Value::Const(2),
            },
            Op::Bin {
                op: BinOp::Mul,
                dst: VReg::phys("r8"),
                lhs: Value::Reg(VReg::phys("rdx")),
                rhs: Value::Const(4),
            },
        ]);
        let params = live_in_arg_slots_llir(&lf, CallConv::SysVAmd64);
        assert!(params.contains(&0), "rdi (slot 0) is a parameter: {:?}", params);
        assert!(params.contains(&1), "rsi (slot 1) is a parameter: {:?}", params);
        assert!(
            !params.contains(&2),
            "rdx (slot 2) is sub-register scratch, not a parameter: {:?}",
            params
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
