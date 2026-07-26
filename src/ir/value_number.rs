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
use crate::ir::types::{LlirFunction, LlirInstr, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

/// The registers that carry a return value under `cc` (all width sub-names).
fn return_reg_names(cc: CallConv) -> &'static [&'static str] {
    crate::ir::abi::return_registers(cc)
}

/// Argument-passing registers in positional order (with width sub-names) per `cc`.
fn arg_slot_names(cc: CallConv) -> &'static [&'static [&'static str]] {
    crate::ir::abi::argument_slots(cc)
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
pub fn live_in_arg_slots_llir(lf: &LlirFunction, cc: CallConv) -> std::collections::HashSet<usize> {
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
            // A CALL's argument-register uses say what the CALLEE may read. They are
            // not evidence that THIS function has a parameter. Over-approximating uses
            // is right for liveness and dead-code elimination, which is why `def_uses`
            // reports them; it is wrong for inferring a signature, which is what this
            // function does.
            //
            // Honest scope: this is a correctness argument, not a measured fix. It was
            // written expecting it to explain a DecBench type_match drop; measuring
            // before and after showed NO difference on that corpus (arities were right
            // either way — the first touch of an argument register in these functions
            // is its `-O0` spill, which precedes any call). Kept because the inference
            // should not depend on `def_uses` continuing to under-report call effects.
            if matches!(ins.op, Op::Call { .. }) {
                continue;
            }
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
            // Canonicalize a GP sub-register to its 64-bit parent so a value
            // written as `%rax` and read back as `%eax` (or vice versa) renders
            // as ONE name at the shared SSA version — otherwise the two views get
            // distinct names and the read dangles.
            let canon = crate::ir::ssa::parent64(n)
                .map(str::to_string)
                .unwrap_or_else(|| n.clone());
            if version == 0 {
                *n = canon; // entry-def / live-in — bare (canonical) register
                return;
            }
            if is_structural_reg(&canon) || ctx.keep.contains(&(canon.clone(), version)) {
                *n = canon;
                return;
            }
            *n = format!("{}#{}", canon, version);
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
        // A call's effects must be renamed like any other operand. They are the only
        // place the op records its result and its argument reads, so leaving them at
        // the raw ABI names desynchronises them from the renamed def/use they describe:
        // the post-call read becomes `var4` while the call still claims to write
        // `rax`, and the AST then has a value nobody defines.
        Op::Call { target, effects } => {
            if let crate::ir::types::CallTarget::Indirect(v) = target {
                tag_value(v, use_vers, &mut ui, ctx);
            }
            if let Some(e) = effects {
                for a in e.args.iter_mut() {
                    if let Some(&ver) = use_vers.get(ui) {
                        tag_phys(a, ver, ctx);
                    }
                    ui += 1;
                }
                if let Some(r) = e.result.as_mut() {
                    tag_phys(r, def_ver, ctx);
                }
            }
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
        Op::Ite {
            dst, cond, t, e, ..
        } => {
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
        Op::Intrinsic { .. } | Op::Jump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => {}
    }
}

/// Does `op` define a return register under `ret_names`?
fn defs_return_reg(op: &Op, ret_names: &[&str]) -> bool {
    matches!(def_uses(op).0, Some(VReg::Phys(n)) if ret_names.contains(&n.as_str()))
}

/// Can the return-register def at (`def_bi`, `def_ii`) reach an `Op::Return`
/// without an intervening return-register def overwriting it? Such a def is a
/// value the function actually returns (the `if (c) ret=A; else ret=B; return`
/// shape has TWO of them, both reaching the return via the join). A return
/// register reused purely as scratch — a loop-address `rax` overwritten (or
/// replaced by the real return load) before any `Return` — does NOT reach, so
/// it stays foldable.
fn def_reaches_return(
    lf: &LlirFunction,
    ret_names: &[&str],
    va_to_idx: &std::collections::HashMap<u64, usize>,
    def_bi: usize,
    def_ii: usize,
) -> bool {
    // Rest of the def's own block first.
    for ins in &lf.blocks[def_bi].instrs[def_ii + 1..] {
        if matches!(ins.op, Op::Return) {
            return true;
        }
        if defs_return_reg(&ins.op, ret_names) {
            return false; // overwritten before any return
        }
    }
    // Fell off the end of the block — BFS the successors.
    let succ_idx = |b: usize| -> Vec<usize> {
        lf.blocks[b]
            .succs
            .iter()
            .filter_map(|va| va_to_idx.get(va).copied())
            .collect()
    };
    let mut visited = std::collections::HashSet::new();
    let mut stack = succ_idx(def_bi);
    while let Some(b) = stack.pop() {
        if !visited.insert(b) {
            continue;
        }
        let mut killed = false;
        for ins in &lf.blocks[b].instrs {
            if matches!(ins.op, Op::Return) {
                return true;
            }
            if defs_return_reg(&ins.op, ret_names) {
                killed = true;
                break;
            }
        }
        if !killed {
            stack.extend(succ_idx(b));
        }
    }
    false
}

/// True when the return-register def at (`def_bi`, `def_ii`) — whose register is
/// `def_name` — has its value read via a DIFFERENT-name family alias (a
/// sub-register, e.g. a `%eax` def read back as `%al`) before the next
/// return-register def in the same block.
///
/// Such a def must stay BARE: value_number renames a scratch def by SSA version
/// (`%eax` -> `%eax#1`) but the SSA tracks `al`/`ax`/`eax` as independent
/// registers, so a bare sub-register read is NOT renamed with it — and the later
/// naming pass then maps that orphaned `%al` to the `ret` role, producing a
/// use-before-def (`local_1 = ret` before `ret` is assigned). Keeping the def
/// bare matches the correct register-level lowering. Same-name reuse (a loop
/// address `%rax` read as `%rax`) is unaffected, so address-chain folding stays.
fn def_read_by_alias_before_redef(
    lf: &LlirFunction,
    ret_names: &[&str],
    def_bi: usize,
    def_ii: usize,
    def_name: &str,
) -> bool {
    for ins in &lf.blocks[def_bi].instrs[def_ii + 1..] {
        let (_, uses) = def_uses(&ins.op);
        for u in &uses {
            if let VReg::Phys(n) = u {
                if ret_names.contains(&n.as_str()) && n != def_name {
                    return true;
                }
            }
        }
        if defs_return_reg(&ins.op, ret_names) {
            return false;
        }
    }
    false
}

/// Return a copy of `lf` with every physical register occurrence rewritten to
/// its SSA-value-tagged name. `cc` identifies the return registers whose final
/// (returned) value is kept bare so it still names `ret`.
pub fn value_number(
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: CallConv,
) -> LlirFunction {
    let ret_names = return_reg_names(cc);
    // Keep bare every return-register def that can reach a `Return` without being
    // overwritten — the value(s) the function actually returns. Keeping ALL of
    // them bare (not just one per block) is required for branch-merged returns
    // (`if (c) return A; else return B;`), where each branch's `ret = N` must
    // survive as `ret` and not be versioned into a scratch name (which the
    // dead-store pass would then drop, losing the return value). Scratch reuse of
    // a return register that never reaches a return stays versioned and foldable.
    let va_to_idx: std::collections::HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    let mut keep: KeepBare = KeepBare::new();
    for (bi, block) in lf.blocks.iter().enumerate() {
        for (ii, ins) in block.instrs.iter().enumerate() {
            if let (Some(VReg::Phys(n)), _) = def_uses(&ins.op) {
                if ret_names.contains(&n.as_str())
                    && (def_reaches_return(lf, ret_names, &va_to_idx, bi, ii)
                        || def_read_by_alias_before_redef(lf, ret_names, bi, ii, &n))
                {
                    let v = ssa
                        .def_versions
                        .get(&InstrAddr {
                            block_idx: bi,
                            instr_idx: ii,
                        })
                        .copied()
                        .unwrap_or(0);
                    // Key by the canonical (64-bit) name to match tag_phys.
                    let canon = crate::ir::ssa::parent64(&n)
                        .map(str::to_string)
                        .unwrap_or_else(|| n.clone());
                    keep.insert((canon, v));
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
    insert_phi_copies(&mut out, lf, ssa, &ctx);
    out
}

/// Translate *out* of SSA: give every phi result an actual definition.
///
/// [`compute_ssa`](crate::ir::ssa::compute_ssa) places phis on the dominance
/// frontier and hands each merged read the phi's result version, but a phi is not
/// an executable instruction — nothing above emitted a definition for it. The
/// merged read therefore named a value no instruction produced, and the arm
/// definitions feeding it became dead. Dead-code elimination then removed them,
/// correctly, and the emitted C read uninitialised stack:
///
/// ```c
/// // arith:signs, gcc -O0 — return (a<0 ? -a : a) + (b>a ? b-a : a-b)
/// if ((arg0 < arg1)) {
/// } else {
/// }
/// return (var9 + var3);   // var9: declared, never assigned
/// ```
///
/// The standard resolution, and the one used here: replace each phi with a copy
/// `dst = incoming` at the end of every predecessor block. The copies restore the
/// dataflow, which keeps the arm definitions live; copy propagation then folds most
/// of them back into the arms, so the usual rendered result is the natural C rather
/// than a visible temporary.
///
/// Three details that make this correct rather than approximately correct:
///
/// * **Before the terminator.** A copy appended after a block's branch would never
///   execute, and would leave a branch mid-block where the structurer expects a
///   terminator.
/// * **Critical edges need no split.** A copy at the end of a predecessor with
///   several successors also executes on the paths that bypass the merge — but the
///   phi result is only live from the merge block downward (SSA guarantees its uses
///   are dominated by that block), so on any other path the assignment is dead
///   rather than wrong. Splitting the edge would add a basic block, and an invented
///   block is exactly the kind of structural noise the graph-edit-distance metric
///   charges for.
/// * **No swap hazard.** Phi semantics are parallel, so sequential copies would be
///   wrong if one phi's source were another's destination in the same block. It
///   cannot happen here: there is at most one phi per (block, base register), and a
///   phi destination is a version fresh at its own block while incoming versions all
///   come from strictly earlier definitions.
///
/// Only phis whose result is actually READ get copies. An unread phi is dead, and
/// materialising it would add statements to both arms that no source line
/// corresponds to.
fn insert_phi_copies(
    out: &mut LlirFunction,
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    ctx: &VnCtx,
) {
    if ssa.phis.is_empty() {
        return;
    }

    // Which (base, version) pairs does the renamed body actually read? Computed on
    // the OUTPUT, so it sees the tagged names the copies must match.
    let mut read: HashSet<String> = HashSet::new();
    for b in &out.blocks {
        for ins in &b.instrs {
            let (_, uses) = def_uses(&ins.op);
            for u in uses {
                if let VReg::Phys(n) = u {
                    read.insert(n);
                }
            }
        }
    }

    // Pending copies per predecessor block index, appended in phi order so the
    // result is deterministic.
    let mut pending: Vec<Vec<Op>> = vec![Vec::new(); out.blocks.len()];
    for phi in &ssa.phis {
        let mut dst = phi.base.clone();
        tag_phys(&mut dst, phi.dst_version, ctx);
        let VReg::Phys(dst_name) = &dst else {
            // Only physical registers are named this way; a temp phi would need the
            // remap to agree across blocks, which `build_temp_remap` does not
            // guarantee, so leave those alone rather than emit a wrong copy.
            continue;
        };
        if !read.contains(dst_name) {
            continue;
        }
        for (pred, ver) in &phi.incoming {
            if *pred >= out.blocks.len() {
                continue;
            }
            let mut src = phi.base.clone();
            tag_phys(&mut src, *ver, ctx);
            if src == dst {
                continue; // a version kept bare on both sides: `rax = rax`
            }
            pending[*pred].push(Op::Assign {
                dst: dst.clone(),
                src: Value::Reg(src),
            });
        }
    }

    for (bi, ops) in pending.into_iter().enumerate() {
        if ops.is_empty() {
            continue;
        }
        let block = &mut out.blocks[bi];
        // Insert before a trailing terminator; a block that falls through simply
        // takes them at the end.
        let at = match block.instrs.last().map(|i| &i.op) {
            Some(Op::Jump { .. } | Op::CondJump { .. } | Op::Return) => {
                block.instrs.len() - 1
            }
            _ => block.instrs.len(),
        };
        // Share the VA of the instruction the copies precede: these are not real
        // instructions, and inventing an address would make them look like decoded
        // code to anything keyed on VA.
        let va = block
            .instrs
            .get(at)
            .or_else(|| block.instrs.last())
            .map(|i| i.va)
            .unwrap_or(lf.blocks[bi].start_va);
        for (k, op) in ops.into_iter().enumerate() {
            block.instrs.insert(at + k, LlirInstr { va, op });
        }
    }
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

    /// A diamond: both arms write `rbx`, the join reads it.
    ///
    ///   B0: cmp/branch          -> B1, B2
    ///   B1: rbx = 10            -> B3
    ///   B2: rbx = 20            -> B3
    ///   B3: rcx = rbx ; return
    fn diamond() -> LlirFunction {
        let blk = |va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va: va,
            end_va: va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(j, op)| LlirInstr {
                    va: va + (j as u64) * 4,
                    op,
                })
                .collect(),
            succs,
        };
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                blk(
                    0x1000,
                    vec![Op::CondJump {
                        cond: VReg::phys("rdi"),
                        target: 0x1020,
                        inverted: false,
                    }],
                    vec![0x1010, 0x1020],
                ),
                blk(
                    0x1010,
                    vec![Op::Assign {
                        dst: VReg::phys("rbx"),
                        src: Value::Const(10),
                    }],
                    vec![0x1030],
                ),
                blk(
                    0x1020,
                    vec![Op::Assign {
                        dst: VReg::phys("rbx"),
                        src: Value::Const(20),
                    }],
                    vec![0x1030],
                ),
                blk(
                    0x1030,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Reg(VReg::phys("rbx")),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        }
    }

    /// Every versioned register a body READS must be DEFINED somewhere in that body.
    ///
    /// This is the invariant that translating out of SSA exists to preserve, and it
    /// was being violated at every merge point. `compute_ssa` places phis on the
    /// dominance frontier and hands each merged read the phi's *result* version, but
    /// `value_number` only ever renamed existing instructions — nothing emitted a
    /// definition for that result. So the join read `rbx#3`, a name no instruction
    /// wrote, and the two arm definitions `rbx#1`/`rbx#2` became dead.
    ///
    /// What that looks like in emitted C, from `arith:signs` in the DecBench corpus:
    ///
    /// ```c
    /// if ((arg0 < arg1)) {
    /// } else {
    /// }
    /// return (var9 + var3);   // var9 declared, never assigned
    /// ```
    ///
    /// Both arms emptied out by dead-code elimination — correctly, given the IR it
    /// was handed — and the function returned uninitialised stack. Nothing in the
    /// structural accounting flagged it, and it was right not to: every block and
    /// edge WAS accounted for. The defect was one layer down, in the dataflow.
    fn undefined_reads(lf: &LlirFunction) -> Vec<String> {
        let mut defined: HashSet<String> = HashSet::new();
        for b in &lf.blocks {
            for ins in &b.instrs {
                if let (Some(VReg::Phys(n)), _) = def_uses(&ins.op) {
                    defined.insert(n.clone());
                }
            }
        }
        let mut bad = Vec::new();
        for b in &lf.blocks {
            for ins in &b.instrs {
                let (_, uses) = def_uses(&ins.op);
                for u in uses {
                    if let VReg::Phys(n) = u {
                        // A bare (unversioned) name is the live-in value — a
                        // parameter — and is defined by the caller, not here.
                        if n.contains('#') && !defined.contains(&n) {
                            bad.push(n.clone());
                        }
                    }
                }
            }
        }
        bad.sort();
        bad.dedup();
        bad
    }

    #[test]
    fn a_merged_register_read_is_defined_on_every_path() {
        let lf = diamond();
        let ssa = compute_ssa(&lf);
        assert!(
            !ssa.phis.is_empty(),
            "the fixture must actually produce a phi, else it tests nothing"
        );
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        assert_eq!(
            undefined_reads(&out),
            Vec::<String>::new(),
            "the join reads a phi result that nothing defines"
        );
    }

    #[test]
    fn the_phi_copy_lands_before_the_terminator() {
        // A copy appended AFTER a block's branch would never execute (and would
        // leave the branch in the middle of the block, which the structurer reads
        // as a terminator position). Insert before it.
        let lf = diamond();
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        for (bi, b) in out.blocks.iter().enumerate() {
            if let Some(pos) = b
                .instrs
                .iter()
                .position(|i| matches!(i.op, Op::CondJump { .. } | Op::Jump { .. }))
            {
                assert_eq!(
                    pos,
                    b.instrs.len() - 1,
                    "block {bi}: a branch must stay last, got {:?}",
                    b.instrs.iter().map(|i| &i.op).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn a_phi_result_nobody_reads_gets_no_copy() {
        // The join's read is what makes the copy necessary. Drop the read and the
        // phi is dead: emitting copies for it would add statements to both arms
        // that no C programmer wrote, which is exactly the graph-edit-distance
        // noise the renderer works to avoid.
        let mut lf = diamond();
        lf.blocks[3].instrs.retain(|i| matches!(i.op, Op::Return));
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        let before: usize = lf.blocks.iter().map(|b| b.instrs.len()).sum();
        let after: usize = out.blocks.iter().map(|b| b.instrs.len()).sum();
        assert_eq!(
            before, after,
            "an unread phi must not add copies:\n{:#?}",
            out.blocks
                .iter()
                .map(|b| b.instrs.iter().map(|i| &i.op).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
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
        assert_eq!(
            ops[0].op,
            Op::Assign {
                dst: VReg::phys("rbx#1"),
                src: Value::Const(1)
            }
        );
        assert_eq!(
            ops[1].op,
            Op::Assign {
                dst: VReg::phys("rbx#2"),
                src: Value::Const(2)
            }
        );
        assert_eq!(
            ops[2].op,
            Op::Assign {
                dst: VReg::phys("rcx#1"),
                src: Value::Reg(VReg::phys("rbx#2"))
            }
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
    fn return_reg_def_read_via_subregister_stays_bare() {
        // The `return (uint8_t)x` shape:
        //   eax = rdi      (return-reg def; overwritten below, so it does NOT
        //                   reach the Return — normally scratch-versioned)
        //   rcx = al       (its value read back via the sub-register `al`)
        //   eax = 5        (the real returned value)
        //   return
        // Versioning the first `eax` to `eax#1` would orphan the bare `al` read
        // (SSA tracks al independently), which the naming pass then mis-maps to
        // `ret` -> use-before-def. So the first def must stay BARE.
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("eax"),
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Assign {
                dst: VReg::phys("rcx"),
                src: Value::Reg(VReg::phys("al")),
            },
            Op::Assign {
                dst: VReg::phys("eax"),
                src: Value::Const(5),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        // First def stays bare (not versioned) because `al` reads it — and the
        // GP sub-register `eax` is canonicalized to its 64-bit parent `rax`.
        assert_eq!(
            out.blocks[0].instrs[0].op,
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::phys("rdi")),
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
        assert!(
            params.contains(&0),
            "rdi (slot 0) is a parameter: {:?}",
            params
        );
        assert!(
            params.contains(&1),
            "rsi (slot 1) is a parameter: {:?}",
            params
        );
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
