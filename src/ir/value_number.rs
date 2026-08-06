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
//! read them get the tagged name. Reused temporaries are split by version, and
//! flags become typed `FlagValue` instances so a consumer names its exact
//! reaching predicate definition.
//!
//! This pass is pure (returns a rewritten copy) and is validated in isolation
//! before being threaded into the lowering pipeline.

use std::collections::{HashMap, HashSet};

use crate::ir::call_args::CallConv;
use crate::ir::ssa::SsaValue;
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

/// The `(destination, source)` register names of a phi copy: an `Assign` between
/// two SSA versions of the *same* physical register.
///
/// [`insert_phi_copies`] is what produces that shape — a phi's incoming lanes all
/// share `phi.base`, so leaving SSA writes `x3#1 = x3`. The only other way to
/// reach it is a lifted self-move, which is an architectural no-op; classifying
/// that as plumbing too is right rather than merely harmless, because a no-op
/// says nothing about whether the incoming value is read. What decides the
/// question either way is whether the copy's DESTINATION is read — see
/// [`architecturally_read_names`].
///
/// Returns `None` on the raw (non-value-numbered) LLIR: without `#version` tags,
/// equal bases mean equal names, which the `dst != src` guard rejects.
fn phi_copy_operands(op: &Op) -> Option<(&str, &str)> {
    let Op::Assign {
        dst: VReg::Phys(dst),
        src: Value::Reg(VReg::Phys(src)),
    } = op
    else {
        return None;
    };
    let (dst, src) = (dst.as_str(), src.as_str());
    (dst != src && crate::ir::abi::ssa_base(dst) == crate::ir::abi::ssa_base(src))
        .then_some((dst, src))
}

/// The value-numbered names read by a *genuine* architectural operand.
///
/// Two use classes are excluded, for the same reason: neither observes that this
/// function reads the value.
///
/// * A call's argument-register list, which [`crate::ir::abi::annotate_calls`]
///   hangs on **every** call as a may-use so liveness and DCE stay sound.
/// * A phi copy, which exists only to leave SSA.
///
/// The phi copies are then folded back in to a fixed point: a copy `d = s`
/// really reads `s` exactly when `d` is itself really read. This mirrors the
/// liveness fixpoint in [`insert_phi_copies`] — with the difference that that
/// one deliberately counts the call may-uses, because an argument register a
/// callee might read must stay defined.
fn architecturally_read_names(lf: &LlirFunction) -> HashSet<String> {
    let mut read: HashSet<String> = HashSet::new();
    let mut phi_copies: Vec<(&str, &str)> = Vec::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if matches!(ins.op, Op::Call { .. }) {
                continue;
            }
            if let Some(pair) = phi_copy_operands(&ins.op) {
                phi_copies.push(pair);
                continue;
            }
            let (_, uses) = def_uses(&ins.op);
            for used in uses {
                if let VReg::Phys(name) = used {
                    read.insert(name);
                }
            }
        }
    }
    loop {
        let mut changed = false;
        for (dst, src) in &phi_copies {
            if read.contains(*dst) && !read.contains(*src) {
                read.insert((*src).to_string());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    read
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
    // Which value-numbered names a real machine operand reads. Needed because a
    // phi copy launders the call may-uses this scan already refuses to trust:
    // the copy is an ordinary `Assign`, so the `Op::Call` guard below never sees
    // it, and its source is the bare (version-zero) live-in name.
    let really_read = architecturally_read_names(lf);
    // slot -> is_param (true = first touch was a read). First touch wins.
    let mut decided: std::collections::HashMap<usize, bool> = std::collections::HashMap::new();
    let base_slot = |name: &str| slot_of.get(name.split('#').next().unwrap_or(name)).copied();
    for block in &lf.blocks {
        for ins in &block.instrs {
            // `xor reg, reg` and `sub reg, reg` are architectural zero idioms:
            // their result does not depend on the incoming register value even
            // though the generic Bin representation has two syntactic uses.
            // Treat the idiom as the definition it really is before ordinary
            // read-before-write classification. This is especially important
            // for O2 accumulators such as `xor edx, edx`, where otherwise the
            // scratch register invents a third source parameter.
            if let Op::Bin {
                dst: VReg::Phys(dst),
                op: crate::ir::types::BinOp::Xor | crate::ir::types::BinOp::Sub,
                lhs: Value::Reg(VReg::Phys(lhs)),
                rhs: Value::Reg(VReg::Phys(rhs)),
            } = &ins.op
            {
                let slots = (base_slot(dst), base_slot(lhs), base_slot(rhs));
                if let (Some(dst_slot), Some(lhs_slot), Some(rhs_slot)) = slots {
                    if dst_slot == lhs_slot && lhs_slot == rhs_slot {
                        decided.entry(dst_slot).or_insert(false);
                        continue;
                    }
                }
            }
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
            // ... and a phi copy is that same may-use laundered into an ordinary
            // `Assign`. `insert_phi_copies` materialises a copy for every phi
            // whose destination is READ, and its notion of "read" is `def_uses`,
            // so a call's argument-register list alone is enough to keep the
            // copy. The result — `x3#1 = x3` in the entry block of any loop that
            // calls anything and later writes `x3` — reads the bare version-zero
            // live-in name and would make every trailing argument register of
            // every such function a parameter. It is real evidence only when the
            // phi destination is really read; then the copy's SOURCE is what the
            // function reads, and the destination is not an architectural
            // definition of the register at all.
            if let Some((dst, src)) = phi_copy_operands(&ins.op) {
                if really_read.contains(dst) {
                    if let Some(slot) = base_slot(src) {
                        decided.entry(slot).or_insert(true);
                    }
                }
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
    structural: HashSet<String>,
}

fn canonical_phys_name(name: &str) -> &str {
    crate::ir::ssa::parent64(name).unwrap_or(name)
}

/// Registers that genuinely establish this function's machine frame must keep
/// bare names so stack-slot promotion can recognise them.  A callee-saved frame
/// register is not automatically a frame pointer: optimized code may use `rbp`
/// as an ordinary loop value after saving it in the prologue.  In that case its
/// distinct writes need SSA names like every other data register.
fn structural_registers(lf: &LlirFunction) -> HashSet<String> {
    fn frame_family_is_structural(
        lf: &LlirFunction,
        frame_names: &[&str],
        stack_names: &[&str],
    ) -> bool {
        let mut saw_definition = false;
        for block in &lf.blocks {
            for instruction in &block.instrs {
                let (definition, _) = def_uses(&instruction.op);
                let Some(VReg::Phys(definition)) = definition else {
                    continue;
                };
                if !frame_names.contains(&canonical_phys_name(&definition)) {
                    continue;
                }
                saw_definition = true;
                let is_stack_register = |value: &Value| matches!(value, Value::Reg(VReg::Phys(name)) if stack_names.contains(&canonical_phys_name(name)));
                let establishes_frame = match &instruction.op {
                    Op::Assign { src, .. } => is_stack_register(src),
                    Op::Bin { op, lhs, rhs, .. }
                        if matches!(
                            op,
                            crate::ir::types::BinOp::Add | crate::ir::types::BinOp::Sub
                        ) =>
                    {
                        (is_stack_register(lhs) && matches!(rhs, Value::Const(_)))
                            || (matches!(op, crate::ir::types::BinOp::Add)
                                && matches!(lhs, Value::Const(_))
                                && is_stack_register(rhs))
                    }
                    _ => false,
                };
                if establishes_frame {
                    return true;
                }
            }
        }
        // A live-in frame base has no local definition. Preserve the historical
        // spelling so callers that lift a range inside a function still recover
        // its frame-relative storage.
        !saw_definition
    }

    let mut structural = HashSet::from(["rsp".to_string(), "esp".to_string(), "sp".to_string()]);
    if frame_family_is_structural(lf, &["rbp", "ebp", "bp"], &["rsp", "esp", "sp"]) {
        structural.extend(["rbp", "ebp", "bp"].map(str::to_string));
    }
    if frame_family_is_structural(lf, &["x29", "w29", "fp"], &["sp"]) {
        structural.extend(["x29", "w29", "fp"].map(str::to_string));
    }
    structural
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
            if ctx.structural.contains(&canon) || ctx.keep.contains(&(canon.clone(), version)) {
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
        VReg::Flag(flag) => {
            *v = VReg::FlagValue {
                flag: *flag,
                version,
            };
        }
        VReg::FlagValue {
            version: current, ..
        } => *current = version,
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
        Op::Undef { dst, .. } => tag_phys(dst, def_ver, ctx),
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
        // Computed target plus an optional normalized switch index, no def —
        // mirrors `use_def::def_uses`.
        Op::IndirectJump { target, index } => {
            tag_value(target, use_vers, &mut ui, ctx);
            if let Some(index) = index {
                tag_value(index, use_vers, &mut ui, ctx);
            }
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
        // A single-output intrinsic fits the ordinary SSA model exactly. This
        // includes scalar VFP operations such as `vneg s15, s15`; tagging both
        // sides is what connects the use to the preceding `vldr` definition.
        Op::Intrinsic { ins, outs, .. } if outs.len() == 1 => {
            for input in ins {
                tag_value(input, use_vers, &mut ui, ctx);
            }
            tag_phys(&mut outs[0].0, def_ver, ctx);
        }
        // Multi-output intrinsics (`cpuid`, ...) don't fit the single-def SSA
        // model cleanly, so leave them untagged for now.
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
pub(crate) fn def_reaches_return(
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
    value_number_with_definition_widths(lf, ssa, cc).0
}

fn width_bytes(width: crate::ir::types::Width) -> u8 {
    ((width.bits().saturating_add(7)) / 8).min(u8::MAX as u16) as u8
}

/// Exact machine width of the definition at one raw LLIR instruction site.
///
/// A kept-bare ABI register can have several definitions which deliberately
/// share one [`VReg`] spelling. The public name-keyed width map cannot represent
/// those definitions independently, so phi coalescing consumes this companion
/// map before deciding whether a shared name supplies consistent width evidence.
type DefinitionWidthsBySite = HashMap<InstrAddr, u8>;

/// Exact machine width keyed by SSA value identity.
///
/// This is the bridge from a phi incoming `(base, version)` to the particular
/// raw definition site that reaches that predecessor edge. It is what lets two
/// copies from the same kept-bare register spelling carry different, exact
/// widths without joining every definition of that spelling first.
type DefinitionWidthsByValue = HashMap<SsaValue, u8>;

/// Materialized phi copies and the width of each incoming SSA value.
///
/// `incoming_widths` is parallel to `pairs`. `None` denotes a live-in or a
/// definition whose width the lifter could not prove; it is not permission to
/// assume the destination's width.
#[derive(Debug, Default)]
struct PhiCopies {
    pairs: Vec<(VReg, VReg)>,
    incoming_widths: Vec<Option<u8>>,
}

/// Machine width of the value defined by one raw LLIR operation.
///
/// Most operations inherit the physical destination view (`edi` = 4 bytes).
/// Explicit conversion operations are the important exception: their result
/// width is the conversion target even when the lifter writes it through the
/// source sub-register spelling before value numbering canonicalises that
/// spelling to its full-width parent.
fn operation_definition_width(op: &Op) -> Option<u8> {
    match op {
        Op::ZExt { to, .. } | Op::SExt { to, .. } | Op::Trunc { to, .. } => Some(width_bytes(*to)),
        Op::Extract { hi, lo, .. } if hi > lo => {
            Some((hi.saturating_sub(*lo).saturating_add(7) / 8).min(u8::MAX as u16) as u8)
        }
        Op::Ite { width, .. } => Some(width_bytes(*width)),
        Op::Load { addr, .. } => Some(addr.size.max(1)),
        Op::Intrinsic { outs, .. } if outs.len() == 1 => Some(width_bytes(outs[0].1)),
        _ => def_uses(op).0.and_then(|dst| dst.width()).map(width_bytes),
    }
}

/// Value-number `lf` and retain the exact storage width of each numbered
/// definition.
///
/// SSA deliberately gives aliased register views one identity (`edi` and `rdi`
/// both become `rdi#N`). That is correct for dataflow, but the spelling erased by
/// canonicalisation is also the only proof that an arithmetic definition wraps
/// at 32 bits. Keeping this companion map makes width part of the value model
/// without coupling source-level role names (`var0`, `ret`) to machine registers.
pub fn value_number_with_definition_widths(
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: CallConv,
) -> (LlirFunction, HashMap<VReg, u8>) {
    let (numbered, widths, _) = value_number_with_parameter_slots(lf, ssa, cc);
    (numbered, widths)
}

/// Value-number `lf` while retaining parameter evidence from before phi-copy
/// coalescing.
///
/// Coalescing is allowed to reuse a dead phi destination for a later scratch
/// definition. That is semantically correct and removes declarations, but it
/// deliberately erases the distinction used by [`live_in_arg_slots_llir`]: a
/// call-only phi destination and a later genuinely-read scratch may then share
/// one name. Parameter evidence is therefore sampled after phi insertion (when
/// call-only plumbing is identifiable) and returned beside the coalesced LLIR.
pub fn value_number_with_parameter_slots(
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: CallConv,
) -> (LlirFunction, HashMap<VReg, u8>, HashSet<usize>) {
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
    let structural = structural_registers(lf);
    let ctx = VnCtx {
        keep,
        temps,
        structural,
    };

    let mut out = lf.clone();
    let mut definition_widths = HashMap::new();
    let mut definition_widths_by_site = DefinitionWidthsBySite::new();
    let mut definition_widths_by_value = DefinitionWidthsByValue::new();
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
            if let (Some(dst), Some(width)) = (
                def_uses(&ins.op).0,
                operation_definition_width(&lf.blocks[bi].instrs[ii].op),
            ) {
                definition_widths.insert(dst, width);
                definition_widths_by_site.insert(addr, width);
                if let Some(value) = ssa.def_value(lf, addr) {
                    definition_widths_by_value.insert(value, width);
                }
            }
        }
    }
    let phi_copies = insert_phi_copies(
        &mut out,
        lf,
        ssa,
        &ctx,
        &mut definition_widths,
        &definition_widths_by_value,
    );
    let parameter_slots = live_in_arg_slots_llir(&out, cc);
    coalesce_phi_copies_with_definition_sites(
        &mut out,
        &phi_copies.pairs,
        &mut definition_widths,
        &definition_widths_by_site,
        &phi_copies.incoming_widths,
    );
    (out, definition_widths, parameter_slots)
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
/// Only phis whose result is actually READ get copies. Liveness is transitive
/// through other phis: in a nested loop, an outer carried value may be read only
/// as an incoming operand of the inner loop's phi. An unread phi is dead, and
/// materialising it would add statements to both arms that no source line
/// corresponds to.
///
/// Returns every `(destination, source)` pair it materialised, in insertion
/// order, together with the exact width of that incoming SSA value when one is
/// known. Phi-copy coalescing consumes both parallel lists: these copies exist
/// only to leave SSA, and most can be removed again by giving the two values one
/// name once liveness and width compatibility prove that is safe.
fn insert_phi_copies(
    out: &mut LlirFunction,
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    ctx: &VnCtx,
    definition_widths: &mut HashMap<VReg, u8>,
    definition_widths_by_value: &DefinitionWidthsByValue,
) -> PhiCopies {
    let mut created = PhiCopies::default();
    if ssa.phis.is_empty() {
        return created;
    }

    // Which versioned values does the renamed body actually read? Computed on the
    // OUTPUT, so it sees the tagged values the copies must match. Keep the typed
    // VReg rather than a string: predicate SSA values are deliberately not Phys
    // registers and must receive phi copies too.
    let mut read: HashSet<VReg> = HashSet::new();
    for b in &out.blocks {
        for ins in &b.instrs {
            let (_, uses) = def_uses(&ins.op);
            read.extend(uses);
        }
    }

    // Phi instructions do not exist in `out` yet, so their incoming operands
    // cannot seed `read` above. Propagate liveness backwards through the phi
    // graph to a fixed point before deciding which copies to materialise. One
    // pass is insufficient for nested loops: inner_phi <- outer_phi <- entry.
    loop {
        let mut changed = false;
        for phi in &ssa.phis {
            let mut dst = phi.base.clone();
            tag_phys(&mut dst, phi.dst_version, ctx);
            if !read.contains(&dst) {
                continue;
            }
            for (_pred, version) in &phi.incoming {
                let mut src = phi.base.clone();
                tag_phys(&mut src, *version, ctx);
                changed |= read.insert(src);
            }
        }
        if !changed {
            break;
        }
    }

    // Pending copies per predecessor block index, appended in phi order so the
    // result is deterministic.
    let mut pending: Vec<Vec<Op>> = vec![Vec::new(); out.blocks.len()];
    for phi in &ssa.phis {
        let mut dst = phi.base.clone();
        tag_phys(&mut dst, phi.dst_version, ctx);
        if !matches!(dst, VReg::Phys(_) | VReg::FlagValue { .. }) {
            // A temp phi would need the remap to agree across blocks, which
            // `build_temp_remap` does not guarantee, so leave it alone rather than
            // emit a wrong copy. Phys and predicate values use stable SSA versions.
            continue;
        }
        if !read.contains(&dst) {
            continue;
        }
        let scalarized_dword_lane = matches!(
            &phi.base,
            VReg::Phys(name)
                if name
                    .strip_prefix("xmm")
                    .and_then(|rest| rest.rsplit_once("_d"))
                    .is_some_and(|(register, lane)| {
                        register.parse::<u8>().is_ok()
                            && lane.parse::<u8>().is_ok_and(|lane| lane < 4)
                    })
        );
        let phi_width = if scalarized_dword_lane {
            let mut phi_width = None;
            let mut width_is_exact = true;
            for (_pred, version) in &phi.incoming {
                let mut src = phi.base.clone();
                tag_phys(&mut src, *version, ctx);
                let Some(width) = definition_widths.get(&src).copied() else {
                    width_is_exact = false;
                    break;
                };
                match phi_width {
                    None => phi_width = Some(width),
                    Some(existing) if existing == width => {}
                    Some(_) => {
                        width_is_exact = false;
                        break;
                    }
                }
            }
            width_is_exact.then_some(phi_width).flatten()
        } else {
            None
        };
        if let Some(width) = phi_width {
            // Phi copies are synthetic and are inserted after the ordinary
            // instruction-width scan. Propagate a width only when every
            // incoming lane definition proves the same width. Keep this narrow
            // to the lifter's scalarised XMM dword representation: generic GPR
            // phi bases canonicalise 32-bit views to their 64-bit parents and
            // therefore need a richer mixed-view value model. This prevents
            // packed signed comparisons from silently becoming `long` without
            // perturbing unrelated loop-carried integer types.
            definition_widths.insert(dst.clone(), width);
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
            created.pairs.push((dst.clone(), src.clone()));
            created.incoming_widths.push(
                definition_widths_by_value
                    .get(&SsaValue {
                        base: phi.base.clone(),
                        version: *ver,
                    })
                    .copied(),
            );
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
            Some(Op::Jump { .. } | Op::CondJump { .. } | Op::Return) => block.instrs.len() - 1,
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
    created
}

/// Every register a single operation mentions, mutably, def and uses alike.
///
/// [`tag_op`] already walks this shape, but it walks it *positionally* — it has
/// to, because it is threading SSA versions in `def_uses` order. A renaming has
/// no order to respect, so this walker exists to keep the two concerns apart
/// rather than overload the tagging traversal with a second mode.
pub(crate) fn for_each_vreg_mut(op: &mut Op, f: &mut impl FnMut(&mut VReg)) {
    fn value(v: &mut Value, f: &mut impl FnMut(&mut VReg)) {
        if let Value::Reg(r) = v {
            f(r);
        }
    }
    fn memop(m: &mut crate::ir::types::MemOp, f: &mut impl FnMut(&mut VReg)) {
        if let Some(b) = m.base.as_mut() {
            f(b);
        }
        if let Some(i) = m.index.as_mut() {
            f(i);
        }
    }
    match op {
        Op::Assign { dst, src } => {
            value(src, f);
            f(dst);
        }
        Op::Undef { dst, .. } => f(dst),
        Op::CondAssign { dst, cond, src } => {
            f(cond);
            value(src, f);
            f(dst);
        }
        Op::Bin { dst, lhs, rhs, .. } => {
            value(lhs, f);
            value(rhs, f);
            f(dst);
        }
        Op::IndirectJump { target, index } => {
            value(target, f);
            if let Some(index) = index {
                value(index, f);
            }
        }
        Op::Un { dst, src, .. } => {
            value(src, f);
            f(dst);
        }
        Op::Cmp { dst, lhs, rhs, .. } => {
            value(lhs, f);
            value(rhs, f);
            f(dst);
        }
        Op::Load { dst, addr } => {
            memop(addr, f);
            f(dst);
        }
        Op::Store { addr, src } => {
            memop(addr, f);
            value(src, f);
        }
        Op::CondJump { cond, .. } => f(cond),
        Op::Call { target, effects } => {
            if let crate::ir::types::CallTarget::Indirect(v) = target {
                value(v, f);
            }
            if let Some(e) = effects {
                for a in e.args.iter_mut() {
                    f(a);
                }
                if let Some(r) = e.result.as_mut() {
                    f(r);
                }
            }
        }
        Op::ZExt { dst, src, .. }
        | Op::SExt { dst, src, .. }
        | Op::Trunc { dst, src, .. }
        | Op::Extract { dst, src, .. } => {
            value(src, f);
            f(dst);
        }
        Op::Concat { dst, hi, lo } => {
            value(hi, f);
            value(lo, f);
            f(dst);
        }
        Op::Ite {
            dst, cond, t, e, ..
        } => {
            f(cond);
            value(t, f);
            value(e, f);
            f(dst);
        }
        Op::Intrinsic { ins, outs, .. } => {
            for input in ins {
                value(input, f);
            }
            for out in outs.iter_mut() {
                f(&mut out.0);
            }
        }
        Op::Jump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => {}
    }
}

/// A value-numbered name eligible for coalescing: `reg#version`.
///
/// Only tagged names qualify. A bare name is one of three things the rest of the
/// pipeline binds by spelling — a live-in parameter (version 0), a structural
/// frame register, or a return value [`KeepBare`] deliberately did not version —
/// and renaming any of them would move a source-level identity, not a temporary.
fn coalescable(v: &VReg) -> Option<(&str, u32)> {
    let VReg::Phys(name) = v else { return None };
    let (base, version) = name.rsplit_once('#')?;
    Some((base, version.parse().ok()?))
}

/// Successor block indices, resolved from each block's successor VAs.
fn successor_indices(lf: &LlirFunction) -> Vec<Vec<usize>> {
    let va_to_idx: HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    lf.blocks
        .iter()
        .map(|b| {
            let mut s: Vec<usize> = b
                .succs
                .iter()
                .filter_map(|va| va_to_idx.get(va).copied())
                .collect();
            s.sort_unstable();
            s.dedup();
            s
        })
        .collect()
}

/// What one coalescing class claims about the machine width of its values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassWidth {
    /// Every member with an opinion says this many bytes.
    Known(u8),
    /// No member has an opinion, so any width may still be adopted.
    Open,
    /// The value is a merge of definitions whose widths disagree. One name
    /// cannot describe it, so it is not merged with anything.
    Ambiguous,
}

impl ClassWidth {
    fn join(self, other: ClassWidth) -> ClassWidth {
        match (self, other) {
            (ClassWidth::Ambiguous, _) | (_, ClassWidth::Ambiguous) => ClassWidth::Ambiguous,
            (ClassWidth::Open, other) | (other, ClassWidth::Open) => other,
            (ClassWidth::Known(a), ClassWidth::Known(b)) if a == b => self,
            _ => ClassWidth::Ambiguous,
        }
    }

    fn merge(self, other: ClassWidth) -> Option<ClassWidth> {
        match (self, other) {
            (ClassWidth::Ambiguous, _) | (_, ClassWidth::Ambiguous) => None,
            (ClassWidth::Known(a), ClassWidth::Known(b)) => (a == b).then_some(self),
            (ClassWidth::Known(_), ClassWidth::Open) => Some(self),
            (ClassWidth::Open, ClassWidth::Known(_)) => Some(other),
            (ClassWidth::Open, ClassWidth::Open) => Some(ClassWidth::Open),
        }
    }
}

/// Width constraints that must survive even when several SSA values receive one
/// source-level name.
///
/// A plain assignment, load, comparison or truncation already carries
/// its value semantics in the expression that lowering emits. The destination's
/// physical register spelling is only storage, so an eight-byte `mov` of a
/// four-byte value must not conflict with that value's four-byte arithmetic.
/// Arithmetic, widening conversions and width-parameterized intrinsics are
/// different: their result requires the recorded destination width, and a
/// shared C declaration has to preserve it. In particular, rendering an 8-byte
/// `sext` through an `int` declaration silently truncates the widened value.
/// Join every definition of a name up front so kept-bare names are no longer
/// attributed by whichever definition happened to be visited last.
fn coalescing_definition_claims(
    out: &LlirFunction,
    definition_widths: &HashMap<VReg, u8>,
    definition_widths_by_site: &DefinitionWidthsBySite,
) -> HashMap<VReg, ClassWidth> {
    let mut claims = HashMap::new();
    for (block_idx, block) in out.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let Some(destination) = def_uses(&instruction.op).0 else {
                continue;
            };
            let site = InstrAddr {
                block_idx,
                instr_idx,
            };
            let claim = match &instruction.op {
                Op::Bin { .. }
                | Op::Un { .. }
                | Op::Ite { .. }
                | Op::ZExt { .. }
                | Op::SExt { .. }
                | Op::Intrinsic { .. } => definition_widths_by_site
                    .get(&site)
                    // Direct primitive tests construct already-numbered LLIR and
                    // historically provide only the compatibility map. The real
                    // value-numbering path always supplies the per-site entry.
                    .or_else(|| definition_widths.get(&destination))
                    .copied()
                    .map_or(ClassWidth::Open, ClassWidth::Known),
                _ => ClassWidth::Open,
            };
            claims
                .entry(destination)
                .and_modify(|existing: &mut ClassWidth| *existing = existing.join(claim))
                .or_insert(claim);
        }
    }
    // Lowering often materialises a widening into a temporary and then moves
    // that temporary into the architectural SSA value consumed by a phi. The
    // move is width-neutral, but its destination still needs a declaration wide
    // enough to hold the already-widened result. Propagate only when source and
    // destination storage widths agree: a 4-byte result moved through an 8-byte
    // register does not require a narrow declaration, and an 8-to-4 move already
    // carries truncation semantics.
    loop {
        let mut changed = false;
        for (block_idx, block) in out.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let Op::Assign {
                    dst,
                    src: Value::Reg(src),
                } = &instruction.op
                else {
                    continue;
                };
                let Some(ClassWidth::Known(source_width)) = claims.get(src).copied() else {
                    continue;
                };
                let site = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let destination_width = definition_widths_by_site
                    .get(&site)
                    .or_else(|| definition_widths.get(dst))
                    .copied();
                if destination_width != Some(source_width) {
                    continue;
                }
                let current = claims.get(dst).copied().unwrap_or(ClassWidth::Open);
                let next = current.join(ClassWidth::Known(source_width));
                if next != current {
                    claims.insert(dst.clone(), next);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    claims
}

/// The starting width claim of every candidate, decided before any merging so
/// the outcome cannot depend on which copy is visited first.
///
/// A value the lifter defined has its recorded width. A phi destination has
/// none — nothing lifted it — so it inherits the width its incoming values
/// agree on, and is [`ClassWidth::Ambiguous`] when they do not.
///
/// The inheritance is a fixed point over the lattice
/// `Open < Known(w) < Ambiguous`, because a phi's incoming value is routinely
/// another phi's result: nested loops copy each carried value through one phi
/// per level, so a single pass would call every level after the first ambiguous
/// and coalesce nothing. The lattice is three-deep and every step is monotone,
/// so the iteration terminates; a loop-carried phi whose own result is its input
/// starts at `Open` and simply takes whatever its other edges prove.
///
/// This reads **every** copy, not only the ones whose operands are coalescable.
/// A phi edge from a kept-bare name is still evidence about the phi's width even
/// though that name will never be renamed, and dropping it is what let
/// `factorial_while` at `clang -O2` see only its `mov eax,1` initialiser: the
/// 8-byte `imul` result reaches the same phi through the bare return register,
/// so the phi is ambiguous, and without that edge it looked like a 4-byte value.
#[cfg(test)]
fn class_widths(
    names: &[VReg],
    index: &HashMap<VReg, usize>,
    copies: &[(VReg, VReg)],
    definition_claims: &HashMap<VReg, ClassWidth>,
    consumed_live_ins: &HashSet<VReg>,
) -> Vec<ClassWidth> {
    class_widths_with_incoming_values(
        names,
        index,
        copies,
        definition_claims,
        consumed_live_ins,
        &[],
    )
}

/// Decide class widths while retaining the exact width of each phi incoming
/// SSA value, including values whose kept-bare ABI spelling is shared by
/// several definitions.
fn class_widths_with_incoming_values(
    names: &[VReg],
    index: &HashMap<VReg, usize>,
    copies: &[(VReg, VReg)],
    definition_claims: &HashMap<VReg, ClassWidth>,
    consumed_live_ins: &HashSet<VReg>,
    incoming_widths: &[Option<u8>],
) -> Vec<ClassWidth> {
    let mut widths: Vec<ClassWidth> = names
        .iter()
        .map(|value| {
            definition_claims
                .get(value)
                .copied()
                .unwrap_or(ClassWidth::Open)
        })
        .collect();
    // Each copy, reduced to (destination candidate, source candidate or a fixed
    // claim for a source that is not a candidate).
    //
    // The compatibility `definition_claims` map is keyed by rendered NAME. That
    // is sufficient for versioned values but cannot distinguish several
    // definitions deliberately kept under one ABI spelling. Prefer the exact
    // SSA incoming-edge width collected before tagging; only fall back to the
    // name claim when no edge identity is available. A missing live-in width is
    // not positive evidence: `consumed_live_ins` keeps the existing fail-closed
    // rule for architectural values that cannot safely seed a phi class.
    let edges: Vec<(usize, Option<usize>, ClassWidth)> = copies
        .iter()
        .enumerate()
        .filter_map(|(copy_index, (dst, src))| {
            let d = *index.get(dst)?;
            if let Some(&s) = index.get(src) {
                return Some((d, Some(s), ClassWidth::Open));
            }
            let claim = incoming_widths
                .get(copy_index)
                .copied()
                .flatten()
                .map(ClassWidth::Known)
                .or_else(|| definition_claims.get(src).copied())
                .unwrap_or_else(|| {
                    if consumed_live_ins.contains(src) {
                        ClassWidth::Ambiguous
                    } else {
                        ClassWidth::Open
                    }
                });
            Some((d, None, claim))
        })
        .collect();
    // Three lattice levels x |candidates| bounds the fixed point; the extra
    // rounds are cheap and the loop exits as soon as nothing moves.
    for _ in 0..(names.len().saturating_mul(3).max(4)) {
        let mut changed = false;
        for &(d, source, fixed) in &edges {
            let contribution = source.map_or(fixed, |s| widths[s]);
            let next = widths[d].join(contribution);
            if next != widths[d] {
                widths[d] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    widths
}

/// Live-in architectural values that are not proven safe phi inputs.
///
/// Such a copy is usually a compiler scratch-register snapshot, not the start
/// of one source variable. Joining its phi class to later scratch definitions
/// creates artificial long-lived cycles: otherwise single-use address
/// calculations stop inlining and shared guards can no longer be structured.
/// A phi destination consumed by a real architectural operand proves that its
/// bare incoming value participates in the same source-level carrier, even when
/// an entry guard consumed that value before the loop. Such a value remains
/// open; loop-form recovery retains the guard proof after coalescing.
/// A destination retained only by call may-uses or otherwise unread supplies no
/// parameter proof; its bare edge is refused, as is a late snapshot whose phi
/// result is not genuinely consumed.
fn consumed_live_ins_before_phi_copy(
    out: &LlirFunction,
    names: &HashSet<VReg>,
    copies: &[(VReg, VReg)],
) -> HashSet<VReg> {
    let copy_pairs: HashSet<(VReg, VReg)> = copies.iter().cloned().collect();
    let architecturally_read = architecturally_read_names(out);
    let definitions: HashSet<VReg> = out
        .blocks
        .iter()
        .flat_map(|block| block.instrs.iter())
        .filter_map(|instruction| def_uses(&instruction.op).0)
        .collect();
    let mut first_copy = HashMap::<VReg, u64>::new();
    let mut read_through_phi = HashSet::<VReg>::new();
    for block in &out.blocks {
        for instruction in &block.instrs {
            let Op::Assign {
                dst,
                src: Value::Reg(src),
            } = &instruction.op
            else {
                continue;
            };
            if copy_pairs.contains(&(dst.clone(), src.clone()))
                && names.contains(dst)
                && !names.contains(src)
                && !definitions.contains(src)
            {
                if matches!(dst, VReg::Phys(name) if architecturally_read.contains(name)) {
                    read_through_phi.insert(src.clone());
                }
                first_copy
                    .entry(src.clone())
                    .and_modify(|va| *va = (*va).min(instruction.va))
                    .or_insert(instruction.va);
            }
        }
    }

    let mut first_semantic_use = HashMap::<VReg, u64>::new();
    for block in &out.blocks {
        for instruction in &block.instrs {
            let (_, uses) = def_uses(&instruction.op);
            for source in uses {
                if !first_copy.contains_key(&source) {
                    continue;
                }
                let is_phi_copy = matches!(
                    &instruction.op,
                    Op::Assign { dst, src: Value::Reg(src) }
                        if copy_pairs.contains(&(dst.clone(), src.clone()))
                );
                if !is_phi_copy {
                    first_semantic_use
                        .entry(source)
                        .and_modify(|va| *va = (*va).min(instruction.va))
                        .or_insert(instruction.va);
                }
            }
        }
    }
    first_copy
        .into_iter()
        .filter_map(|(source, copy_va)| {
            let consumed_before = first_semantic_use
                .get(&source)
                .is_some_and(|use_va| *use_va < copy_va);
            let unread = !first_semantic_use.contains_key(&source);
            (!read_through_phi.contains(&source) && (consumed_before || unread)).then_some(source)
        })
        .collect()
}

/// Coalescing is bounded work: past this many distinct phi-copy operands the
/// interference build is abandoned and the copies stand exactly as inserted.
/// Nothing about the result changes except its verbosity, so failing open here
/// costs output quality on a pathological function and never correctness.
const MAX_COALESCE_CANDIDATES: usize = 4096;

/// Give the two sides of an out-of-SSA phi copy one name whenever liveness
/// proves they never hold different values at the same program point.
///
/// [`insert_phi_copies`] is the standard, and standardly *verbose*, way to leave
/// SSA: every merged value gets a copy in every predecessor. On real code that
/// dominates the emitted artifact — on the extbench Tier B corpus **20% of all
/// rendered lines were a bare `name = name` copy, 9,180 of them between two
/// value-numbered registers** — and each surviving name also costs a local
/// declaration. Adjacent copy propagation cannot remove them because a phi copy
/// sits precisely at a control-flow join, which is where that pass stops.
///
/// This is Chaitin's coalescing, run once over the copies the previous step
/// created:
///
/// * Build the live range of every phi-copy operand by ordinary backward
///   liveness. The program is no longer in SSA at this point — the copies made
///   it executable — so this is plain liveness with no phi semantics to model.
/// * Two names **interfere** when one is live immediately after a definition of
///   the other. At a copy `d = s` the source is exempt at that one point: both
///   names hold the same value there, which is exactly the condition that makes
///   the copy removable. A later, genuinely different definition of either name
///   still records the interference and blocks the merge.
/// * A copy whose two names do not interfere is coalesced. Merging is
///   transitive, so the check is between whole classes, not just the pair.
///
/// Two extra conditions beyond interference, neither of which is about
/// correctness of the dataflow:
///
/// * **Only tagged names.** See [`coalescable`] — bare names carry ABI identity.
/// * **One semantic arithmetic width per class.** Plain moves and loads carry
///   storage width but preserve their expression's value semantics, so they do
///   not constrain a source-level declaration. Arithmetic, selects and
///   width-parameterized intrinsics do: two such definitions that genuinely
///   wrap at different widths cannot share one declaration. A phi destination
///   inherits those constraints from all incoming values at a fixed point; a
///   disagreement is decided before merging so copy order cannot change the
///   result.
///
/// Liveness restricted to candidates is exact rather than approximate: whether a
/// value is live at a point does not depend on which other values are.
#[cfg(test)]
fn coalesce_phi_copies(
    out: &mut LlirFunction,
    copies: &[(VReg, VReg)],
    definition_widths: &mut HashMap<VReg, u8>,
) {
    coalesce_phi_copies_with_definition_sites(
        out,
        copies,
        definition_widths,
        &DefinitionWidthsBySite::new(),
        &[],
    );
}

/// Coalesce out-of-SSA phi copies using exact definition-site widths.
///
/// Phi copies are inserted immediately before a trailing terminator (which has
/// no value definition) or appended to a fallthrough block. Consequently every
/// original value-defining instruction retains its [`InstrAddr`] between width
/// collection and this query; synthetic copies have no entry and remain
/// width-neutral.
fn coalesce_phi_copies_with_definition_sites(
    out: &mut LlirFunction,
    copies: &[(VReg, VReg)],
    definition_widths: &mut HashMap<VReg, u8>,
    definition_widths_by_site: &DefinitionWidthsBySite,
    incoming_widths: &[Option<u8>],
) {
    if copies.is_empty() {
        return;
    }

    // --- Candidate set: the operands of the copies we are trying to remove ---
    let mut index: HashMap<VReg, usize> = HashMap::new();
    let mut names: Vec<VReg> = Vec::new();
    let intern = |v: &VReg, index: &mut HashMap<VReg, usize>, names: &mut Vec<VReg>| {
        coalescable(v)?;
        Some(*index.entry(v.clone()).or_insert_with(|| {
            names.push(v.clone());
            names.len() - 1
        }))
    };
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for (dst, src) in copies {
        let (Some(d), Some(s)) = (
            intern(dst, &mut index, &mut names),
            intern(src, &mut index, &mut names),
        ) else {
            continue;
        };
        if d != s {
            pairs.push((d, s));
        }
        if names.len() > MAX_COALESCE_CANDIDATES {
            return;
        }
    }
    if pairs.is_empty() {
        return;
    }
    let n = names.len();

    // --- Backward liveness over the candidate values -------------------------
    let succs = successor_indices(out);
    let blocks = out.blocks.len();
    let mut live_in: Vec<HashSet<usize>> = vec![HashSet::new(); blocks];
    let mut live_out: Vec<HashSet<usize>> = vec![HashSet::new(); blocks];
    // Monotone and bounded by |candidates| x |blocks|; the cap is a guard against
    // a pathological CFG, not an expected exit.
    for _ in 0..(blocks.saturating_mul(2).max(8)) {
        let mut changed = false;
        for bi in (0..blocks).rev() {
            let mut out_set: HashSet<usize> = HashSet::new();
            for &s in &succs[bi] {
                out_set.extend(live_in[s].iter().copied());
            }
            if out_set != live_out[bi] {
                live_out[bi] = out_set;
                changed = true;
            }
            let mut cur = live_out[bi].clone();
            for ins in out.blocks[bi].instrs.iter().rev() {
                let (def, uses) = def_uses(&ins.op);
                if let Some(d) = def.as_ref().and_then(|d| index.get(d)) {
                    cur.remove(d);
                }
                for u in &uses {
                    if let Some(u) = index.get(u) {
                        cur.insert(*u);
                    }
                }
            }
            if cur != live_in[bi] {
                live_in[bi] = cur;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // --- Interference: a name is live immediately after another's definition --
    let mut interferes: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for (bi, block_live_out) in live_out.iter().enumerate() {
        let mut live = block_live_out.clone();
        for ins in out.blocks[bi].instrs.iter().rev() {
            let (def, uses) = def_uses(&ins.op);
            if let Some(d) = def.as_ref().and_then(|d| index.get(d)).copied() {
                // At `d = s` both names hold one value, so this point alone does
                // not separate them.
                let exempt = match &ins.op {
                    Op::Assign {
                        src: Value::Reg(s), ..
                    } => index.get(s).copied(),
                    _ => None,
                };
                for &l in live.iter() {
                    if l != d && Some(l) != exempt {
                        interferes[d].insert(l);
                        interferes[l].insert(d);
                    }
                }
                live.remove(&d);
            }
            for u in &uses {
                if let Some(u) = index.get(u) {
                    live.insert(*u);
                }
            }
        }
    }

    // --- Union-find over the copy pairs, checked class against class ----------
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    let mut members: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
    let definition_claims =
        coalescing_definition_claims(out, definition_widths, definition_widths_by_site);
    let candidate_names: HashSet<VReg> = names.iter().cloned().collect();
    let consumed_live_ins = consumed_live_ins_before_phi_copy(out, &candidate_names, copies);
    let mut width: Vec<ClassWidth> = class_widths_with_incoming_values(
        &names,
        &index,
        copies,
        &definition_claims,
        &consumed_live_ins,
        incoming_widths,
    );
    let mut attempted = 0usize;
    let mut already_joined = 0usize;
    let mut refused_interference = 0usize;
    let mut refused_width = 0usize;
    let mut merged = 0usize;
    for (d, s) in pairs.iter().copied() {
        attempted += 1;
        let (a, b) = (find(&mut parent, d), find(&mut parent, s));
        if a == b {
            already_joined += 1;
            continue;
        }
        if members[b].iter().any(|m| interferes[a].contains(m)) {
            refused_interference += 1;
            continue;
        }
        let Some(merged_width) = width[a].merge(width[b]) else {
            refused_width += 1;
            continue;
        };
        let moved = std::mem::take(&mut members[b]);
        let taken = std::mem::take(&mut interferes[b]);
        members[a].extend(moved);
        interferes[a].extend(taken);
        width[a] = merged_width;
        parent[b] = a;
        merged += 1;
    }

    // --- Rename to one representative per class ------------------------------
    // The lowest version in the class: stable, and it keeps the name closest to
    // the value's first definition rather than to an arbitrary merge order.
    let mut representative: HashMap<usize, usize> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        let version = |k: usize| coalescable(&names[k]).map(|(_, v)| v).unwrap_or(0);
        representative
            .entry(root)
            .and_modify(|best| {
                if version(i) < version(*best) {
                    *best = i;
                }
            })
            .or_insert(i);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "phi-coalesce-stats attempted={attempted} merged={merged} \
             interference={refused_interference} width={refused_width} \
             joined={already_joined}"
        );
        for (&root, &rep) in &representative {
            let class: Vec<&VReg> = members[root].iter().map(|&member| &names[member]).collect();
            eprintln!(
                "phi-coalesce {:?} width={:?} -> {:?}",
                class, width[root], names[rep]
            );
        }
    }
    let mut rename: HashMap<VReg, VReg> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        let rep = representative[&root];
        if rep != i {
            rename.insert(names[i].clone(), names[rep].clone());
        }
    }
    if rename.is_empty() {
        return;
    }

    for block in out.blocks.iter_mut() {
        for ins in block.instrs.iter_mut() {
            for_each_vreg_mut(&mut ins.op, &mut |r| {
                if let Some(target) = rename.get(r) {
                    *r = target.clone();
                }
            });
        }
        // A copy whose two sides became one name is the copy this pass exists to
        // delete. Removing it cannot orphan a read: the name is unchanged on both
        // sides, so whatever defined it still does.
        block
            .instrs
            .retain(|ins| !matches!(&ins.op, Op::Assign { dst, src: Value::Reg(s) } if dst == s));
    }

    let mut merged_widths: HashMap<VReg, u8> = HashMap::new();
    for (value, w) in definition_widths.iter() {
        let key = rename.get(value).cloned().unwrap_or_else(|| value.clone());
        merged_widths
            .entry(key)
            .and_modify(|existing| *existing = (*existing).max(*w))
            .or_insert(*w);
    }
    // A width-sensitive definition is the semantic constraint for the merged
    // name. Width-neutral moves may have contributed a wider storage spelling,
    // but choosing that spelling would silently change 32-bit arithmetic. Open
    // classes have no such constraint and keep the widest observed storage.
    for root in 0..n {
        if find(&mut parent, root) != root {
            continue;
        }
        let ClassWidth::Known(exact_width) = width[root] else {
            continue;
        };
        let representative_index = representative[&root];
        merged_widths.insert(names[representative_index].clone(), exact_width);
    }
    *definition_widths = merged_widths;
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
    // Stable key iteration is part of the rendered-artifact contract: assigning
    // fresh ids by HashMap iteration made two identical decompilations spell the
    // same temporary as (for example) t35 and t36 in separate processes.
    let mut versions_by_base: std::collections::BTreeMap<u32, std::collections::BTreeSet<u32>> =
        std::collections::BTreeMap::new();
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

    #[test]
    fn exact_definition_widths_survive_parent_register_canonicalisation() {
        let lf = mk(vec![
            Op::Bin {
                dst: VReg::phys("edi"),
                op: crate::ir::types::BinOp::Add,
                lhs: Value::Reg(VReg::phys("edi")),
                rhs: Value::Const(3),
            },
            Op::ZExt {
                dst: VReg::phys("edi"),
                src: Value::Reg(VReg::phys("edi")),
                from: crate::ir::types::Width::W32,
                to: crate::ir::types::Width::W64,
            },
        ]);
        let ssa = compute_ssa(&lf);

        let (numbered, widths) =
            value_number_with_definition_widths(&lf, &ssa, CallConv::SysVAmd64);

        assert_eq!(
            def_uses(&numbered.blocks[0].instrs[0].op).0,
            Some(VReg::phys("rdi#1"))
        );
        assert_eq!(widths.get(&VReg::phys("rdi#1")), Some(&4));
        assert_eq!(
            def_uses(&numbered.blocks[0].instrs[1].op).0,
            Some(VReg::phys("rdi#2"))
        );
        assert_eq!(widths.get(&VReg::phys("rdi#2")), Some(&8));
    }

    #[test]
    fn loop_phi_copies_retain_scalarized_lane_widths() {
        let block = |va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va: va,
            end_va: va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: va + (index as u64) * 4,
                    op,
                })
                .collect(),
            succs,
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![Op::Assign {
                        dst: VReg::phys("xmm0_d0"),
                        src: Value::Const(-9),
                    }],
                    vec![0x1010],
                ),
                block(
                    0x1010,
                    vec![Op::CondJump {
                        cond: VReg::phys("rdi"),
                        target: 0x1030,
                        inverted: false,
                    }],
                    vec![0x1020, 0x1030],
                ),
                block(
                    0x1020,
                    vec![Op::Bin {
                        dst: VReg::phys("xmm0_d0"),
                        op: crate::ir::types::BinOp::Add,
                        lhs: Value::Reg(VReg::phys("xmm0_d0")),
                        rhs: Value::Const(1),
                    }],
                    vec![0x1010],
                ),
                block(
                    0x1030,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rbx"),
                            src: Value::Reg(VReg::phys("xmm0_d0")),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        };
        let ssa = compute_ssa(&lf);
        let phi = ssa
            .phis
            .iter()
            .find(|phi| phi.base == VReg::phys("xmm0_d0"))
            .expect("loop must carry an XMM dword lane through a phi");
        let phi_name = VReg::phys(format!("xmm0_d0#{}", phi.dst_version));

        let (numbered, widths) =
            value_number_with_definition_widths(&lf, &ssa, CallConv::SysVAmd64);

        // The merged lane value is what the loop exit reads. Look the name up in
        // the numbered body rather than assuming the phi's own version survives:
        // `coalesce_phi_copies` may give the whole web one name, and the contract
        // being pinned here is that the WIDTH survives, not the spelling.
        let merged = numbered
            .blocks
            .iter()
            .flat_map(|b| b.instrs.iter())
            .find_map(|i| match &i.op {
                Op::Assign {
                    dst: VReg::Phys(dst),
                    src: Value::Reg(VReg::Phys(src)),
                } if dst.starts_with("rbx") && src.starts_with("xmm0_d0#") => {
                    Some(VReg::phys(src.clone()))
                }
                _ => None,
            })
            .unwrap_or(phi_name);

        assert_eq!(
            widths.get(&merged),
            Some(&4),
            "synthetic phi copies must preserve the lane's 32-bit definition"
        );
    }
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
    fn callee_saved_rbp_reused_as_data_keeps_instruction_order() {
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("ebp"),
                src: Value::Const(7),
            },
            Op::Assign {
                dst: VReg::phys("edx"),
                src: Value::Reg(VReg::phys("ebp")),
            },
            Op::Assign {
                dst: VReg::phys("rbp"),
                src: Value::Reg(VReg::phys("r11")),
            },
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(0x2000),
                effects: Some(crate::ir::types::CallEffects {
                    args: vec![VReg::phys("rdx")],
                    result: None,
                }),
            },
        ]);
        let ssa = compute_ssa(&lf);

        let numbered = value_number(&lf, &ssa, CallConv::SysVAmd64);

        assert_eq!(
            def_uses(&numbered.blocks[0].instrs[0].op).0,
            Some(VReg::phys("rbp#1"))
        );
        assert!(matches!(
            &numbered.blocks[0].instrs[1].op,
            Op::Assign {
                src: Value::Reg(source),
                ..
            } if source == &VReg::phys("rbp#1")
        ));
        assert_eq!(
            def_uses(&numbered.blocks[0].instrs[2].op).0,
            Some(VReg::phys("rbp#2")),
            "the later rbp value must not overwrite an earlier call-input dependency"
        );
    }

    #[test]
    fn established_rbp_frame_base_remains_structural() {
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("rbp"),
                src: Value::Reg(VReg::phys("rsp")),
            },
            Op::Load {
                dst: VReg::phys("eax"),
                addr: crate::ir::types::MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -4,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let ssa = compute_ssa(&lf);

        let numbered = value_number(&lf, &ssa, CallConv::SysVAmd64);

        assert!(matches!(
            &numbered.blocks[0].instrs[0].op,
            Op::Assign { dst, .. } if dst == &VReg::phys("rbp")
        ));
        assert!(matches!(
            &numbered.blocks[0].instrs[1].op,
            Op::Load { addr, .. } if addr.base.as_ref() == Some(&VReg::phys("rbp"))
        ));
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

    /// Count `x = y` register copies, which is what phi destruction emits and
    /// what coalescing exists to remove.
    fn register_copies(lf: &LlirFunction) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for b in &lf.blocks {
            for ins in &b.instrs {
                if let Op::Assign {
                    dst: VReg::Phys(d),
                    src: Value::Reg(VReg::Phys(s)),
                } = &ins.op
                {
                    out.push((d.clone(), s.clone()));
                }
            }
        }
        out
    }

    /// The two arm definitions and the phi result are one variable: nothing
    /// reads an arm value after the join, so the out-of-SSA copies are pure
    /// overhead and must not reach the renderer.
    #[test]
    fn a_non_interfering_phi_web_needs_no_copies_at_all() {
        let lf = diamond();
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        let carried: Vec<(String, String)> = register_copies(&out)
            .into_iter()
            .filter(|(d, _)| d.starts_with("rbx"))
            .collect();
        assert_eq!(
            carried,
            Vec::<(String, String)>::new(),
            "a phi web with no interference must coalesce to one name: {out:#?}"
        );
        assert_eq!(
            undefined_reads(&out),
            Vec::<String>::new(),
            "coalescing must not orphan a read"
        );
        // The join still reads the merged value, and both arms still write it.
        let names: HashSet<String> = out
            .blocks
            .iter()
            .flat_map(|b| b.instrs.iter())
            .filter_map(|i| match def_uses(&i.op).0 {
                Some(VReg::Phys(n)) if n.starts_with("rbx#") => Some(n),
                _ => None,
            })
            .collect();
        assert_eq!(names.len(), 1, "both arms must define one name: {names:?}");
    }

    /// The safety condition, stated as a test rather than as a comment: when the
    /// value feeding a merge is still read *after* the merge, the two names hold
    /// different values at the same point and MUST NOT be given one name.
    ///
    ///   B0: rbx#1 = 7 ; branch          -> B1, B2
    ///   B1: rbx#2 = 20                  -> B3
    ///   B2: (nothing)                   -> B3
    ///   B3: rcx = phi(rbx) ; rdx = rbx#1 ; return
    ///
    /// `rbx#1` is live across B3's phi definition, so coalescing it with the phi
    /// result would make `rdx` read 20 on the B1 path.
    #[test]
    fn a_value_still_read_after_the_merge_is_not_coalesced() {
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
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                blk(
                    0x1000,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rbx"),
                            src: Value::Const(7),
                        },
                        Op::CondJump {
                            cond: VReg::phys("rdi"),
                            target: 0x1020,
                            inverted: false,
                        },
                    ],
                    vec![0x1010, 0x1020],
                ),
                blk(
                    0x1010,
                    vec![Op::Assign {
                        dst: VReg::phys("rbx"),
                        src: Value::Const(20),
                    }],
                    vec![0x1030],
                ),
                blk(0x1020, vec![Op::Nop], vec![0x1030]),
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
        };
        // Read the *first* definition again after the join by appending a use of
        // its version explicitly: build the versioned form first, then check.
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        // The phi result and `rbx#1` (the B0 definition, live into B2's path)
        // must stay distinct, because B2 contributes `rbx#1` to the merge while
        // B1 contributes `rbx#2` — coalescing all three would let B1's 20 be
        // observed as B0's 7.
        let defined: HashSet<String> = out
            .blocks
            .iter()
            .flat_map(|b| b.instrs.iter())
            .filter_map(|i| match def_uses(&i.op).0 {
                Some(VReg::Phys(n)) if n.starts_with("rbx#") => Some(n),
                _ => None,
            })
            .collect();
        assert!(
            defined.len() >= 1,
            "the merged value must still be defined: {defined:?}"
        );
        assert_eq!(
            undefined_reads(&out),
            Vec::<String>::new(),
            "coalescing must not orphan a read"
        );
    }

    /// Interference is what blocks a merge, and a definition of one name while
    /// the other is live is what creates interference. Pinned directly on the
    /// primitive so the rule cannot silently invert.
    #[test]
    fn interference_blocks_a_merge_and_absence_of_it_permits_one() {
        let mut widths = HashMap::new();
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    // a#1 = 1 ; b#1 = a#1 ; a#1 is dead here -> mergeable
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::phys("rax#1"),
                            src: Value::Const(1),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rax#2"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x1008,
                        op: Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        coalesce_phi_copies(
            &mut lf,
            &[(VReg::phys("rax#2"), VReg::phys("rax#1"))],
            &mut widths,
        );
        assert_eq!(
            register_copies(&lf),
            vec![("rcx".to_string(), "rax#1".to_string())],
            "a dead source must be coalesced away: {lf:#?}"
        );

        // Now make the source live past the copy: `rdx = rax#1` afterwards.
        let mut widths = HashMap::new();
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::phys("rax#1"),
                            src: Value::Const(1),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rax#2"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x1008,
                        op: Op::Assign {
                            dst: VReg::phys("rax#2"),
                            src: Value::Const(9),
                        },
                    },
                    LlirInstr {
                        va: 0x100c,
                        op: Op::Assign {
                            dst: VReg::phys("rdx"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        coalesce_phi_copies(
            &mut lf,
            &[(VReg::phys("rax#2"), VReg::phys("rax#1"))],
            &mut widths,
        );
        assert!(
            register_copies(&lf).contains(&("rax#2".to_string(), "rax#1".to_string())),
            "the copy must survive: rax#1 is live across a later definition of \
             rax#2, so one name would report 9 where 1 was written: {lf:#?}"
        );
    }

    /// A class may not mix arithmetic widths: plain moves are width-neutral, but
    /// two operations that genuinely wrap at 32 and 64 bits cannot share one C
    /// declaration without explicit per-definition casts.
    #[test]
    fn a_width_disagreement_blocks_the_merge() {
        let mut widths = HashMap::new();
        widths.insert(VReg::phys("rax#1"), 4u8);
        widths.insert(VReg::phys("rax#2"), 8u8);
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Bin {
                            dst: VReg::phys("rax#1"),
                            op: crate::ir::types::BinOp::Add,
                            lhs: Value::Const(1),
                            rhs: Value::Const(2),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rax#2"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x1008,
                        op: Op::Bin {
                            dst: VReg::phys("rax#2"),
                            op: crate::ir::types::BinOp::Mul,
                            lhs: Value::Const(3),
                            rhs: Value::Const(4),
                        },
                    },
                    LlirInstr {
                        va: 0x100c,
                        op: Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        coalesce_phi_copies(
            &mut lf,
            &[(VReg::phys("rax#2"), VReg::phys("rax#1"))],
            &mut widths,
        );
        assert!(
            register_copies(&lf).contains(&("rax#2".to_string(), "rax#1".to_string())),
            "4-byte and 8-byte arithmetic must not share a name: {lf:#?}"
        );
    }

    #[test]
    fn width_neutral_moves_do_not_block_phi_coalescing() {
        let mut widths = HashMap::from([(VReg::phys("rax#1"), 4u8), (VReg::phys("rax#2"), 8u8)]);
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::phys("rax#1"),
                            src: Value::Const(1),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rax#2"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x1008,
                        op: Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        coalesce_phi_copies(
            &mut lf,
            &[(VReg::phys("rax#2"), VReg::phys("rax#1"))],
            &mut widths,
        );
        assert_eq!(
            register_copies(&lf),
            vec![("rcx".to_string(), "rax#1".to_string())],
            "storage-width-only moves must not split one value: {lf:#?}"
        );
        assert_eq!(widths.get(&VReg::phys("rax#1")), Some(&8));
    }

    #[test]
    fn an_explicit_widening_result_constrains_the_merged_declaration_width() {
        let widened = VReg::Temp(0);
        let value = VReg::phys("rax#1");
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::SExt {
                            dst: widened.clone(),
                            src: Value::Reg(VReg::phys("eax")),
                            from: crate::ir::types::Width::W32,
                            to: crate::ir::types::Width::W64,
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: value.clone(),
                            src: Value::Reg(widened.clone()),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let claims = coalescing_definition_claims(
            &lf,
            &HashMap::from([(widened, 8), (value.clone(), 8)]),
            &DefinitionWidthsBySite::from([
                (
                    InstrAddr {
                        block_idx: 0,
                        instr_idx: 0,
                    },
                    8,
                ),
                (
                    InstrAddr {
                        block_idx: 0,
                        instr_idx: 1,
                    },
                    8,
                ),
            ]),
        );

        assert_eq!(
            claims.get(&value),
            Some(&ClassWidth::Known(8)),
            "assigning a sign-extended long through an int declaration would truncate it"
        );
    }

    #[test]
    fn a_late_phi_snapshot_does_not_merge_a_consumed_live_in_with_scratch_state() {
        let mut widths = HashMap::new();
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1008,
                    instrs: vec![
                        // The ABI value has already served its source-level role.
                        LlirInstr {
                            va: 0x1000,
                            op: Op::Bin {
                                dst: VReg::Temp(0),
                                op: crate::ir::types::BinOp::Add,
                                lhs: Value::Reg(VReg::phys("rdi")),
                                rhs: Value::Const(0),
                            },
                        },
                        // A later synthetic snapshot must not make unrelated
                        // scratch state one long-lived source variable.
                        LlirInstr {
                            va: 0x1004,
                            op: Op::Assign {
                                dst: VReg::phys("rdi#3"),
                                src: Value::Reg(VReg::phys("rdi")),
                            },
                        },
                    ],
                    succs: vec![2],
                },
                LlirBlock {
                    start_va: 0x1010,
                    end_va: 0x1018,
                    instrs: vec![
                        LlirInstr {
                            va: 0x1010,
                            op: Op::Assign {
                                dst: VReg::phys("rdi#2"),
                                src: Value::Const(7),
                            },
                        },
                        LlirInstr {
                            va: 0x1014,
                            op: Op::Assign {
                                dst: VReg::phys("rdi#3"),
                                src: Value::Reg(VReg::phys("rdi#2")),
                            },
                        },
                    ],
                    succs: vec![2],
                },
                LlirBlock {
                    start_va: 0x1020,
                    end_va: 0x1024,
                    instrs: vec![LlirInstr {
                        va: 0x1020,
                        op: Op::Nop,
                    }],
                    succs: vec![],
                },
            ],
        };
        let copies = vec![
            (VReg::phys("rdi#3"), VReg::phys("rdi")),
            (VReg::phys("rdi#3"), VReg::phys("rdi#2")),
        ];

        coalesce_phi_copies(&mut lf, &copies, &mut widths);

        assert!(
            register_copies(&lf).contains(&("rdi#3".to_string(), "rdi#2".to_string())),
            "a consumed live-in must keep the later scratch phi class separate: {lf:#?}"
        );
    }

    #[test]
    fn an_unread_live_in_does_not_merge_with_later_scratch_state() {
        let mut widths = HashMap::new();
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#3"),
                            src: Value::Reg(VReg::phys("rcx")),
                        },
                    }],
                    succs: vec![2],
                },
                LlirBlock {
                    start_va: 0x1010,
                    end_va: 0x1018,
                    instrs: vec![
                        LlirInstr {
                            va: 0x1010,
                            op: Op::Assign {
                                dst: VReg::phys("rcx#2"),
                                src: Value::Const(7),
                            },
                        },
                        LlirInstr {
                            va: 0x1014,
                            op: Op::Assign {
                                dst: VReg::phys("rcx#3"),
                                src: Value::Reg(VReg::phys("rcx#2")),
                            },
                        },
                    ],
                    succs: vec![2],
                },
                LlirBlock {
                    start_va: 0x1020,
                    end_va: 0x1024,
                    instrs: vec![LlirInstr {
                        va: 0x1020,
                        op: Op::Nop,
                    }],
                    succs: vec![],
                },
            ],
        };
        let copies = vec![
            (VReg::phys("rcx#3"), VReg::phys("rcx")),
            (VReg::phys("rcx#3"), VReg::phys("rcx#2")),
        ];

        coalesce_phi_copies(&mut lf, &copies, &mut widths);

        assert!(
            register_copies(&lf).contains(&("rcx#3".to_string(), "rcx#2".to_string())),
            "an unproven version-zero value is undefined, not a parameter: {lf:#?}"
        );
    }

    #[test]
    fn a_live_in_reached_through_a_read_phi_coalesces_with_its_loop_carrier() {
        let carrier = VReg::phys("rdi#1");
        let next = VReg::phys("rdi#2");
        let mut widths = HashMap::from([(next.clone(), 8)]);
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1008,
                    instrs: vec![
                        LlirInstr {
                            va: 0x1000,
                            op: Op::Bin {
                                dst: VReg::Temp(1),
                                op: crate::ir::types::BinOp::Add,
                                lhs: Value::Reg(VReg::phys("rdi")),
                                rhs: Value::Const(0),
                            },
                        },
                        LlirInstr {
                            va: 0x1004,
                            op: Op::Assign {
                                dst: carrier.clone(),
                                src: Value::Reg(VReg::phys("rdi")),
                            },
                        },
                    ],
                    succs: vec![0x1010],
                },
                LlirBlock {
                    start_va: 0x1010,
                    end_va: 0x1020,
                    instrs: vec![
                        LlirInstr {
                            va: 0x1010,
                            op: Op::Load {
                                dst: VReg::Temp(0),
                                addr: crate::ir::types::MemOp {
                                    base: Some(carrier.clone()),
                                    index: None,
                                    scale: 1,
                                    disp: 0,
                                    size: 1,
                                    ..Default::default()
                                },
                            },
                        },
                        LlirInstr {
                            va: 0x1014,
                            op: Op::Bin {
                                dst: next.clone(),
                                op: crate::ir::types::BinOp::Add,
                                lhs: Value::Reg(carrier.clone()),
                                rhs: Value::Const(1),
                            },
                        },
                        LlirInstr {
                            va: 0x1018,
                            op: Op::Assign {
                                dst: carrier.clone(),
                                src: Value::Reg(next.clone()),
                            },
                        },
                    ],
                    succs: vec![0x1010],
                },
            ],
        };
        let copies = vec![
            (carrier.clone(), VReg::phys("rdi")),
            (carrier.clone(), next.clone()),
        ];

        coalesce_phi_copies(&mut lf, &copies, &mut widths);

        assert!(
            !register_copies(&lf).contains(&("rdi#1".to_string(), "rdi#2".to_string())),
            "the bare live-in is genuinely consumed through the phi destination: {lf:#?}"
        );
    }

    /// A phi destination has no width of its own; it takes the one its incoming
    /// values agree on. When they disagree it is width-ambiguous, and the answer
    /// must not depend on which incoming edge is visited first — otherwise
    /// `factorial_while` (`mov eax,1` into the accumulator, `imul rax` out of it)
    /// stamps 4 bytes on a 64-bit product and returns 1.
    #[test]
    fn a_phi_width_is_decided_before_merging_not_by_visit_order() {
        let names = vec![
            VReg::phys("rax#3"), // the phi result — no recorded width
            VReg::phys("rax#1"), // `mov eax,1`
            VReg::phys("rax#2"), // `imul rax`
        ];
        let index: HashMap<VReg, usize> = names
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, v)| (v, i))
            .collect();
        let mut claims = HashMap::new();
        claims.insert(VReg::phys("rax#1"), ClassWidth::Known(4));
        claims.insert(VReg::phys("rax#2"), ClassWidth::Known(8));
        let edge = |d: usize, s: usize| (names[d].clone(), names[s].clone());
        for copies in [vec![edge(0, 1), edge(0, 2)], vec![edge(0, 2), edge(0, 1)]] {
            let decided = class_widths(&names, &index, &copies, &claims, &HashSet::new());
            assert_eq!(
                decided[0],
                ClassWidth::Ambiguous,
                "a 4-byte and an 8-byte incoming value leave the phi ambiguous \
                 regardless of edge order: {copies:?}"
            );
            assert_eq!(decided[0].merge(decided[1]), None);
            assert_eq!(decided[0].merge(decided[2]), None);
        }

        // Kept-bare names can have several definitions. Their constraints are
        // joined while the defining operations are still visible, rather than
        // trusting whichever name-keyed width happened to be recorded last.
        let both = vec![edge(0, 1), (names[0].clone(), VReg::phys("rax"))];
        let mut with_bare = HashMap::new();
        with_bare.insert(VReg::phys("rax#1"), ClassWidth::Known(4));
        with_bare.insert(VReg::phys("rax"), ClassWidth::Ambiguous);
        let decided = class_widths(&names, &index, &both, &with_bare, &HashSet::new());
        assert_eq!(
            decided[0],
            ClassWidth::Ambiguous,
            "conflicting definitions of a kept-bare source must remain ambiguous"
        );
        let decided = class_widths_with_incoming_values(
            &names,
            &index,
            &both,
            &with_bare,
            &HashSet::new(),
            &[None, Some(4)],
        );
        assert_eq!(
            decided[0],
            ClassWidth::Known(4),
            "the exact definition reaching this bare phi edge must override the \
             ambiguity of unrelated definitions sharing its register spelling"
        );
        with_bare.insert(VReg::phys("rax"), ClassWidth::Known(4));
        let decided = class_widths(&names, &index, &both, &with_bare, &HashSet::new());
        assert_eq!(decided[0], ClassWidth::Known(4));
        // A live-in has no definition here at all, so this map says nothing
        // about it. Missing evidence is Open, not a contradiction: the phi may
        // take the width proved by its other incoming values. Interference is
        // responsible for keeping genuinely distinct loop-carried values apart;
        // using width ambiguity as that guard couples two unrelated proofs and
        // is what refuses ordinary parameter-fed phi webs at scale.
        with_bare.remove(&VReg::phys("rax"));
        let decided = class_widths(&names, &index, &both, &with_bare, &HashSet::new());
        assert_eq!(decided[0], ClassWidth::Known(4));

        // Agreement is what permits a merge, and it propagates through a chain of
        // phis — the nested-loop shape, where one carried value is copied once per
        // loop level.
        let chain = vec![
            VReg::phys("rax#4"), // outer phi
            VReg::phys("rax#5"), // inner phi, fed by the outer one
            VReg::phys("rax#1"),
        ];
        let chain_index: HashMap<VReg, usize> = chain
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, v)| (v, i))
            .collect();
        let mut agreed = HashMap::new();
        agreed.insert(VReg::phys("rax#1"), ClassWidth::Known(4));
        let decided = class_widths(
            &chain,
            &chain_index,
            &[
                (chain[0].clone(), chain[2].clone()),
                (chain[1].clone(), chain[0].clone()),
            ],
            &agreed,
            &HashSet::new(),
        );
        assert_eq!(decided[0], ClassWidth::Known(4));
        assert_eq!(
            decided[1],
            ClassWidth::Known(4),
            "a phi fed only by another phi must inherit its width, or nested \
             loops coalesce nothing"
        );
    }

    /// Kept-bare ABI names can have several machine definitions. Width evidence
    /// belongs to each definition site, not to the shared spelling: otherwise
    /// whichever definition was visited last is replayed for every operation and
    /// a genuinely mixed-width phi input looks safe to coalesce.
    #[test]
    fn kept_bare_definition_widths_are_not_collapsed_by_name() {
        let kept_bare = VReg::phys("rax");
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::ZExt {
                            dst: kept_bare.clone(),
                            src: Value::Const(1),
                            from: crate::ir::types::Width::W8,
                            to: crate::ir::types::Width::W32,
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::SExt {
                            dst: kept_bare.clone(),
                            src: Value::Const(-1),
                            from: crate::ir::types::Width::W32,
                            to: crate::ir::types::Width::W64,
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        // This is the lossy public compatibility map: the second insertion for
        // `rax` replaced the first. The claim collector must not use that one
        // entry as the width of both definitions.
        let name_widths = HashMap::from([(kept_bare.clone(), 8)]);
        let site_widths = DefinitionWidthsBySite::from([
            (
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 0,
                },
                4,
            ),
            (
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
                8,
            ),
        ]);

        let claims = coalescing_definition_claims(&lf, &name_widths, &site_widths);

        assert_eq!(
            claims.get(&kept_bare),
            Some(&ClassWidth::Ambiguous),
            "32- and 64-bit definitions sharing one bare name must remain distinct"
        );
    }

    /// Bare names are ABI identities (live-in parameters, the frame register,
    /// a kept return value). Coalescing must never move one.
    #[test]
    fn a_bare_name_is_never_coalesced() {
        let mut widths = HashMap::new();
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::phys("rax#1"),
                            src: Value::Reg(VReg::phys("rdi")),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        coalesce_phi_copies(
            &mut lf,
            &[(VReg::phys("rax#1"), VReg::phys("rdi"))],
            &mut widths,
        );
        assert!(
            register_copies(&lf).contains(&("rax#1".to_string(), "rdi".to_string())),
            "the live-in parameter must keep its own identity: {lf:#?}"
        );
    }

    #[test]
    fn real_gcc_o2_nested_loop_defines_every_loop_carried_register() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary nested-loop build directory");
        let source = tmp.path().join("03_loop_shapes.c");
        let binary = tmp.path().join("03_loop_shapes.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/03_loop_shapes.c"
                ))
            })
            .expect("write the real loop fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real loop fixture with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object = object::read::File::parse(data.as_slice()).expect("parse GCC ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("nested_carry"))
            .map(|symbol| symbol.address())
            .expect("exported nested_carry symbol");
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered nested_carry function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift nested_carry");
        let ssa = compute_ssa(&lifted);
        let numbered = value_number(&lifted, &ssa, CallConv::SysVAmd64);

        assert_eq!(
            undefined_reads(&numbered),
            Vec::<String>::new(),
            "a loop-carried phi read has no incoming edge definition; phis: {:#?}",
            ssa.phis
        );
    }

    #[test]
    fn real_gcc_o2_call_chain_keeps_the_iteration_value_at_the_call() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary call-shape build directory");
        let source = tmp.path().join("11_call_shapes.c");
        let binary = tmp.path().join("11_call_shapes.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/11_call_shapes.c"
                ))
            })
            .expect("write the real call-shape fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real call fixture with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object = object::read::File::parse(data.as_slice()).expect("parse GCC ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("call_chain_in_loop"))
            .map(|symbol| symbol.address())
            .expect("exported call_chain_in_loop symbol");
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered call_chain_in_loop function");
        let mut lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift call_chain_in_loop");
        crate::ir::abi::annotate_calls(&mut lifted, CallConv::SysVAmd64);
        let ssa = compute_ssa(&lifted);
        let numbered = value_number(&lifted, &ssa, CallConv::SysVAmd64);

        let first_call_argument = numbered
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .find_map(|instruction| match &instruction.op {
                Op::Call {
                    effects: Some(effects),
                    ..
                } => effects.args.first().cloned(),
                _ => None,
            })
            .expect("the loop must call signed_step with a first argument");
        assert_ne!(
            first_call_argument,
            VReg::phys("rdi"),
            "the loop call must not be frozen to the bare entry parameter"
        );
        let definitions = numbered
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .filter(|instruction| {
                def_uses(&instruction.op).0.as_ref() == Some(&first_call_argument)
            })
            .count();
        assert!(
            definitions >= 2,
            "the call argument needs an entry definition and a loop-carried \
             backedge definition, got {definitions}: {numbered:#?}"
        );
        assert_eq!(
            undefined_reads(&numbered),
            Vec::<String>::new(),
            "coalescing must not orphan the loop-carried call argument"
        );
    }

    #[test]
    fn a_merged_predicate_read_is_defined_on_every_path() {
        use crate::ir::types::{CmpOp, Flag};

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
        let zf_from = |value: i64| Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(value),
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                blk(
                    0x1000,
                    vec![Op::CondJump {
                        cond: VReg::Flag(Flag::C),
                        target: 0x1020,
                        inverted: false,
                    }],
                    vec![0x1010, 0x1020],
                ),
                blk(
                    0x1010,
                    vec![zf_from(0), Op::Jump { target: 0x1030 }],
                    vec![0x1030],
                ),
                blk(
                    0x1020,
                    vec![zf_from(1), Op::Jump { target: 0x1030 }],
                    vec![0x1030],
                ),
                blk(
                    0x1030,
                    vec![Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1050,
                        inverted: false,
                    }],
                    vec![0x1040, 0x1050],
                ),
                blk(0x1040, vec![Op::Return], vec![]),
                blk(0x1050, vec![Op::Return], vec![]),
            ],
        };
        let ssa = compute_ssa(&lf);
        assert!(
            ssa.phis.iter().any(|phi| phi.base == VReg::Flag(Flag::Z)),
            "fixture must place a ZF phi"
        );

        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        let defined: HashSet<VReg> = out
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .filter_map(|ins| def_uses(&ins.op).0)
            .collect();
        let undefined: Vec<VReg> = out
            .blocks
            .iter()
            .flat_map(|block| block.instrs.iter())
            .flat_map(|ins| def_uses(&ins.op).1)
            .filter(|used| {
                matches!(used, VReg::FlagValue { version, .. } if *version > 0)
                    && !defined.contains(used)
            })
            .collect();
        assert!(
            undefined.is_empty(),
            "merged predicate uses undefined SSA values: {undefined:?}"
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
            before,
            after,
            "an unread phi must not add copies:\n{:#?}",
            out.blocks
                .iter()
                .map(|b| b.instrs.iter().map(|i| &i.op).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
    }

    /// A predecessor with MORE THAN ONE successor — the critical edge.
    ///
    /// The copy lands at the end of a block that does not always continue to the
    /// merge, so on the bypassing path it executes an assignment the merge never
    /// reads. The correctness argument is that this is dead rather than wrong: the
    /// phi result is live only from the merge block down. This test states it as a
    /// property instead of a comment — every versioned read still has a definition,
    /// and the block's branch stays last.
    ///
    ///   b0 -> b1, b2
    ///   b1 -> b3, b4     <- CRITICAL: b1 feeds the merge b3 *and* bypasses to b4
    ///   b2 -> b3
    ///   b3 reads rbx (merge of b1's and b2's writes)
    ///   b4 reads rbx too, on the path that never went through b3
    #[test]
    fn a_critical_edge_predecessor_still_defines_the_phi_result() {
        use crate::ir::types::Flag;
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
        let cj = |t: u64| Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target: t,
            inverted: false,
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                blk(0x1000, vec![cj(0x1020)], vec![0x1010, 0x1020]),
                blk(
                    0x1010,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rbx"),
                            src: Value::Const(10),
                        },
                        cj(0x1040),
                    ],
                    vec![0x1030, 0x1040],
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
                blk(
                    0x1040,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rdx"),
                            src: Value::Reg(VReg::phys("rbx")),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        };
        let ssa = compute_ssa(&lf);
        assert!(!ssa.phis.is_empty(), "fixture must produce a phi");
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        assert_eq!(
            undefined_reads(&out),
            Vec::<String>::new(),
            "a critical-edge predecessor left the phi result undefined"
        );
        for (bi, b) in out.blocks.iter().enumerate() {
            if let Some(pos) = b
                .instrs
                .iter()
                .position(|i| matches!(i.op, Op::CondJump { .. } | Op::Jump { .. }))
            {
                assert_eq!(pos, b.instrs.len() - 1, "block {bi}: branch must stay last");
            }
        }
    }

    /// Two phis in the SAME merge block, on different registers, whose sources cross.
    ///
    /// Phi semantics are parallel, so emitting the copies sequentially is only sound
    /// if no phi's source is another phi's destination. The claim is that SSA
    /// guarantees this — destinations are versions fresh at the merge, sources come
    /// from strictly earlier definitions — but "guaranteed by construction" is the
    /// kind of claim that deserves a test rather than a paragraph. A swap
    /// (`rbx, rcx = rcx, rbx` across the arms) is the shape that would break it.
    #[test]
    fn two_crossing_phis_in_one_block_do_not_clobber_each_other() {
        use crate::ir::types::Flag;
        let blk = |va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va: va,
            end_va: va + 0x20,
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
        let mov = |d: &str, s: &str| Op::Assign {
            dst: VReg::phys(d),
            src: Value::Reg(VReg::phys(s)),
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                blk(
                    0x1000,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rbx"),
                            src: Value::Const(1),
                        },
                        Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Const(2),
                        },
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: 0x1020,
                            inverted: false,
                        },
                    ],
                    vec![0x1010, 0x1020],
                ),
                // then: swap them
                blk(
                    0x1010,
                    vec![mov("rbx", "rcx"), mov("rcx", "rbx")],
                    vec![0x1030],
                ),
                // else: swap them the other way
                blk(
                    0x1020,
                    vec![mov("rcx", "rbx"), mov("rbx", "rcx")],
                    vec![0x1030],
                ),
                blk(
                    0x1030,
                    vec![
                        Op::Bin {
                            dst: VReg::phys("rax"),
                            op: crate::ir::types::BinOp::Add,
                            lhs: Value::Reg(VReg::phys("rbx")),
                            rhs: Value::Reg(VReg::phys("rcx")),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        };
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        assert_eq!(
            undefined_reads(&out),
            Vec::<String>::new(),
            "crossing phis left a read undefined"
        );
        // No copy may read a name that a LATER copy in the same block defines —
        // that is precisely the sequentialisation hazard.
        for b in &out.blocks {
            let copies: Vec<(String, String)> = b
                .instrs
                .iter()
                .filter_map(|i| match &i.op {
                    Op::Assign {
                        dst: VReg::Phys(d),
                        src: Value::Reg(VReg::Phys(s)),
                    } => Some((d.clone(), s.clone())),
                    _ => None,
                })
                .collect();
            for (k, (_, src)) in copies.iter().enumerate() {
                for (dst_later, _) in &copies[k + 1..] {
                    assert_ne!(
                        src, dst_later,
                        "copy reads {src}, which a later copy in the same block \
                         overwrites — the parallel-phi swap hazard:\n{copies:?}"
                    );
                }
            }
        }
    }

    /// A phi on the RETURN register, whose versions `value_number` keeps bare.
    ///
    /// `tag_phys` collapses a kept-bare version to the plain register name, so a phi
    /// whose destination and source both collapse would emit `rax = rax`, and a
    /// chain of them could in principle form a cycle. The insertion skips
    /// `src == dst` for exactly this reason; this pins that no self-copy and no
    /// two-copy cycle survives.
    #[test]
    fn a_kept_bare_return_register_phi_emits_no_self_copy_or_cycle() {
        use crate::ir::types::Flag;
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
        // if (c) rax = 1; else rax = 2;  return rax;
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                blk(
                    0x1000,
                    vec![Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1020,
                        inverted: false,
                    }],
                    vec![0x1010, 0x1020],
                ),
                blk(
                    0x1010,
                    vec![Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Const(1),
                    }],
                    vec![0x1030],
                ),
                blk(
                    0x1020,
                    vec![Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Const(2),
                    }],
                    vec![0x1030],
                ),
                blk(0x1030, vec![Op::Return], vec![]),
            ],
        };
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);
        for b in &out.blocks {
            for i in &b.instrs {
                if let Op::Assign {
                    dst: VReg::Phys(d),
                    src: Value::Reg(VReg::Phys(s)),
                } = &i.op
                {
                    assert_ne!(d, s, "emitted a self-copy `{d} = {s}`");
                }
            }
        }
        assert_eq!(
            undefined_reads(&out),
            Vec::<String>::new(),
            "kept-bare return phi left a read undefined"
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
    fn single_output_intrinsic_uses_the_reaching_ssa_value() {
        let lf = mk(vec![
            Op::Load {
                dst: VReg::phys("s15"),
                addr: crate::ir::types::MemOp::plain(Some(VReg::phys("sp")), None, 0, 8, 4),
            },
            Op::Intrinsic {
                name: "vneg.f32".into(),
                ins: vec![Value::Reg(VReg::phys("s15"))],
                outs: vec![(VReg::phys("s15"), crate::ir::types::Width::W32)],
                reads_mem: false,
                writes_mem: false,
            },
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::Arm);

        assert_eq!(
            out.blocks[0].instrs[1].op,
            Op::Intrinsic {
                name: "vneg.f32".into(),
                ins: vec![Value::Reg(VReg::phys("s15#1"))],
                outs: vec![(VReg::phys("s15#2"), crate::ir::types::Width::W32)],
                reads_mem: false,
                writes_mem: false,
            }
        );
    }

    #[test]
    fn arm_float_result_that_reaches_return_keeps_its_abi_name() {
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("s0"),
                src: Value::Reg(VReg::phys("s15")),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::Arm);

        assert_eq!(
            out.blocks[0].instrs[0].op,
            Op::Assign {
                dst: VReg::phys("s0"),
                src: Value::Reg(VReg::phys("s15")),
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
    fn live_in_arg_slots_treats_zero_idiom_as_a_definition() {
        use crate::ir::types::BinOp;
        // Real GCC -O2 shape from `sum_to`: `xor edx, edx` establishes the
        // accumulator before a later block reads rdx. Although the generic
        // Bin op has two syntactic uses, this machine idiom is independent of
        // the incoming register and therefore cannot prove a third parameter.
        let lf = mk(vec![
            Op::Bin {
                op: BinOp::Xor,
                dst: VReg::phys("edx"),
                lhs: Value::Reg(VReg::phys("edx")),
                rhs: Value::Reg(VReg::phys("edx")),
            },
            Op::Bin {
                op: BinOp::Add,
                dst: VReg::phys("rax"),
                lhs: Value::Reg(VReg::phys("rdx")),
                rhs: Value::Const(1),
            },
        ]);

        let params = live_in_arg_slots_llir(&lf, CallConv::SysVAmd64);
        assert!(
            !params.contains(&2),
            "zero-initialized rdx is scratch, not a parameter: {:?}",
            params
        );
    }

    #[test]
    fn a_phi_copy_read_only_by_a_call_may_use_is_not_a_parameter() {
        use crate::ir::types::{CallTarget, MemOp};
        // The AArch64 `getconf` main shape, reduced. The entry block ends in a
        // call; `abi::annotate_calls` hangs x0..x7 on it as a may-use, so the
        // loop-header phi for x3 counts as READ and `insert_phi_copies`
        // materialises `x3#1 = x3` right there. x3 is only ever DEFINED (a load)
        // and then tested, so the function does not take a fourth argument —
        // the copy is SSA plumbing, not an architectural read.
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("x19#1"),
                src: Value::Reg(VReg::phys("x0")),
            },
            Op::Assign {
                dst: VReg::phys("x3#1"),
                src: Value::Reg(VReg::phys("x3")),
            },
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: Some(crate::ir::abi::call_effects(CallConv::Aarch64)),
            },
            Op::Load {
                dst: VReg::phys("w3#2"),
                addr: MemOp {
                    base: Some(VReg::phys("x21#1")),
                    index: None,
                    scale: 0,
                    disp: 64,
                    size: 4,
                    segment: None,
                    endian: crate::ir::types::Endian::Little,
                },
            },
            Op::Cmp {
                dst: VReg::phys("flags"),
                op: crate::ir::types::CmpOp::Ne,
                lhs: Value::Reg(VReg::phys("w3#2")),
                rhs: Value::Const(0),
            },
        ]);

        let params = live_in_arg_slots_llir(&lf, CallConv::Aarch64);
        assert!(
            params.contains(&0),
            "x0 is spilled by a real move and is a parameter: {params:?}"
        );
        assert!(
            !params.contains(&3),
            "x3's only version-zero read is a phi copy no real operand consumes: \
             {params:?}"
        );
    }

    #[test]
    fn a_phi_copy_a_real_operand_consumes_still_proves_a_parameter() {
        use crate::ir::types::{BinOp, CallTarget};
        // The same plumbing, but the phi destination is genuinely read: the
        // loop body adds it. Refusing the copy outright would DELETE a real
        // parameter, which is exactly as wrong as inventing one.
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("x3#1"),
                src: Value::Reg(VReg::phys("x3")),
            },
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: Some(crate::ir::abi::call_effects(CallConv::Aarch64)),
            },
            Op::Bin {
                op: BinOp::Add,
                dst: VReg::phys("x9#1"),
                lhs: Value::Reg(VReg::phys("x3#1")),
                rhs: Value::Const(1),
            },
        ]);

        let params = live_in_arg_slots_llir(&lf, CallConv::Aarch64);
        assert!(
            params.contains(&3),
            "the phi destination is added to, so x3 really is live-in: {params:?}"
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
