//! Spelling one register occurrence at one SSA version.
//!
//! Everything here answers a single question -- what does this register
//! operand render as, given the version SSA proved for it -- and the only
//! reason any of it changes is a change to that naming scheme or to the
//! `Op` set the traversal must cover.

use crate::ir::types::{LlirFunction, Op, VReg, Value};
use crate::ir::use_def::def_ref;

use super::keep_bare::KeepBare;
use super::temp_remap::TempRemap;

/// Immutable context threaded through the tagging recursion.
pub(crate) struct VnCtx {
    keep: KeepBare,
    temps: TempRemap,
    structural: Vec<&'static str>,
}

impl VnCtx {
    /// Assemble the tagging context for `lf`.
    ///
    /// The structural-register set is derived from `lf` rather than passed in:
    /// it is a property of this function's frame and has no other consumer.
    pub(crate) fn new(lf: &LlirFunction, keep: KeepBare, temps: TempRemap) -> Self {
        Self {
            keep,
            temps,
            structural: structural_registers(lf),
        }
    }
}

fn canonical_phys_name(name: &str) -> &str {
    crate::ir::ssa::parent64(name).unwrap_or(name)
}

/// Registers that genuinely establish this function's machine frame must keep
/// bare names so stack-slot promotion can recognise them.  A callee-saved frame
/// register is not automatically a frame pointer: optimized code may use `rbp`
/// as an ordinary loop value after saving it in the prologue.  In that case its
/// distinct writes need SSA names like every other data register.
fn structural_registers(lf: &LlirFunction) -> Vec<&'static str> {
    fn frame_family_is_structural(
        lf: &LlirFunction,
        frame_names: &[&str],
        stack_names: &[&str],
    ) -> bool {
        let mut saw_definition = false;
        for block in &lf.blocks {
            for instruction in &block.instrs {
                let Some(VReg::Phys(definition)) = def_ref(&instruction.op) else {
                    continue;
                };
                if !frame_names.contains(&canonical_phys_name(definition)) {
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

    // A list of static names, not a `HashSet<String>`: every member is a
    // literal, there are at most nine, and `tag_phys` asks whether a register is
    // structural once per operand — a scan of nine short strings beats hashing
    // one, and it drops the owned copies entirely.
    let mut structural: Vec<&'static str> = vec!["rsp", "esp", "sp"];
    if frame_family_is_structural(lf, &["rbp", "ebp", "bp"], &["rsp", "esp", "sp"]) {
        structural.extend(["rbp", "ebp", "bp"]);
    }
    if frame_family_is_structural(lf, &["x29", "w29", "fp"], &["sp"]) {
        structural.extend(["x29", "w29", "fp"]);
    }
    structural
}

/// The value-tagged name of a register at a given SSA version. Physical
/// registers get a `reg#version` name (version 0 / structural / kept-bare stay
/// bare); reused temporaries are remapped to their split id.
pub(crate) fn tag_phys(v: &mut VReg, version: u32, ctx: &VnCtx) {
    match v {
        VReg::Phys(n) => {
            // Canonicalize a GP sub-register to its 64-bit parent so a value
            // written as `%rax` and read back as `%eax` (or vice versa) renders
            // as ONE name at the shared SSA version — otherwise the two views get
            // distinct names and the read dangles.
            //
            // `parent64` returns a `&'static str`, so the canonical spelling
            // costs nothing to look at. Only the decision to REWRITE `n`
            // allocates: this used to build the canonical `String` (plus a
            // second copy as a `KeepBare` probe key) for every register
            // operand, including the common case where the register is already
            // canonical and stays bare, where nothing needed to be written.
            let parent = crate::ir::ssa::parent64(n);
            let canon: &str = parent.unwrap_or(n.as_str());
            let stays_bare = version == 0
                || ctx.structural.contains(&canon)
                || ctx.keep.contains(canon, version);
            let renamed = if stays_bare {
                // entry-def / live-in / structural / kept-bare: the canonical
                // spelling, which is already in place unless this is a
                // sub-register view.
                parent.map(str::to_string)
            } else {
                Some(format!("{canon}#{version}"))
            };
            if let Some(renamed) = renamed {
                *n = renamed;
            }
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
/// advancing the use cursor exactly as `def_uses` enumerated it.
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
pub(crate) fn tag_op(op: &mut Op, def_ver: u32, use_vers: &[u32], ctx: &VnCtx) {
    let mut ui = 0usize;
    match op {
        Op::Assign { dst, src } => {
            tag_value(src, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Undef { dst, .. } => tag_phys(dst, def_ver, ctx),
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
        Op::CondLoad {
            dst,
            cond,
            addr,
            fallback,
            ..
        } => {
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx);
            }
            ui = 1;
            tag_memop_uses(addr, use_vers, &mut ui, ctx);
            tag_value(fallback, use_vers, &mut ui, ctx);
            tag_phys(dst, def_ver, ctx);
        }
        Op::Store { addr, src } => {
            tag_memop_uses(addr, use_vers, &mut ui, ctx);
            tag_value(src, use_vers, &mut ui, ctx);
        }
        Op::CondStore {
            cond, addr, src, ..
        } => {
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx);
            }
            ui = 1;
            tag_memop_uses(addr, use_vers, &mut ui, ctx);
            tag_value(src, use_vers, &mut ui, ctx);
        }
        Op::CondJump { cond, .. } | Op::CondReturn { cond, .. } => {
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx);
            }
        }
        Op::CondReturnValue { cond, value, .. } => {
            if let Some(&ver) = use_vers.first() {
                tag_phys(cond, ver, ctx);
            }
            ui = 1;
            tag_value(value, use_vers, &mut ui, ctx);
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
        Op::ReturnValue { value } => tag_value(value, use_vers, &mut ui, ctx),
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
        // Effect-only and single-output intrinsics fit the ordinary SSA model
        // exactly. This includes memory effects such as `memory.fill` and
        // scalar VFP operations such as `vneg s15, s15`; tagging every input is
        // what connects each use to its reaching definition.
        Op::Intrinsic { ins, outs, .. } if outs.len() <= 1 => {
            for input in ins {
                tag_value(input, use_vers, &mut ui, ctx);
            }
            if let Some((output, _)) = outs.first_mut() {
                tag_phys(output, def_ver, ctx);
            }
        }
        // Multi-output intrinsics (`cpuid`, ...) don't fit the single-def SSA
        // model cleanly, so leave them untagged for now.
        Op::Intrinsic { .. } | Op::Jump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => {}
    }
}
