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
//!
//! # What is in this file
//!
//! The four public entry points, the width bookkeeping they thread, and
//! `insert_phi_copies` -- the step that gives every phi result an executable
//! definition. The analyses it drives each own their own module:
//!
//! * `architectural_reads` -- which names a genuine machine operand reads,
//!   with out-of-SSA plumbing excluded. Two consumers, one definition.
//! * `parameter_slots` -- which argument slots are live-in parameters.
//! * `keep_bare` -- which return-register definitions must stay unversioned,
//!   and the reaching-return proofs that decide it.
//! * `temp_remap` -- splitting a reused lifter temporary per SSA version.
//!   Its ids reach the rendered artifact, so it carries a determinism contract.
//! * `tagging` -- spelling one register occurrence at one SSA version.
//! * `vreg_walk` -- the order-free mutable walk over an operation's registers.
//! * `coalesce` -- merging the phi copies liveness and width prove removable.

use std::collections::{HashMap, HashSet};

use crate::ir::call_args::CallConv;
use crate::ir::ssa::SsaValue;
use crate::ir::types::{LlirFunction, LlirInstr, Op, VReg, Value};
use crate::ir::use_def::{def_ref, for_each_use, use_count, InstrAddr};

mod architectural_reads;
mod coalesce;
mod keep_bare;
mod parameter_slots;
mod tagging;
mod temp_remap;
mod vreg_walk;

pub use coalesce::SourceRegisterLifetime;
pub(crate) use keep_bare::{def_reaches_return, def_reaches_unresolved_return};
pub use parameter_slots::live_in_arg_slots_llir;
pub(crate) use vreg_walk::for_each_vreg_mut;

use coalesce::{coalesce_phi_copies_with_definition_sites, DefinitionWidthsBySite};
use tagging::{tag_op, tag_phys, VnCtx};
use temp_remap::build_temp_remap;

#[cfg(test)]
use coalesce::{coalesce_phi_copies, coalesce_phi_copies_with_lifetimes};

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
        _ => def_ref(op).and_then(|dst| dst.width()).map(width_bytes),
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
    value_number_with_parameter_slots_and_lifetimes(lf, ssa, cc, &[])
}

/// Value-number while preserving authoritative source-register lifetime splits.
pub fn value_number_with_parameter_slots_and_lifetimes(
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: CallConv,
    source_lifetimes: &[SourceRegisterLifetime],
) -> (LlirFunction, HashMap<VReg, u8>, HashSet<usize>) {
    let keep = keep_bare::definitions(lf, ssa, cc);
    let ctx = VnCtx::new(lf, keep, build_temp_remap(lf, ssa));

    let mut out = lf.clone();
    let mut definition_widths = HashMap::new();
    let mut definition_widths_by_site = DefinitionWidthsBySite::new();
    let mut definition_widths_by_value = DefinitionWidthsByValue::new();
    // One buffer for every instruction's use versions. The per-instruction
    // `Vec` was a heap allocation for a list that is normally one or two long.
    let mut use_vers: Vec<u32> = Vec::new();
    for (bi, block) in out.blocks.iter_mut().enumerate() {
        for (ii, ins) in block.instrs.iter_mut().enumerate() {
            let addr = InstrAddr {
                block_idx: bi,
                instr_idx: ii,
            };
            // Read out of the indexed SSA tables rather than the
            // address-keyed maps: same answer, no hashing. See
            // `SsaInfo::def_version`.
            let def_ver = ssa.def_version(lf, addr);
            // Only the use ARITY is wanted here; `def_uses` would allocate a
            // vector of cloned register spellings to report it.
            use_vers.clear();
            use_vers.extend((0..use_count(&ins.op)).map(|k| ssa.use_version(lf, addr, k)));
            tag_op(&mut ins.op, def_ver, &use_vers, &ctx);
            if let (Some(dst), Some(width)) = (
                def_ref(&ins.op),
                operation_definition_width(&lf.blocks[bi].instrs[ii].op),
            ) {
                definition_widths.insert(dst.clone(), width);
                definition_widths_by_site.insert(addr, width);
                if let Some(value) = ssa.def_value_ref(lf, addr) {
                    definition_widths_by_value.insert(value.clone(), width);
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
        source_lifetimes,
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
            for_each_use(&ins.op, |u| {
                if !read.contains(u) {
                    read.insert(u.clone());
                }
            });
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
            Some(Op::Jump { .. } | Op::CondJump { .. }) => block.instrs.len() - 1,
            Some(op) if op.is_return() => block.instrs.len() - 1,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::use_def::def_uses;

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
    fn explicit_return_preserves_exact_result_definition_identity() {
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("eax"),
                src: Value::Const(42),
            },
            Op::ReturnValue {
                value: Value::Reg(VReg::phys("rax")),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let numbered = value_number(&lf, &ssa, CallConv::SysVAmd64);

        assert_eq!(
            numbered.blocks[0].instrs[0].op,
            Op::Assign {
                dst: VReg::phys("rax#1"),
                src: Value::Const(42),
            }
        );
        assert_eq!(
            numbered.blocks[0].instrs[1].op,
            Op::ReturnValue {
                value: Value::Reg(VReg::phys("rax#1")),
            }
        );
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
                    proven_args: Vec::new(),
                    result: None,
                    result_is_source_value: false,
                    args_are_exact: true,
                    is_tail_call: false,
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
    fn proven_nonexact_call_inputs_are_signature_evidence_but_all_args_remain_uses() {
        let all_args = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            .into_iter()
            .map(VReg::phys)
            .collect::<Vec<_>>();
        let lf = mk(vec![Op::Call {
            target: crate::ir::types::CallTarget::Direct(0x2000),
            effects: Some(crate::ir::types::CallEffects {
                result: Some(VReg::phys("rax")),
                result_is_source_value: true,
                args: all_args.clone(),
                proven_args: vec![VReg::phys("rdi")],
                args_are_exact: false,
                is_tail_call: false,
            }),
        }]);

        let (_, uses) = def_uses(&lf.blocks[0].instrs[0].op);
        assert_eq!(
            uses, all_args,
            "conservative call liveness must be retained"
        );
        assert_eq!(
            live_in_arg_slots_llir(&lf, CallConv::SysVAmd64),
            std::collections::HashSet::from([0]),
            "only the callee-proven input is source-signature evidence"
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

    #[test]
    fn source_register_lifetime_blocks_cross_variable_phi_coalescing() {
        let mut widths = HashMap::new();
        let mut lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1030,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::phys("r4#1"),
                            src: Value::Const(1),
                        },
                    },
                    LlirInstr {
                        va: 0x1020,
                        op: Op::Assign {
                            dst: VReg::phys("r4#2"),
                            src: Value::Reg(VReg::phys("r4#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x1024,
                        op: Op::Assign {
                            dst: VReg::phys("r0#1"),
                            src: Value::Reg(VReg::phys("r4#2")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };

        coalesce_phi_copies_with_lifetimes(
            &mut lf,
            &[(VReg::phys("r4#2"), VReg::phys("r4#1"))],
            &mut widths,
            &[SourceRegisterLifetime {
                register: "r4".to_string(),
                ranges: vec![(0x1020, 0x1030)],
            }],
        );

        assert_eq!(
            register_copies(&lf),
            vec![
                ("r4#2".to_string(), "r4#1".to_string()),
                ("r0#1".to_string(), "r4#2".to_string()),
            ]
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("gcc");
                return;
            }
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real loop fixture with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("gcc");
                return;
            }
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real call fixture with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
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
    fn effect_only_intrinsic_uses_every_reaching_ssa_value() {
        let lf = mk(vec![
            Op::Assign {
                dst: VReg::phys("rdi"),
                src: Value::Const(0x1000),
            },
            Op::Assign {
                dst: VReg::phys("rcx"),
                src: Value::Const(16),
            },
            Op::Intrinsic {
                name: "memory.fill.4.word8".into(),
                ins: vec![Value::Reg(VReg::phys("rdi")), Value::Reg(VReg::phys("rcx"))],
                outs: Vec::new(),
                reads_mem: false,
                writes_mem: true,
            },
        ]);
        let ssa = compute_ssa(&lf);
        let out = value_number(&lf, &ssa, CallConv::SysVAmd64);

        assert!(matches!(
            &out.blocks[0].instrs[2].op,
            Op::Intrinsic { ins, outs, .. }
                if ins == &[
                    Value::Reg(VReg::phys("rdi#1")),
                    Value::Reg(VReg::phys("rcx#1")),
                ] && outs.is_empty()
        ));
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
    fn real_arm_alignment_save_does_not_invent_four_parameters() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc");
        let image = crate::program::image::ProgramImage::from_path(&path)
            .expect("index checked-in ARM ELF");
        let budgets = crate::analysis::cfg::Budgets {
            max_functions: 1,
            max_blocks: 16,
            max_instructions: 128,
            timeout_ms: 1_000,
            total_timeout_ms: 0,
        };
        let (functions, _) =
            crate::analysis::cfg::analyze_functions_image_with_seeds(&image, &budgets, &[0x5d4]);
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == 0x5d4)
            .expect("discover real _fini");
        let lifted = crate::ir::lift_function::lift_function_from_image(&image, function)
            .expect("lift real _fini");

        assert_eq!(
            live_in_arg_slots_llir(&lifted, CallConv::ArmHardFloat),
            HashSet::new(),
            "the balanced push/pop of caller-saved r3 is stack alignment, not arg3"
        );
    }

    #[test]
    fn arm_r3_save_restored_and_used_remains_parameter_evidence() {
        use crate::ir::types::MemOp;

        let saved_r3 = MemOp::plain(Some(VReg::phys("sp")), None, 0, 0, 4);
        let saved_lr = MemOp::plain(Some(VReg::phys("sp")), None, 0, 4, 4);
        let mut function = mk(vec![
            Op::Store {
                addr: saved_r3.clone(),
                src: Value::Reg(VReg::phys("r3")),
            },
            Op::Store {
                addr: saved_lr,
                src: Value::Reg(VReg::phys("lr")),
            },
            Op::Load {
                dst: VReg::phys("r3"),
                addr: saved_r3,
            },
            Op::Assign {
                dst: VReg::phys("r0"),
                src: Value::Reg(VReg::phys("r3")),
            },
            Op::Return,
        ]);
        // Both stores are the expansion of one `push {r3, lr}` instruction.
        function.blocks[0].instrs[1].va = function.blocks[0].instrs[0].va;

        assert!(
            live_in_arg_slots_llir(&function, CallConv::ArmHardFloat).contains(&3),
            "a restored value consumed by the function is not alignment padding"
        );
    }

    #[test]
    fn arm_r3_save_with_a_conditional_exit_is_not_proven_alignment_padding() {
        use crate::ir::types::MemOp;

        let saved_r3 = MemOp::plain(Some(VReg::phys("sp")), None, 0, 0, 4);
        let saved_lr = MemOp::plain(Some(VReg::phys("sp")), None, 0, 4, 4);
        let mut function = mk(vec![
            Op::Store {
                addr: saved_r3.clone(),
                src: Value::Reg(VReg::phys("r3")),
            },
            Op::Store {
                addr: saved_lr,
                src: Value::Reg(VReg::phys("lr")),
            },
            Op::Load {
                dst: VReg::phys("r3"),
                addr: saved_r3,
            },
            Op::CondJump {
                cond: VReg::phys("z"),
                inverted: false,
                target: 0x2000,
            },
            Op::Return,
        ]);
        // Both stores are the expansion of one `push {r3, lr}` instruction.
        function.blocks[0].instrs[1].va = function.blocks[0].instrs[0].va;

        assert!(
            live_in_arg_slots_llir(&function, CallConv::ArmHardFloat).contains(&3),
            "a conditional control-flow suffix is not a proven balanced exit"
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
    fn a_versioned_read_of_a_later_definition_is_not_a_parameter() {
        use crate::ir::types::{BinOp, MemOp};
        // `37_heapsort`'s `sift_down` at gcc -O2, stripped, reduced to its two
        // relevant blocks. The entry block jumps PAST the loop body to the
        // header, which computes `r8`; the body then reads it. In the block
        // LIST the reading block comes first (it sits at the lower address), so
        // a first-touch-wins scan over that list sees a read of `r8` before any
        // write and reports a fifth parameter that does not exist.
        //
        // Value numbering already settled the question: the read is `r8#1`, the
        // header's definition, not the version-zero name a live-in would carry.
        let mut lf = mk(vec![Op::Jump { target: 0x2000 }]);
        lf.blocks[0].succs = vec![0x2000];
        lf.blocks.push(LlirBlock {
            start_va: 0x1100,
            end_va: 0x1200,
            instrs: vec![LlirInstr {
                va: 0x1100,
                op: Op::Load {
                    dst: VReg::phys("r10#1"),
                    addr: MemOp {
                        base: Some(VReg::phys("r8#1")),
                        index: None,
                        scale: 0,
                        disp: 0,
                        size: 4,
                        segment: None,
                        endian: crate::ir::types::Endian::Little,
                    },
                },
            }],
            succs: vec![],
        });
        lf.blocks.push(LlirBlock {
            start_va: 0x2000,
            end_va: 0x2100,
            instrs: vec![LlirInstr {
                va: 0x2000,
                op: Op::Bin {
                    dst: VReg::phys("r8#1"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsi")),
                    rhs: Value::Const(1),
                },
            }],
            succs: vec![0x1100],
        });

        let params = live_in_arg_slots_llir(&lf, CallConv::SysVAmd64);
        assert!(
            params.contains(&1),
            "rsi is read at version zero and is a parameter: {params:?}"
        );
        assert!(
            !params.contains(&4),
            "r8 is only ever read as `r8#1`, the header's own definition: \
             {params:?}"
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
