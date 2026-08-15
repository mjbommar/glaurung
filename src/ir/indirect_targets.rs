//! What a relocation proves about where a computed transfer goes.
//!
//! [`crate::ir::cfg_edges::TerminalKind::Indirect`] is documented as "a computed
//! transfer whose destinations were never recovered", and the health counter
//! built on it — `unresolved_indirect_edges` — is read as the number of places
//! the decompiler does not know where control goes. Measured over the gcc-O2
//! fixture corpus that reading was wrong by two orders of magnitude, and it was
//! wrong in one specific way: nearly every counted transfer reads a slot whose
//! contents a relocation names.
//!
//! Three shapes account for essentially all of it, and only the third is
//! genuinely unknown:
//!
//! * A PLT stub — `jmp *GOT[f]`. `.rela.plt` binds that slot to `f`. The
//!   destination is `f`, proven, not guessed.
//! * The `crtstuff` pair `deregister_tm_clones` / `register_tm_clones` —
//!   `mov rax, [GOT[_ITM_deregisterTMCloneTable]] ; test rax,rax ; je ; jmp *rax`.
//!   One load and one register hop, and `.rela.dyn` names the symbol at the far
//!   end.
//! * `.plt`'s header stub — `jmp *.got.plt[2]`, which the loader fills with
//!   `_dl_runtime_resolve`. **No relocation names it**, so nothing static can,
//!   and this module says so rather than inventing an answer.
//!
//! # Why the stored bytes are never the answer
//!
//! A GOT slot's link-time contents are whatever the linker left there — zero, or
//! the address of the lazy-binding trampoline. The loader overwrites it. Reading
//! those bytes and calling the result a destination is precisely the class of
//! error that had `lift_x86` lowering `call *(%rcx,%rax,8)` to a confident call
//! to address zero. So the *only* evidence admitted here is a relocation naming
//! a symbol at the place, which is [`crate::program::references::EvidenceSource::Relocation`]
//! at [`crate::program::references::Confidence::Proved`] — the one tier
//! [`crate::program::references::OperandRole::BranchTarget`] may act on without
//! the role itself having to vouch for it. Everything weaker leaves the transfer
//! exactly as unresolved as it was.
//!
//! # What is deliberately NOT resolved
//!
//! A table dispatch (`jmp *(%rdx,%rax,8)`) has a base and an index, so it names
//! no single place and gets no proof here. Recovering those is
//! [`crate::analysis::jump_table`]'s job, and when it declines the transfer stays
//! [`crate::ir::cfg_edges::TerminalKind::Indirect`] — design rule 8. This module
//! never converts an unproven transfer into a resolved one; it only stops
//! reporting a *proven* one as unresolved.

use std::collections::{BTreeMap, HashMap};

use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{LlirFunction, Op, Value};
use crate::ir::use_def::InstrAddr;

/// What is known about the destination of one computed transfer.
///
/// Absence from the map produced by [`resolve_indirect_jumps`] is the third
/// state and the default: nothing was proven, and the transfer keeps its
/// unresolved classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndirectDestination {
    /// A relocation binds the place this transfer reads to a named symbol, so
    /// control goes to that symbol. The frame is replaced; it does not come
    /// back here.
    Symbol(String),
    /// The transfer reads a fixed, statically known place that no relocation
    /// names. The *place* is recovered and its *contents* are not — a real
    /// distinction, because the everyday instance is `.got.plt[2]` holding the
    /// dynamic loader's resolver, which is understood rather than mysterious.
    UnnamedSlot(u64),
}

/// Prove, where a relocation allows it, the destination of every computed
/// transfer in `lf`.
///
/// Returns a map keyed by the virtual address of the `Op::IndirectJump`
/// instruction. `relocated_slots` maps a place to the symbol a relocation binds
/// there — see [`crate::program::image::ProgramImage::relocated_symbol_slots`].
/// A transfer with no entry in the result is one nothing proved anything about.
pub fn resolve_indirect_jumps(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    relocated_slots: &HashMap<u64, String>,
) -> BTreeMap<u64, IndirectDestination> {
    let mut out = BTreeMap::new();
    // Index every instruction-level SSA definition once. A value defined by a
    // phi has no defining instruction and so is deliberately absent: a target
    // merged from two paths is not one place, and this module proves places.
    let mut definitions: HashMap<SsaValue, InstrAddr> = HashMap::new();
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for instr_idx in 0..block.instrs.len() {
            let at = InstrAddr {
                block_idx,
                instr_idx,
            };
            for value in ssa.def_values(lf, at) {
                definitions.insert(value, at);
            }
        }
    }

    for (block_idx, block) in lf.blocks.iter().enumerate() {
        let Some(instr_idx) = block.instrs.len().checked_sub(1) else {
            continue;
        };
        let instr = &block.instrs[instr_idx];
        let Op::IndirectJump { target, .. } = &instr.op else {
            continue;
        };
        // Only a register target can be traced to a load. An immediate or a
        // memory target here would already be something else.
        if !matches!(target, Value::Reg(_)) {
            continue;
        }
        let at = InstrAddr {
            block_idx,
            instr_idx,
        };
        // Use 0 is the target: `use_def` reads the target before the optional
        // switch index, and this is the index that ordering guarantees.
        let Some(used) = ssa.use_value(lf, at, 0) else {
            continue;
        };
        let Some(&defined_at) = definitions.get(&used) else {
            continue;
        };
        let Some(definition) = lf
            .blocks
            .get(defined_at.block_idx)
            .and_then(|b| b.instrs.get(defined_at.instr_idx))
        else {
            continue;
        };
        let Op::Load { addr, .. } = &definition.op else {
            continue;
        };
        // A base or an index means the place is computed, not fixed: that is a
        // table dispatch, and it is not this module's to answer.
        if addr.base.is_some() || addr.index.is_some() {
            continue;
        }
        let Ok(place) = u64::try_from(addr.disp) else {
            continue;
        };
        out.insert(
            instr.va,
            match relocated_slots.get(&place) {
                Some(name) => IndirectDestination::Symbol(name.clone()),
                None => IndirectDestination::UnnamedSlot(place),
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, VReg};

    fn function(spec: &[(u64, Vec<Op>, Vec<u64>)]) -> LlirFunction {
        LlirFunction {
            entry_va: spec.first().map(|(va, _, _)| *va).unwrap_or(0),
            blocks: spec
                .iter()
                .map(|(va, ops, succs)| LlirBlock {
                    start_va: *va,
                    end_va: va + 0x10,
                    instrs: ops
                        .iter()
                        .cloned()
                        .enumerate()
                        .map(|(i, op)| LlirInstr {
                            va: va + i as u64,
                            op,
                        })
                        .collect(),
                    succs: succs.clone(),
                })
                .collect(),
        }
    }

    fn load(dst: &str, place: i64) -> Op {
        Op::Load {
            dst: VReg::phys(dst),
            addr: MemOp::plain(None, None, 1, place, 8),
        }
    }

    fn indirect(reg: &str) -> Op {
        Op::IndirectJump {
            target: Value::Reg(VReg::phys(reg)),
            index: None,
        }
    }

    fn resolve(lf: &LlirFunction, slots: &[(u64, &str)]) -> BTreeMap<u64, IndirectDestination> {
        let ssa = crate::ir::ssa::compute_ssa(lf);
        let map: HashMap<u64, String> = slots
            .iter()
            .map(|(place, name)| (*place, (*name).to_string()))
            .collect();
        resolve_indirect_jumps(lf, &ssa, &map)
    }

    /// The PLT stub shape: `endbr64 ; jmp *GOT[f]` lifts to a load from a fixed
    /// place followed by a register-indirect jump, and `.rela.plt` names `f`.
    #[test]
    fn a_plt_stub_reads_a_slot_a_relocation_names() {
        let lf = function(&[(0x1030, vec![load("t0", 0x3fd8), indirect("t0")], vec![])]);

        let resolved = resolve(&lf, &[(0x3fd8, "__cxa_finalize")]);

        assert_eq!(
            resolved.get(&0x1031),
            Some(&IndirectDestination::Symbol("__cxa_finalize".into())),
            "the relocation at the slot proves the destination: {resolved:?}"
        );
    }

    /// `deregister_tm_clones`: the load and the jump are in DIFFERENT blocks,
    /// with a null test between them. An intra-block scan finds nothing here,
    /// which is why this walks SSA rather than the preceding instruction.
    #[test]
    fn a_got_load_proves_a_jump_one_block_later() {
        let lf = function(&[
            (
                0x1063,
                vec![
                    load("rax", 0x3fe8),
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1078,
                        inverted: false,
                    },
                ],
                vec![0x106f, 0x1078],
            ),
            (0x106f, vec![indirect("rax")], vec![]),
            (0x1078, vec![Op::Return], vec![]),
        ]);

        let resolved = resolve(&lf, &[(0x3fe8, "_ITM_deregisterTMCloneTable")]);

        assert_eq!(
            resolved.get(&0x106f),
            Some(&IndirectDestination::Symbol(
                "_ITM_deregisterTMCloneTable".into()
            )),
            "the reaching definition is a block away: {resolved:?}"
        );
    }

    /// `.plt`'s header stub reads `.got.plt[2]`, which the loader fills with
    /// `_dl_runtime_resolve` and NO relocation names. The place is recovered and
    /// the contents are not, and saying so is the whole point of the second
    /// variant.
    #[test]
    fn a_slot_no_relocation_names_is_reported_as_a_slot_not_a_symbol() {
        let lf = function(&[(0x1020, vec![load("t0", 0x4010), indirect("t0")], vec![])]);

        let resolved = resolve(&lf, &[(0x3fd8, "__cxa_finalize")]);

        assert_eq!(
            resolved.get(&0x1021),
            Some(&IndirectDestination::UnnamedSlot(0x4010)),
            "an unrelocated slot names no symbol, and must not borrow another's: {resolved:?}"
        );
    }

    /// A table dispatch computes its place from a base and an index, so there is
    /// no single slot to prove. It must come back with NOTHING — inventing a
    /// destination from the base displacement is exactly the failure mode this
    /// module exists downstream of.
    #[test]
    fn a_table_dispatch_is_left_entirely_alone() {
        let lf = function(&[(
            0x1170,
            vec![
                Op::Load {
                    dst: VReg::phys("t0"),
                    addr: MemOp::plain(Some(VReg::phys("rdx")), Some(VReg::phys("rax")), 8, 0, 8),
                },
                indirect("t0"),
            ],
            vec![],
        )]);

        let resolved = resolve(&lf, &[(0, "wrong")]);

        assert!(
            resolved.is_empty(),
            "a computed place proves nothing: {resolved:?}"
        );
    }

    /// A jump through a register that no load defines proves nothing. The
    /// register here is a function's live-in, so there is no defining
    /// instruction at all.
    #[test]
    fn a_register_no_load_defines_proves_nothing() {
        let lf = function(&[(0x1000, vec![indirect("rax")], vec![])]);

        assert!(resolve(&lf, &[(0x3fd8, "f")]).is_empty());
    }

    /// The proof is a relocation, never the bytes at the place: an empty slot
    /// map must resolve NO symbol, however plausible the address looks.
    #[test]
    fn without_relocations_no_transfer_names_a_symbol() {
        let lf = function(&[(0x1030, vec![load("t0", 0x3fd8), indirect("t0")], vec![])]);

        let resolved = resolve(&lf, &[]);

        assert_eq!(
            resolved.get(&0x1031),
            Some(&IndirectDestination::UnnamedSlot(0x3fd8)),
            "no relocation, no symbol: {resolved:?}"
        );
    }

    // ---- on a real binary --------------------------------------------------

    /// The measurement this module was built from, as a test.
    ///
    /// Over a real dynamically linked ELF, count what the terminal census says
    /// about every computed transfer. Before this module the answer was
    /// "unresolved" for all of them; the corpus census that motivated the work
    /// put 98.8% of that count in three boilerplate shapes, two of which a
    /// relocation names outright. So the assertions are that the great majority
    /// now carry a proof, that at least one PLT import is named, and — the one
    /// that actually guards correctness — that nothing claims a symbol the
    /// relocation table does not list.
    #[test]
    fn a_real_elf_resolves_its_plt_transfers_and_invents_no_others() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::ir::cfg_edges::{classify_terminals_with_destinations, TerminalKind};
        use crate::program::image::ProgramImage;
        use std::path::Path;

        let path =
            Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
        if !path.exists() {
            return;
        }
        let image = ProgramImage::from_path(path).expect("the sample image parses");
        let slots = image.relocated_symbol_slots();
        assert!(
            !slots.is_empty(),
            "a dynamically linked ELF has relocated symbol slots"
        );

        let budgets = Budgets {
            max_functions: 256,
            max_blocks: 512,
            max_instructions: 40_000,
            timeout_ms: 4000,
            total_timeout_ms: 0,
        };
        let (funcs, _cg) = analyze_functions_bytes(image.bytes(), &budgets);

        let mut symbol = 0usize;
        let mut slot = 0usize;
        let mut unresolved = 0usize;
        let mut named: Vec<String> = Vec::new();
        for func in &funcs {
            let Ok(lf) = crate::ir::lift_function::lift_function_from_image(&image, func) else {
                continue;
            };
            let ssa = crate::ir::ssa::compute_ssa_for_target(&lf, *image.target());
            let destinations = resolve_indirect_jumps(&lf, &ssa, &slots);
            for destination in destinations.values() {
                if let IndirectDestination::Symbol(name) = destination {
                    named.push(name.clone());
                }
            }
            let index: HashMap<u64, usize> = lf
                .blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (b.start_va, i))
                .collect();
            let succs: Vec<Vec<usize>> = lf
                .blocks
                .iter()
                .map(|b| {
                    b.succs
                        .iter()
                        .filter_map(|va| index.get(va).copied())
                        .collect()
                })
                .collect();
            for row in classify_terminals_with_destinations(&lf, &succs, &destinations) {
                for edge in row {
                    match edge.kind {
                        TerminalKind::IndirectToSymbol => symbol += 1,
                        TerminalKind::IndirectThroughSlot => slot += 1,
                        TerminalKind::Indirect => unresolved += 1,
                        _ => {}
                    }
                }
            }
        }

        let total = symbol + slot + unresolved;
        assert!(
            total > 0,
            "the sample has computed transfers to classify at all"
        );
        assert!(
            symbol > 0,
            "no transfer resolved to a symbol over {total} computed transfers; \
             this binary's PLT stubs each read a relocated GOT slot"
        );
        // Every name claimed must be a name the relocation table actually lists.
        // A resolver that fabricates plausible symbols is far worse than one
        // that resolves nothing, so this is the assertion that matters.
        for name in &named {
            assert!(
                slots.values().any(|listed| listed == name),
                "{name:?} is not a symbol any relocation names"
            );
        }
        assert!(
            symbol + slot > unresolved,
            "proved {symbol} symbol and {slot} slot destinations but left \
             {unresolved} unaccounted — the boilerplate shapes should dominate"
        );
        eprintln!(
            "[indirect-census] symbol={symbol} slot={slot} unresolved={unresolved} \
             of {total} computed transfers"
        );
    }
}
