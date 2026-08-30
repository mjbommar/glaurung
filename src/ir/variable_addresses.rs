//! Machine addresses for a recovered stack variable, joined on STORAGE rather
//! than on name lineage.
//!
//! # Why this can exist when the AST cannot supply it
//!
//! Our AST carries no instruction origin: `lower_block` calls
//! `lower_op(&ins.op, ..)` and drops `ins.va`, and `ast::Function` keeps only
//! `entry_va`. That is a real blocker for a LINE map, which needs
//! AST-node-to-instruction lineage.
//!
//! It is not a blocker for a VARIABLE-to-address map, and conflating the two is
//! how this capability went unbuilt. A promoted stack local is minted from a
//! frame coordinate — `stack_locals` publishes `(base, disp)` per name in
//! [`StackLocalFacts::frame_coordinates`] — and the LLIR still holds, on every
//! instruction, both that coordinate (`MemOp { base, disp, .. }`) and the
//! machine address it came from (`LlirInstr::va`). The join is therefore on the
//! storage the analyst is actually naming, and needs no node identity, no
//! rename tracking, and no change to `Expr`/`Stmt`.
//!
//! dewolf and Reko emit this same shape — direct per-variable addresses with no
//! line map — and DecBench's ingest supports it: variable addresses are
//! filtered independently of line mappings and survive with none, and its
//! auditor counts `functions_with_direct_only_addresses` as a first-class
//! statistic.
//!
//! # Fail-closed rules
//!
//! Every rule below drops evidence rather than guessing, because a plausible
//! WRONG address is worse than no address: it is a real instruction start
//! inside the function, so it passes a consumer's validator and silently
//! mis-attributes the evidence to the wrong variable.
//!
//! 1. **Exact coordinate match only.** `(ssa_base(base), disp)` must equal the
//!    slot's published coordinate. No ranges, no nearest-match.
//! 2. **An indexed access is not this scalar.** `MemOp { index: Some(..) }` at a
//!    slot's coordinate is an element of an array that *starts* there, which is
//!    a different object from the slot the name denotes.
//! 3. **A coordinate shared by two names is withheld.** `frame_coordinates`
//!    already withholds a NAME reachable from two coordinates; this is the
//!    other direction, and it is not free — two promoted names can converge on
//!    one coordinate after later passes rename them.
//! 4. **No base, no claim.** `MemOp { base: None }` is an absolute address, not
//!    a frame slot.
//! 5. **A moving base names no fixed storage.** A coordinate `(base, disp)`
//!    denotes one location only while `base` holds the value it held when the
//!    slot was minted. A frame pointer does; a STACK pointer does not, and our
//!    lifter makes that visible: `push` decomposes into `rsp = rsp - 8` and
//!    `store [rsp + 0]` sharing one `va`, so a push through a function's
//!    `stack_top` slot at `(sp, 0)` matches its coordinate exactly while
//!    referring to entirely different bytes. Measured on real binaries: 17
//!    such matches in `hello-rust-debug`, 14 in `hello-rust-musl`, 3 in
//!    `test_mathlib`, every one of them a `push` or `pop`.
//!
//!    So an access is withheld when its own instruction redefines its base, and
//!    a function that does that anywhere loses ALL of its stack-pointer-based
//!    coordinates — one push invalidates every later `(sp, d)` in that
//!    function, not just the push's own. Frame-pointer bases are unaffected,
//!    which is where the evidence overwhelmingly is.
//!
//! # Where this produces evidence, and where it is silent
//!
//! Every claim below was validated address-by-address against a disassembler,
//! checking that each address is a real instruction start whose instruction
//! actually accesses that displacement. Measured 2026-08-29:
//!
//! | corpus | tool | addresses | wrong |
//! |---|---|---|---|
//! | 250 fixture binaries, all compilers and `-O` levels | objdump | 6,726 | 0 |
//! | 25 of those, re-run through a second disassembler | llvm-objdump | 661 (identical) | 0 |
//! | real Rust / Go / C executables | objdump | 1,519 | 0 |
//! | aarch64 `-O0` | aarch64 objdump | 102 | 0 |
//! | i386 `-O0` | objdump | 37 | 0 |
//! | 4 real Microsoft PE DLLs | llvm-objdump | 50 | 0 |
//! | Mach-O | llvm-objdump | 7 | 0 |
//!
//! Per-slot coverage on the fixture corpus: 287/374 slots at x86-64 gcc `-O0`
//! (77%), 496/576 at clang `-O0` (86%), 0/330 at gcc `-O2`.
//!
//! It is SILENT — never wrong — whenever `stack_locals` normalised the slot to
//! an ENTRY-RELATIVE frame while the machine addresses it through a live
//! register. Two configurations do this today:
//!
//! * **x86-64 at `-O2`**, where gcc omits the frame pointer: coordinates are
//!   `entry_rsp`-based, and `entry_rsp` never appears as an LLIR `MemOp` base
//!   because the machine only ever names `rsp`. Of 330 slots, 202 had no
//!   coordinate at all (withheld upstream as ambiguous) and the remaining 128
//!   were in the entry-relative space.
//! * **ARM32**, where the Thumb frame register is `r7` and locals sit at
//!   POSITIVE displacements from it, while the published coordinates are
//!   entry-relative and negative. Verified: LLIR shows `r7(+4 … +24)`,
//!   coordinates show `-12 … -36`.
//!
//! # An address can fall outside the function's reported `size`
//!
//! A function is not always contiguous. `cpp_exception.cold` is placed BELOW
//! its hot part, so an address that legitimately belongs to `cpp_exception`
//! lands outside `[entry_va, entry_va + size)` — measured, 2 of 6,726 addresses
//! over 250 fixture binaries. Those addresses are correct and are emitted; a
//! consumer that clamps to the contiguous extent will drop them, which loses
//! evidence but never mis-attributes any.
//!
//! Closing that gap needs a per-instruction stack-pointer delta over the LLIR
//! CFG — translating `rsp + d` to `entry_rsp + d'` through every push, call and
//! frame adjustment. That is a real analysis with real failure modes, and an
//! imprecise one would emit exactly the plausible-but-wrong address this module
//! exists to avoid. It is deliberately not attempted here; the slots simply
//! carry no addresses, which a consumer reads as "no evidence" rather than as
//! bad evidence.

use std::collections::{BTreeSet, HashMap};

use crate::ir::abi::ssa_base;
use crate::ir::types::{LlirFunction, MemOp, Op, VReg};

/// Every `MemOp` an op reads or writes through.
///
/// Exhaustive over the four `MemOp`-carrying variants rather than a wildcard,
/// so a fifth added later is a compile error here instead of silently
/// contributing no evidence.
fn mem_operands(op: &Op) -> Vec<&MemOp> {
    match op {
        Op::Load { addr, .. }
        | Op::CondLoad { addr, .. }
        | Op::Store { addr, .. }
        | Op::CondStore { addr, .. } => vec![addr],
        _ => Vec::new(),
    }
}

/// Registers that name the stack pointer, whose value moves within a function.
///
/// A frame pointer is deliberately absent: `rbp`/`x29`/`r7` are set once in the
/// prologue and constant thereafter, which is exactly what makes a coordinate
/// through one denote fixed storage.
fn is_stack_pointer(name: &str) -> bool {
    matches!(name, "rsp" | "esp" | "sp")
}

/// The physical register an op defines, unversioned.
fn defined_register(op: &Op) -> Option<String> {
    match crate::ir::use_def::def_uses(op).0 {
        Some(VReg::Phys(name)) => Some(ssa_base(&name).to_string()),
        _ => None,
    }
}

/// The frame coordinate an access denotes, or `None` when it does not denote
/// one unambiguously. See the module's fail-closed rules.
fn coordinate_of(addr: &MemOp) -> Option<(&str, i64)> {
    if addr.index.is_some() {
        return None;
    }
    // Only a physical register names a frame base. A `Temp` or a flag
    // reaching here is a computed address, not a slot coordinate.
    let VReg::Phys(base) = addr.base.as_ref()? else {
        return None;
    };
    Some((ssa_base(base), addr.disp))
}

/// Machine addresses per promoted stack-local name.
///
/// Keys are the promoted names `frame_coordinates` uses — the same keys
/// `recovered_variables` reports — so the caller joins by name with no further
/// mapping. A name with no surviving evidence is absent rather than present
/// with an empty list: absent means "we are not claiming", empty would mean
/// "we claim there are none".
pub fn stack_slot_addresses(
    lf: &LlirFunction,
    frame_coordinates: &HashMap<String, (String, i64)>,
) -> HashMap<String, Vec<u64>> {
    if frame_coordinates.is_empty() {
        return HashMap::new();
    }
    // Invert, and drop any coordinate two names share (rule 3).
    let mut owner: HashMap<(&str, i64), Option<&str>> = HashMap::new();
    for (name, (base, disp)) in frame_coordinates {
        owner
            .entry((ssa_base(base), *disp))
            .and_modify(|slot| *slot = None)
            .or_insert(Some(name.as_str()));
    }

    // Rule 5, first half: which machine instructions redefine the very base
    // they access through. `push` is `rsp = rsp - 8` and `store [rsp + 0]`
    // sharing one `va`, so both facts are visible at the same address.
    let mut self_modifying: BTreeSet<u64> = BTreeSet::new();
    let mut moving_sp_sites: BTreeSet<u64> = BTreeSet::new();
    let mut sp_access_span: Option<(u64, u64)> = None;
    for block in &lf.blocks {
        let mut defined_at: HashMap<u64, Vec<String>> = HashMap::new();
        for instr in &block.instrs {
            if let Some(register) = defined_register(&instr.op) {
                defined_at.entry(instr.va).or_default().push(register);
            }
        }
        for instr in &block.instrs {
            for addr in mem_operands(&instr.op) {
                let Some((base, _)) = coordinate_of(addr) else {
                    continue;
                };
                if defined_at
                    .get(&instr.va)
                    .is_some_and(|regs| regs.iter().any(|r| r == base))
                {
                    self_modifying.insert(instr.va);
                    if is_stack_pointer(base) {
                        moving_sp_sites.insert(instr.va);
                    }
                } else if is_stack_pointer(base) {
                    sp_access_span = Some(match sp_access_span {
                        None => (instr.va, instr.va),
                        Some((lo, hi)) => (lo.min(instr.va), hi.max(instr.va)),
                    });
                }
            }
        }
    }

    // Second half of rule 5: a stack pointer that moves only in the prologue
    // and epilogue leaves the body in ONE coordinate space, and every access
    // there agrees with the coordinate the slot was minted in. What breaks that
    // is a move BETWEEN two accesses -- an x86 `push` mid-function. So the test
    // is whether any moving site falls inside the span of sp-based accesses,
    // not whether one exists at all. AArch64's pre-indexed
    // `stp x29, x30, [sp, #-32]!` is a prologue site outside that span, and
    // treating it as disqualifying cost 235 of 242 correct addresses.
    let stack_pointer_moves = match sp_access_span {
        None => !moving_sp_sites.is_empty(),
        Some((lo, hi)) => moving_sp_sites.iter().any(|va| (lo..=hi).contains(va)),
    };

    let mut out: HashMap<String, BTreeSet<u64>> = HashMap::new();
    for block in &lf.blocks {
        for instr in &block.instrs {
            if self_modifying.contains(&instr.va) {
                continue;
            }
            for addr in mem_operands(&instr.op) {
                let Some(coordinate) = coordinate_of(addr) else {
                    continue;
                };
                if stack_pointer_moves && is_stack_pointer(coordinate.0) {
                    continue;
                }
                if let Some(Some(name)) = owner.get(&coordinate) {
                    out.entry((*name).to_string())
                        .or_default()
                        .insert(instr.va);
                }
            }
        }
    }
    out.into_iter()
        .map(|(name, vas)| (name, vas.into_iter().collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{Endian, LlirBlock, LlirInstr, Value};

    fn mem(base: Option<&str>, index: Option<&str>, disp: i64) -> MemOp {
        MemOp {
            base: base.map(|b| VReg::Phys(b.to_string())),
            index: index.map(|i| VReg::Phys(i.to_string())),
            scale: 0,
            disp,
            size: 4,
            segment: None,
            endian: Endian::Little,
        }
    }

    fn func(ops: Vec<(u64, Op)>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + ops.len() as u64 * 4,
                instrs: ops
                    .into_iter()
                    .map(|(va, op)| LlirInstr { va, op })
                    .collect(),
                succs: Vec::new(),
            }],
        }
    }

    fn coords(items: &[(&str, &str, i64)]) -> HashMap<String, (String, i64)> {
        items
            .iter()
            .map(|(n, b, d)| (n.to_string(), (b.to_string(), *d)))
            .collect()
    }

    /// The ordinary case: two accesses to `rbp-0x18` are two uses of the slot
    /// promoted from that coordinate.
    #[test]
    fn loads_and_stores_at_a_slots_coordinate_are_its_addresses() {
        let lf = func(vec![
            (
                0x1004,
                Op::Store {
                    addr: mem(Some("rbp"), None, -24),
                    src: Value::Const(0),
                },
            ),
            (
                0x100c,
                Op::Load {
                    dst: VReg::Phys("eax".into()),
                    addr: mem(Some("rbp"), None, -24),
                },
            ),
        ]);
        let got = stack_slot_addresses(&lf, &coords(&[("local_18", "rbp", -24)]));
        assert_eq!(got.get("local_18"), Some(&vec![0x1004, 0x100c]));
    }

    /// SSA versioning is spelling, not identity -- `rbp#3` is `rbp`.
    #[test]
    fn an_ssa_versioned_base_still_matches() {
        let lf = func(vec![(
            0x1004,
            Op::Load {
                dst: VReg::Phys("eax".into()),
                addr: mem(Some("rbp#3"), None, -24),
            },
        )]);
        let got = stack_slot_addresses(&lf, &coords(&[("local_18", "rbp", -24)]));
        assert_eq!(got.get("local_18"), Some(&vec![0x1004]));
    }

    /// An element of an array that STARTS at the slot is a different object
    /// from the scalar the name denotes.
    #[test]
    fn an_indexed_access_is_not_the_scalar_slot() {
        let lf = func(vec![(
            0x1004,
            Op::Load {
                dst: VReg::Phys("eax".into()),
                addr: mem(Some("rbp"), Some("rax"), -24),
            },
        )]);
        assert!(stack_slot_addresses(&lf, &coords(&[("local_18", "rbp", -24)])).is_empty());
    }

    /// A different displacement, or a different base, is different storage.
    /// `rbp-0x18` and `entry_rsp-0x18` are the case this exists for.
    #[test]
    fn a_different_coordinate_does_not_match() {
        let lf = func(vec![
            (
                0x1004,
                Op::Load {
                    dst: VReg::Phys("eax".into()),
                    addr: mem(Some("rbp"), None, -20),
                },
            ),
            (
                0x1008,
                Op::Load {
                    dst: VReg::Phys("eax".into()),
                    addr: mem(Some("entry_rsp"), None, -24),
                },
            ),
        ]);
        assert!(stack_slot_addresses(&lf, &coords(&[("local_18", "rbp", -24)])).is_empty());
    }

    /// Two names on one coordinate cannot be told apart, so neither is claimed.
    /// `frame_coordinates` withholds a name reachable from two coordinates;
    /// this is the other direction and is not covered by that rule.
    #[test]
    fn a_coordinate_two_names_share_is_withheld() {
        let lf = func(vec![(
            0x1004,
            Op::Load {
                dst: VReg::Phys("eax".into()),
                addr: mem(Some("rbp"), None, -24),
            },
        )]);
        let got = stack_slot_addresses(
            &lf,
            &coords(&[("local_18", "rbp", -24), ("alias_18", "rbp", -24)]),
        );
        assert!(got.is_empty(), "{got:?}");
    }

    /// An absolute address is not a frame slot.
    #[test]
    fn a_baseless_access_claims_nothing() {
        let lf = func(vec![(
            0x1004,
            Op::Load {
                dst: VReg::Phys("eax".into()),
                addr: mem(None, None, -24),
            },
        )]);
        assert!(stack_slot_addresses(&lf, &coords(&[("local_18", "rbp", -24)])).is_empty());
    }

    /// Absent, not empty: a name with no evidence is one we are not claiming
    /// about, which is a different statement from "it has no addresses".
    #[test]
    fn a_slot_with_no_access_is_absent_rather_than_empty() {
        let lf = func(vec![(
            0x1004,
            Op::Load {
                dst: VReg::Phys("eax".into()),
                addr: mem(Some("rbp"), None, -8),
            },
        )]);
        let got = stack_slot_addresses(
            &lf,
            &coords(&[("local_8", "rbp", -8), ("local_18", "rbp", -24)]),
        );
        assert!(got.contains_key("local_8"));
        assert!(!got.contains_key("local_18"));
    }

    /// One machine instruction can expand into several LLIR ops sharing a `va`;
    /// the consumer wants a set of instruction addresses, not a multiset.
    #[test]
    fn addresses_are_deduplicated_and_sorted() {
        let lf = func(vec![
            (
                0x1010,
                Op::Load {
                    dst: VReg::Phys("eax".into()),
                    addr: mem(Some("rbp"), None, -24),
                },
            ),
            (
                0x1004,
                Op::Store {
                    addr: mem(Some("rbp"), None, -24),
                    src: Value::Const(0),
                },
            ),
            (
                0x1004,
                Op::Load {
                    dst: VReg::Phys("edx".into()),
                    addr: mem(Some("rbp"), None, -24),
                },
            ),
        ]);
        assert_eq!(
            stack_slot_addresses(&lf, &coords(&[("s", "rbp", -24)])).get("s"),
            Some(&vec![0x1004, 0x1010])
        );
    }

    /// `push` is `rsp = rsp - 8` and `store [rsp + 0]` at ONE `va`, so it
    /// matches a `(sp, 0)` slot's coordinate exactly while referring to
    /// entirely different bytes. Measured on real binaries before this rule:
    /// 17 such matches in `hello-rust-debug`, 14 in `hello-rust-musl`.
    #[test]
    fn an_instruction_that_moves_its_own_base_claims_nothing() {
        let lf = func(vec![
            (
                0x1004,
                Op::Bin {
                    dst: VReg::Phys("rsp".into()),
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Value::Reg(VReg::Phys("rsp".into())),
                    rhs: Value::Const(8),
                },
            ),
            (
                0x1004,
                Op::Store {
                    addr: mem(Some("rsp"), None, 0),
                    src: Value::Const(7),
                },
            ),
        ]);
        assert!(stack_slot_addresses(&lf, &coords(&[("stack_top", "rsp", 0)])).is_empty());
    }

    /// A push ANYWHERE between two sp-based accesses shifts the storage the
    /// second one names, so neither is claimed -- not just the push itself.
    #[test]
    fn a_push_between_two_accesses_invalidates_both() {
        let lf = func(vec![
            (
                0x1000,
                Op::Load {
                    dst: VReg::Phys("rax".into()),
                    addr: mem(Some("rsp"), None, 8),
                },
            ),
            (
                0x1004,
                Op::Bin {
                    dst: VReg::Phys("rsp".into()),
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Value::Reg(VReg::Phys("rsp".into())),
                    rhs: Value::Const(8),
                },
            ),
            (
                0x1004,
                Op::Store {
                    addr: mem(Some("rsp"), None, 0),
                    src: Value::Const(7),
                },
            ),
            (
                0x1008,
                Op::Load {
                    dst: VReg::Phys("rdx".into()),
                    addr: mem(Some("rsp"), None, 8),
                },
            ),
        ]);
        assert!(stack_slot_addresses(&lf, &coords(&[("s", "rsp", 8)])).is_empty());
    }

    /// A stack pointer moved only in the PROLOGUE leaves the body in one
    /// coordinate space. AArch64's pre-indexed `stp x29, x30, [sp, #-32]!` is
    /// exactly this; treating it as disqualifying cost 235 of 242 correct
    /// addresses.
    #[test]
    fn a_prologue_only_adjustment_does_not_disqualify_the_body() {
        let lf = func(vec![
            (
                0x1000,
                Op::Bin {
                    dst: VReg::Phys("sp".into()),
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Value::Reg(VReg::Phys("sp".into())),
                    rhs: Value::Const(32),
                },
            ),
            (
                0x1000,
                Op::Store {
                    addr: mem(Some("sp"), None, 0),
                    src: Value::Const(0),
                },
            ),
            (
                0x1004,
                Op::Store {
                    addr: mem(Some("sp"), None, 28),
                    src: Value::Const(1),
                },
            ),
            (
                0x1008,
                Op::Load {
                    dst: VReg::Phys("w0".into()),
                    addr: mem(Some("sp"), None, 28),
                },
            ),
        ]);
        assert_eq!(
            stack_slot_addresses(&lf, &coords(&[("local_1c", "sp", 28)])).get("local_1c"),
            Some(&vec![0x1004, 0x1008])
        );
    }

    /// A FRAME pointer is set once and constant after, which is what makes a
    /// coordinate through one denote fixed storage. The rule must not punish it.
    #[test]
    fn a_frame_pointer_setup_does_not_disqualify_anything() {
        let lf = func(vec![
            (
                0x1000,
                Op::Assign {
                    dst: VReg::Phys("rbp".into()),
                    src: Value::Reg(VReg::Phys("rsp".into())),
                },
            ),
            (
                0x1004,
                Op::Store {
                    addr: mem(Some("rbp"), None, -24),
                    src: Value::Const(0),
                },
            ),
        ]);
        assert_eq!(
            stack_slot_addresses(&lf, &coords(&[("local_18", "rbp", -24)])).get("local_18"),
            Some(&vec![0x1004])
        );
    }

    #[test]
    fn no_coordinates_means_no_work_and_no_claims() {
        let lf = func(vec![(
            0x1004,
            Op::Load {
                dst: VReg::Phys("eax".into()),
                addr: mem(Some("rbp"), None, -24),
            },
        )]);
        assert!(stack_slot_addresses(&lf, &HashMap::new()).is_empty());
    }
}
