//! Contract tests for the MIR definedness query surface.
//!
//! These describe EPIC 5's minimum query surface from the consumer side:
//! `value_at`, `clobbers_between`, a reaching-definition set, and
//! `memory_version`. Every case either proves an exact state or names the
//! exact reason a proof failed — never a plausible guess.

use crate::core::binary::{Arch, Endianness, Format};
use crate::ir::types::{
    BinOp, CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value, Width,
};
use crate::program::image::ProgramImage;
use crate::target::TargetSpec;

use super::{
    lower_verified, lower_verified_with_image, ClobberAnswer, ClobberKind, Definition,
    DefinitionOracle, DefinitionState, MemoryDefinition, MemoryRegion, ProgramPoint, StorageId,
    UnknownReason,
};

fn function(blocks: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
    LlirFunction {
        entry_va: blocks.first().map_or(0, |block| block.0),
        blocks: blocks
            .into_iter()
            .map(|(start_va, ops, succs)| LlirBlock {
                start_va,
                end_va: start_va + 4 * ops.len() as u64,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(index, op)| LlirInstr {
                        va: start_va + 4 * index as u64,
                        op,
                    })
                    .collect(),
                succs,
            })
            .collect(),
    }
}

fn x86() -> TargetSpec {
    TargetSpec::from_image_metadata(Arch::X86_64, Endianness::Little, Format::ELF, false)
}

fn arm() -> TargetSpec {
    TargetSpec::from_image_metadata(Arch::ARM, Endianness::Little, Format::ELF, false)
}

fn x86_image() -> ProgramImage {
    ProgramImage::from_path(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"),
    )
    .expect("index real x86-64 ELF")
}

fn add(dst: &str, src: &str, constant: i64) -> Op {
    Op::Bin {
        dst: VReg::phys(dst),
        op: BinOp::Add,
        lhs: Value::Reg(VReg::phys(src)),
        rhs: Value::Const(constant),
    }
}

fn set(dst: &str, constant: i64) -> Op {
    Op::Assign {
        dst: VReg::phys(dst),
        src: Value::Const(constant),
    }
}

// ---------------------------------------------------------------- value_at --

#[test]
fn value_at_names_the_exact_definition_in_straight_line_code() {
    let llir = function(vec![(
        0x100,
        vec![set("rax", 1), add("rbx", "rax", 1)],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let defined = mir.instructions()[0].outputs[0];
    let storage = mir.value(defined).storage;

    assert_eq!(
        oracle.value_at(
            storage,
            ProgramPoint::after(&mir, mir.instructions()[0].id)
                .expect("point after the definition")
        ),
        DefinitionState::Exact(defined)
    );
    assert_eq!(
        oracle.value_at(
            storage,
            ProgramPoint::before(&mir, mir.instructions()[1].id).expect("point before the use")
        ),
        DefinitionState::Exact(defined)
    );
}

#[test]
fn value_at_before_any_definition_reports_no_mir_definition() {
    let llir = function(vec![(0x140, vec![set("rax", 1)], vec![])]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let storage = mir.value(mir.instructions()[0].outputs[0]).storage;
    assert_eq!(
        oracle.value_at(storage, ProgramPoint::block_entry(mir.entry)),
        DefinitionState::NoDefinition
    );
}

#[test]
fn value_at_a_diamond_join_is_the_merging_phi() {
    let llir = function(vec![
        (0x200, vec![Op::Nop], vec![0x210, 0x220]),
        (0x210, vec![set("rax", 1)], vec![0x230]),
        (0x220, vec![set("rax", 2)], vec![0x230]),
        (0x230, vec![add("rbx", "rax", 1)], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let join = &mir.instructions()[3];
    let reaching = mir.use_(join.uses[0]).value;
    let storage = mir.use_(join.uses[0]).storage;

    assert!(matches!(
        mir.value(reaching).definition,
        Definition::Phi { .. }
    ));
    assert_eq!(
        oracle.value_at(
            storage,
            ProgramPoint::before(&mir, join.id).expect("join point")
        ),
        DefinitionState::Exact(reaching)
    );
}

#[test]
fn value_at_a_conditional_definition_merges_the_untracked_live_in() {
    let llir = function(vec![
        (0x280, vec![Op::Nop], vec![0x290, 0x2a0]),
        (0x290, vec![set("rax", 1)], vec![0x2b0]),
        (0x2a0, vec![Op::Nop], vec![0x2b0]),
        (0x2b0, vec![add("rbx", "rax", 1)], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let join = mir.instructions().last().expect("join instruction");
    let phi = mir.use_(join.uses[0]).value;
    let set_value = mir.instructions()[1].outputs[0];

    assert_eq!(
        oracle.value_at(
            mir.use_(join.uses[0]).storage,
            ProgramPoint::before(&mir, join.id).expect("join point")
        ),
        DefinitionState::Exact(phi)
    );

    let reaching = oracle.reaching_definitions(join.uses[0]);
    assert!(reaching.is_complete(), "{reaching:#?}");
    assert!(reaching.definitions().contains(&set_value));
    assert!(
        reaching
            .definitions()
            .iter()
            .any(|value| matches!(mir.value(*value).definition, Definition::Input)),
        "the unconditional path must keep its explicit function input: {reaching:#?}"
    );
    assert_eq!(reaching.phis(), &[phi]);
}

#[test]
fn value_at_a_loop_header_is_the_loop_carried_phi() {
    let llir = function(vec![
        (0x300, vec![set("rax", 0)], vec![0x310]),
        (
            0x310,
            vec![Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("rax")),
            }],
            vec![0x320, 0x330],
        ),
        (0x320, vec![add("rax", "rax", 1)], vec![0x310]),
        (0x330, vec![Op::Return], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let header = &mir.instructions()[1];
    let phi = mir.use_(header.uses[0]).value;
    assert!(matches!(mir.value(phi).definition, Definition::Phi { .. }));
    assert_eq!(
        oracle.value_at(
            mir.use_(header.uses[0]).storage,
            ProgramPoint::before(&mir, header.id).expect("header point")
        ),
        DefinitionState::Exact(phi)
    );

    let reaching = oracle.reaching_definitions(header.uses[0]);
    assert!(reaching.is_complete(), "{reaching:#?}");
    assert_eq!(
        reaching.definitions().len(),
        2,
        "the initial and the loop-carried definitions both reach: {reaching:#?}"
    );
    assert!(reaching
        .definitions()
        .contains(&mir.instructions()[0].outputs[0]));
    assert!(reaching
        .definitions()
        .contains(&mir.instructions()[2].outputs[0]));
}

#[test]
fn value_at_irreducible_flow_still_resolves_to_one_phi() {
    let llir = function(vec![
        (0x380, vec![Op::Nop], vec![0x390, 0x3a0]),
        (0x390, vec![set("rax", 1)], vec![0x3a0]),
        (0x3a0, vec![add("rbx", "rax", 1)], vec![0x390, 0x3b0]),
        (0x3b0, vec![Op::Return], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let irreducible_use = mir.instructions()[2].uses[0];
    let phi = mir.use_(irreducible_use).value;
    assert!(matches!(mir.value(phi).definition, Definition::Phi { .. }));
    assert_eq!(
        oracle.value_at(
            mir.use_(irreducible_use).storage,
            ProgramPoint::before(&mir, mir.instructions()[2].id).expect("irreducible point")
        ),
        DefinitionState::Exact(phi)
    );
    let reaching = oracle.reaching_definitions(irreducible_use);
    assert!(reaching.is_complete(), "{reaching:#?}");
    assert!(reaching
        .definitions()
        .contains(&mir.instructions()[1].outputs[0]));
}

#[test]
fn value_at_after_an_unannotated_call_fails_closed() {
    let llir = function(vec![(
        0x400,
        vec![
            set("rax", 1),
            Op::Call {
                target: CallTarget::Direct(0x9000),
                effects: None,
            },
            add("rbx", "rax", 1),
        ],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let defined = mir.instructions()[0].outputs[0];
    let storage = mir.value(defined).storage;
    let call = mir.instructions()[1].id;

    // The raw SSA use edge still points at the pre-call value: the call declares
    // no register effect at all. The query must not repeat that claim.
    assert_eq!(mir.use_(mir.instructions()[2].uses[0]).value, defined);
    assert_eq!(
        oracle.value_at(
            storage,
            ProgramPoint::before(&mir, mir.instructions()[2].id).expect("post-call point")
        ),
        DefinitionState::Unknown(UnknownReason::OpaqueInstruction(call))
    );
}

#[test]
fn an_opaque_call_cannot_clobber_a_lifter_temporary() {
    let llir = function(vec![(
        0x440,
        vec![
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Const(1),
            },
            Op::Call {
                target: CallTarget::Direct(0x9000),
                effects: None,
            },
            Op::Bin {
                dst: VReg::phys("rbx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::Temp(0)),
                rhs: Value::Const(1),
            },
        ],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let temp = mir.instructions()[0].outputs[0];
    assert_eq!(
        oracle.value_at(
            mir.value(temp).storage,
            ProgramPoint::before(&mir, mir.instructions()[2].id).expect("post-call point")
        ),
        DefinitionState::Exact(temp),
        "a callee cannot write a register the machine does not have"
    );
}

#[test]
fn value_at_after_a_multi_output_intrinsic_names_each_declared_output() {
    let llir = function(vec![(
        0x480,
        vec![
            Op::Intrinsic {
                name: "two_results".into(),
                ins: vec![],
                outs: vec![
                    (VReg::phys("r0"), Width::W32),
                    (VReg::phys("r1"), Width::W32),
                ],
                reads_mem: false,
                writes_mem: false,
            },
            Op::Nop,
        ],
        vec![],
    )]);
    let mir = lower_verified(&llir, arm()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let intrinsic = &mir.instructions()[0];
    let point = ProgramPoint::after(&mir, intrinsic.id).expect("point after the intrinsic");
    for output in &intrinsic.outputs {
        assert_eq!(
            oracle.value_at(mir.value(*output).storage, point),
            DefinitionState::Exact(*output),
            "a declared intrinsic output is an exact, if unknown-valued, state"
        );
        assert!(matches!(
            oracle.definition(*output),
            Some(Definition::UnknownEffect { .. })
        ));
    }
}

#[test]
fn value_at_a_poisoned_storage_is_the_explicit_undef_value() {
    let llir = function(vec![(
        0x4c0,
        vec![
            Op::Undef {
                dst: VReg::phys("rax"),
                reason: "architecturally undefined".into(),
            },
            add("rbx", "rax", 1),
        ],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let poison = mir.instructions()[0].outputs[0];
    assert_eq!(
        oracle.value_at(
            mir.value(poison).storage,
            ProgramPoint::before(&mir, mir.instructions()[1].id).expect("use point")
        ),
        DefinitionState::Exact(poison)
    );
    assert!(matches!(
        oracle.definition(poison),
        Some(Definition::Undef { .. })
    ));
    assert!(!oracle.value_is_all_paths_defined(mir.instructions()[1].outputs[0]));
}

#[test]
fn value_at_in_an_unreachable_block_is_explicitly_unreachable() {
    let llir = function(vec![
        (0x500, vec![Op::Return], vec![]),
        (0x510, vec![set("rax", 1), add("rbx", "rax", 1)], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let orphan = &mir.instructions()[1];
    assert_eq!(
        oracle.value_at(
            mir.value(orphan.outputs[0]).storage,
            ProgramPoint::before(&mir, mir.instructions()[2].id).expect("unreachable point")
        ),
        DefinitionState::Unreachable
    );
}

#[test]
fn value_at_rejects_an_out_of_range_storage_and_point() {
    let llir = function(vec![(0x540, vec![set("rax", 1)], vec![])]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let storage = mir.value(mir.instructions()[0].outputs[0]).storage;
    let bad_storage = StorageId(mir.storages().len());
    let entry = ProgramPoint::block_entry(mir.entry);
    let past_the_end = ProgramPoint {
        block: mir.entry,
        index: 99,
    };

    assert_eq!(
        oracle.value_at(bad_storage, entry),
        DefinitionState::Unknown(UnknownReason::UnknownStorage(bad_storage))
    );
    assert_eq!(
        oracle.value_at(storage, past_the_end),
        DefinitionState::Unknown(UnknownReason::InvalidPoint(past_the_end))
    );
}

// -------------------------------------------------------- clobbers_between --

#[test]
fn clobbers_between_proves_an_undisturbed_value() {
    let llir = function(vec![
        (0x600, vec![set("rax", 1)], vec![0x610]),
        (0x610, vec![add("rbx", "rax", 1)], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let value = mir.instructions()[0].outputs[0];
    let from = ProgramPoint::after(&mir, mir.instructions()[0].id).expect("definition point");
    let to = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("use point");

    assert_eq!(
        oracle.clobbers_between(value, from, to),
        ClobberAnswer::None
    );
}

#[test]
fn clobbers_between_names_a_redefinition() {
    let llir = function(vec![(
        0x640,
        vec![set("rax", 1), set("rax", 2), add("rbx", "rax", 1)],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let value = mir.instructions()[0].outputs[0];
    let overwrite = &mir.instructions()[1];
    let from = ProgramPoint::after(&mir, mir.instructions()[0].id).expect("definition point");
    let to = ProgramPoint::before(&mir, mir.instructions()[2].id).expect("use point");

    assert_eq!(
        oracle.clobbers_between(value, from, to),
        ClobberAnswer::Clobbered(vec![ClobberKind::Definition {
            instruction: overwrite.id,
            value: overwrite.outputs[0],
        }])
    );
}

#[test]
fn clobbers_between_reports_an_unannotated_call_conservatively() {
    let llir = function(vec![(
        0x680,
        vec![
            set("rax", 1),
            Op::Call {
                target: CallTarget::Direct(0x9000),
                effects: None,
            },
            add("rbx", "rax", 1),
        ],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let value = mir.instructions()[0].outputs[0];
    let from = ProgramPoint::after(&mir, mir.instructions()[0].id).expect("definition point");
    let to = ProgramPoint::before(&mir, mir.instructions()[2].id).expect("use point");

    assert_eq!(
        oracle.clobbers_between(value, from, to),
        ClobberAnswer::Clobbered(vec![ClobberKind::Opaque {
            instruction: mir.instructions()[1].id,
        }])
    );
}

#[test]
fn clobbers_between_sees_a_loop_back_edge_rewrite() {
    let llir = function(vec![
        (0x6c0, vec![set("rax", 0)], vec![0x6d0]),
        (
            0x6d0,
            vec![Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("rax")),
            }],
            vec![0x6e0, 0x6f0],
        ),
        (0x6e0, vec![add("rax", "rax", 1)], vec![0x6d0]),
        (0x6f0, vec![Op::Return], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let initial = mir.instructions()[0].outputs[0];
    let from = ProgramPoint::after(&mir, mir.instructions()[0].id).expect("definition point");
    let to = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("header point");

    let ClobberAnswer::Clobbered(sites) = oracle.clobbers_between(initial, from, to) else {
        panic!("the back edge rewrites the storage");
    };
    assert!(
        sites.iter().any(|site| matches!(
            site,
            ClobberKind::Definition { instruction, .. } if *instruction == mir.instructions()[2].id
        )),
        "{sites:#?}"
    );
    assert!(
        sites
            .iter()
            .any(|site| matches!(site, ClobberKind::Phi { block, .. } if *block == mir.instructions()[1].block)),
        "the loop phi replaces the storage identity: {sites:#?}"
    );
}

#[test]
fn clobbers_between_fails_closed_without_a_path() {
    let llir = function(vec![
        (0x700, vec![set("rax", 1)], vec![0x710, 0x720]),
        (0x710, vec![Op::Nop], vec![0x730]),
        (0x720, vec![Op::Nop], vec![0x730]),
        (0x730, vec![add("rbx", "rax", 1)], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let value = mir.instructions()[0].outputs[0];
    let from = ProgramPoint::block_entry(mir.instructions()[2].block);
    let to = ProgramPoint::block_entry(mir.instructions()[1].block);

    assert_eq!(
        oracle.clobbers_between(value, from, to),
        ClobberAnswer::Unknown(UnknownReason::NoPath { from, to })
    );
}

#[test]
fn clobbers_between_refuses_a_value_that_does_not_hold_the_storage() {
    let llir = function(vec![(
        0x740,
        vec![set("rax", 1), add("rbx", "rax", 1)],
        vec![],
    )]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let value = mir.instructions()[0].outputs[0];
    let from = ProgramPoint::block_entry(mir.entry);
    let to = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("use point");

    assert_eq!(
        oracle.clobbers_between(value, from, to),
        ClobberAnswer::Unknown(UnknownReason::ValueNotHeldAtOrigin { value, at: from })
    );
}

// --------------------------------------------------- reaching-definition set --

#[test]
fn reaching_definitions_keep_a_poisoned_arm_in_the_proved_set() {
    let llir = function(vec![
        (0x780, vec![Op::Nop], vec![0x790, 0x7a0]),
        (0x790, vec![set("rax", 7)], vec![0x7b0]),
        (
            0x7a0,
            vec![Op::Undef {
                dst: VReg::phys("rax"),
                reason: "architecturally undefined".into(),
            }],
            vec![0x7b0],
        ),
        (0x7b0, vec![add("rbx", "rax", 1)], vec![]),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let merged = mir.instructions().last().expect("join").uses[0];
    let reaching = oracle.reaching_definitions(merged);

    assert!(reaching.is_complete(), "{reaching:#?}");
    assert_eq!(reaching.definitions().len(), 2, "{reaching:#?}");
    assert!(
        reaching.single().is_none(),
        "a two-element set is not one value"
    );
    assert!(reaching
        .definitions()
        .iter()
        .any(|value| matches!(mir.value(*value).definition, Definition::Undef { .. })));
    assert!(!oracle.all_paths_defined(merged));
}

#[test]
fn reaching_definitions_terminate_through_a_phi_cycle() {
    let llir = function(vec![
        (0x800, vec![set("rax", 0)], vec![0x810]),
        (0x810, vec![Op::Nop], vec![0x820, 0x830]),
        (0x820, vec![Op::Nop], vec![0x810]),
        (
            0x830,
            vec![Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("rax")),
            }],
            vec![],
        ),
    ]);
    let mir = lower_verified(&llir, x86()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let exit_use = mir.instructions().last().expect("exit copy").uses[0];
    let reaching = oracle.reaching_definitions(exit_use);
    assert!(reaching.is_complete(), "{reaching:#?}");
    assert_eq!(
        reaching.single(),
        Some(mir.instructions()[0].outputs[0]),
        "an empty loop body cannot invent a second definition: {reaching:#?}"
    );
}

#[test]
fn reaching_definitions_of_an_unknown_effect_stay_an_unknown_effect() {
    let llir = function(vec![(
        0x860,
        vec![
            Op::Intrinsic {
                name: "opaque".into(),
                ins: vec![],
                outs: vec![(VReg::phys("r0"), Width::W32)],
                reads_mem: false,
                writes_mem: false,
            },
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Reg(VReg::phys("r0")),
            },
        ],
        vec![],
    )]);
    let mir = lower_verified(&llir, arm()).expect("valid MIR");
    let oracle = DefinitionOracle::new(&mir);

    let reaching = oracle.reaching_definitions(mir.instructions()[1].uses[0]);
    assert_eq!(reaching.single(), Some(mir.instructions()[0].outputs[0]));
    assert!(matches!(
        oracle.definition(reaching.single().expect("single definition")),
        Some(Definition::UnknownEffect { .. })
    ));
}

// ----------------------------------------------------------- memory_version --

#[test]
fn memory_version_carries_a_store_state_to_a_later_load() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 8, 4);
    let llir = function(vec![(
        0x900,
        vec![
            Op::Store {
                addr: address.clone(),
                src: Value::Const(7),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: address,
            },
        ],
        vec![],
    )]);
    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified memory MIR");
    let oracle = DefinitionOracle::new(&mir);

    let store = mir.instructions()[0]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("heap store effect");
    let point = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("load point");

    assert_eq!(
        oracle.memory_version(MemoryRegion::HeapUnknown, point),
        DefinitionState::Exact(store.output.expect("store output"))
    );
}

#[test]
fn memory_version_advances_every_region_an_unproven_pointer_may_alias() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 8, 4);
    let llir = function(vec![(
        0x940,
        vec![
            Op::Store {
                addr: address.clone(),
                src: Value::Const(7),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: address,
            },
        ],
        vec![],
    )]);
    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified memory MIR");
    let oracle = DefinitionOracle::new(&mir);

    let point = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("load point");
    let heap = oracle
        .memory_version(MemoryRegion::HeapUnknown, point)
        .exact()
        .expect("heap state");
    let stack = oracle
        .memory_version(MemoryRegion::Stack, point)
        .exact()
        .expect("stack state");
    let read_only = oracle
        .memory_version(MemoryRegion::ReadOnlyImage, point)
        .exact()
        .expect("read-only image state");

    // The store's address is a bare pointer, so it may alias the frame. Each
    // region keeps its own identity while every mutable one advances.
    assert_ne!(heap, stack);
    assert_eq!(mir.memory_value(stack).region, MemoryRegion::Stack);
    assert!(
        matches!(
            oracle.memory_definition(stack),
            Some(MemoryDefinition::InstructionOutput { .. })
        ),
        "an unproven pointer store may alias the frame and must clobber it"
    );
    assert!(
        matches!(
            oracle.memory_definition(read_only),
            Some(MemoryDefinition::Entry { .. })
        ),
        "no store can advance non-writable image memory"
    );
}

#[test]
fn memory_version_leaves_the_heap_alone_for_a_proven_frame_store() {
    let llir = function(vec![(
        0x970,
        vec![
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, 8, 4),
                src: Value::Const(7),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, 8, 4),
            },
        ],
        vec![],
    )]);
    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified frame MIR");
    let oracle = DefinitionOracle::new(&mir);

    let point = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("load point");
    assert!(
        matches!(
            oracle.memory_definition(
                oracle
                    .memory_version(MemoryRegion::Stack, point)
                    .exact()
                    .expect("stack state")
            ),
            Some(MemoryDefinition::InstructionOutput { .. })
        ),
        "the proven frame store owns the stack state"
    );
    assert!(
        matches!(
            oracle.memory_definition(
                oracle
                    .memory_version(MemoryRegion::HeapUnknown, point)
                    .exact()
                    .expect("heap state")
            ),
            Some(MemoryDefinition::Entry { .. })
        ),
        "a proven frame store must not clobber unrelated pointer memory"
    );
}

#[test]
fn memory_version_at_a_join_is_the_memory_phi() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 0, 4);
    let llir = function(vec![
        (0x980, vec![Op::Nop], vec![0x990, 0x9a0]),
        (
            0x990,
            vec![Op::Store {
                addr: address.clone(),
                src: Value::Const(1),
            }],
            vec![0x9b0],
        ),
        (0x9a0, vec![Op::Nop], vec![0x9b0]),
        (
            0x9b0,
            vec![Op::Load {
                dst: VReg::phys("rax"),
                addr: address,
            }],
            vec![],
        ),
    ]);
    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified diamond MIR");
    let oracle = DefinitionOracle::new(&mir);

    let load = &mir.instructions()[3];
    let point = ProgramPoint::before(&mir, load.id).expect("join point");
    let state = oracle
        .memory_version(MemoryRegion::HeapUnknown, point)
        .exact()
        .expect("heap join state");

    assert!(matches!(
        oracle.memory_definition(state),
        Some(MemoryDefinition::Phi { .. })
    ));
}

#[test]
fn memory_version_after_an_unannotated_call_is_its_clobber() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 0, 8);
    let llir = function(vec![(
        0x9e0,
        vec![
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: None,
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: address,
            },
        ],
        vec![],
    )]);
    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified call MIR");
    let oracle = DefinitionOracle::new(&mir);

    let call = mir.instructions()[0]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("call heap clobber");
    let point = ProgramPoint::before(&mir, mir.instructions()[1].id).expect("load point");

    assert_eq!(
        oracle.memory_version(MemoryRegion::HeapUnknown, point),
        DefinitionState::Exact(call.output.expect("clobber output"))
    );
}

// --------------------------------------------------- real-binary properties --

/// Lower `main` from a real fixture and hold the query surface to its contract.
///
/// The invariant that matters is one-directional: a query may refuse to answer,
/// but it may never answer with a *different* value than the verified SSA edge
/// it is derived from. A wrong `Exact` is the failure mode every consumer of
/// this surface would silently inherit.
#[test]
fn real_functions_never_answer_with_the_wrong_value() {
    use std::path::Path;

    use crate::analysis::cfg::{analyze_functions_image_with_seeds, Budgets};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::target::TargetId;

    let fixtures = [
        (
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
            TargetId::X86_64,
        ),
        (
            "samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc",
            TargetId::Arm32,
        ),
    ];
    let budgets = Budgets {
        max_functions: 1,
        max_blocks: 256,
        max_instructions: 10_000,
        timeout_ms: 1_000,
        total_timeout_ms: 0,
    };

    for (path, expected_target) in fixtures {
        let image = ProgramImage::from_path(Path::new(path)).expect("index real fixture");
        assert_eq!(image.target().id(), expected_target);
        let main = image
            .defined_text_symbol_address("main")
            .map(|address| image.normalize_function_entry(address))
            .expect("fixture has main");
        let (functions, _) = analyze_functions_image_with_seeds(&image, &budgets, &[main]);
        let source = functions
            .iter()
            .find(|function| image.normalize_function_entry(function.entry_point.value) == main)
            .expect("discover main");
        let llir = lift_function_from_image(&image, source).expect("lift main");
        let mir = lower_verified_with_image(&llir, &image).expect("verify real MIR");
        let oracle = DefinitionOracle::new(&mir);

        let mut proved = 0usize;
        for use_ in mir.uses() {
            let instruction = &mir.instructions()[use_.instruction.0];
            if !mir.blocks()[instruction.block.0].reachable {
                continue;
            }
            let point = ProgramPoint::before(&mir, instruction.id).expect("use point");
            match oracle.value_at(use_.storage, point) {
                DefinitionState::Exact(value) => {
                    assert_eq!(
                        value, use_.value,
                        "value_at contradicted the verified use edge at {:#x}",
                        instruction.source_va
                    );
                    proved += 1;
                }
                DefinitionState::Unknown(UnknownReason::OpaqueInstruction(_)) => {}
                other => panic!(
                    "a reachable use at {:#x} resolved to {other:?}",
                    instruction.source_va
                ),
            }

            // Rule 6: the set is always provable, and never contains a phi.
            let reaching = oracle.reaching_definitions(use_.id);
            assert!(reaching.is_complete(), "{reaching:#?}");
            assert!(!reaching.definitions().is_empty(), "{reaching:#?}");
            for definition in reaching.definitions() {
                assert!(
                    !matches!(oracle.definition(*definition), Some(Definition::Phi { .. })),
                    "a reaching-definition root must not be a phi"
                );
            }

            // `clobbers_between` must agree with `value_at`: if the value is
            // proved undisturbed from its own definition, `value_at` must have
            // named it.
            if let Some(Definition::InstructionOutput { instruction, .. }) =
                oracle.definition(use_.value)
            {
                let from = ProgramPoint::after(&mir, *instruction).expect("definition point");
                if oracle.clobbers_between(use_.value, from, point) == ClobberAnswer::None {
                    assert_eq!(
                        oracle.value_at(use_.storage, point),
                        DefinitionState::Exact(use_.value),
                        "an unclobbered value must be the state at its use"
                    );
                }
            }
        }
        assert!(
            proved > 0,
            "{expected_target:?} main must prove at least one exact state"
        );

        // Every region's memory state is proved at every block entry.
        for block in mir.blocks().iter().filter(|block| block.reachable) {
            for region in [
                MemoryRegion::Stack,
                MemoryRegion::KnownGlobal,
                MemoryRegion::ReadOnlyImage,
                MemoryRegion::HeapUnknown,
                MemoryRegion::FullyUnknown,
            ] {
                let state = oracle.memory_version(region, ProgramPoint::block_entry(block.id));
                let value = state
                    .exact()
                    .unwrap_or_else(|| panic!("{region:?} at block {} was {state:?}", block.id.0));
                assert_eq!(mir.memory_value(value).region, region);
            }
        }
    }
}

// -------------------------------------------------------- exceptional flow --

/// A landing pad is reachable only because the LSDA proves the unwind edge.
///
/// This case was recorded as untestable — "LLIR has no exceptional-edge
/// representation yet". That was already false for MIR when it was written:
/// `analysis::exception::with_exceptional_successors` builds the augmented graph
/// from LSDA proof and `python_bindings::ir` hands *that* graph to SSA. What
/// still has no exceptional edges is the STRUCTURER — `ir::cfg_edges::classify`
/// runs with an empty proof set — which is a separate, open Phase 4 item. So the
/// oracle can be held to its contract across an unwind today.
///
/// The contrast is what the edge buys, and it is not the phi: a landing pad
/// already names the join as its successor, so the join merges two operands
/// either way, and the reaching set contains both either way. Without the proven
/// edge the pad has no PREDECESSOR — its block is unreachable and its operand is
/// a `Definition::Unreachable` root, a value no execution can produce. The edge
/// is what makes that root a real `InstructionOutput`. A consumer reading the
/// un-augmented answer would be told the handler is dead code.
///
/// The augmentation is block-granular: the exceptional successor leaves the
/// protected block at its end, so the operand contributed by the normal path is
/// that block's final definition. That is the graph SSA already consumes, and
/// pinning the query against it is the point.
#[test]
fn value_at_a_landing_pad_join_merges_the_lsda_proven_edge() {
    use crate::analysis::exception::{
        exceptional_edges, with_exceptional_successors, ExceptionAction, ExceptionCallSite,
    };

    let llir = function(vec![
        (
            0x500,
            vec![
                Op::Call {
                    target: CallTarget::Direct(0x9000),
                    effects: None,
                },
                set("rbx", 1),
            ],
            vec![0x530],
        ),
        (0x520, vec![set("rbx", 2)], vec![0x530]),
        (0x530, vec![add("rax", "rbx", 1)], vec![]),
    ]);
    let site = ExceptionCallSite {
        function_start: 0x500,
        protected_start: 0x500,
        protected_end: 0x508,
        landing_pad: 0x520,
        action: ExceptionAction::Catch,
        catch_type: None,
        type_info_location: None,
    };
    assert_eq!(
        exceptional_edges(&llir, std::slice::from_ref(&site))
            .into_iter()
            .collect::<Vec<_>>(),
        vec![(0x500, 0x520)],
        "the LSDA site must prove exactly one edge into the pad"
    );

    let handler_value = |mir: &super::MirFunction| {
        let instruction = mir
            .instructions()
            .iter()
            .find(|instruction| instruction.source_va == 0x520)
            .expect("handler instruction");
        (instruction.block, instruction.outputs[0])
    };

    // Without the edge nothing reaches the pad, so its definition is unreachable
    // and the join's phi merges a value no execution can produce.
    let normal = lower_verified(&llir, x86()).expect("valid MIR");
    let normal_oracle = DefinitionOracle::new(&normal);
    let (normal_block, normal_handler) = handler_value(&normal);
    assert!(
        !normal.blocks()[normal_block.0].reachable,
        "an un-augmented landing pad has no predecessor"
    );
    assert_eq!(
        normal.value(normal_handler).definition,
        Definition::Unreachable {
            block: normal_block
        }
    );
    let normal_join = normal.instructions().last().expect("join instruction");
    let normal_reaching = normal_oracle.reaching_definitions(normal_join.uses[0]);
    assert!(
        normal_reaching.definitions().contains(&normal_handler),
        "the operand is still merged — it is merely unproducible: {normal_reaching:#?}"
    );

    // With it, the handler is live and its definition must enter the set.
    let augmented = with_exceptional_successors(&llir, std::slice::from_ref(&site));
    let mir = lower_verified(&augmented, x86()).expect("valid MIR over the augmented graph");
    let oracle = DefinitionOracle::new(&mir);
    let (handler_block, handler) = handler_value(&mir);
    assert!(
        mir.blocks()[handler_block.0].reachable,
        "the proven unwind edge is the pad's only predecessor"
    );
    assert!(matches!(
        mir.value(handler).definition,
        Definition::InstructionOutput { .. }
    ));

    let join = mir.instructions().last().expect("join instruction");
    let phi = mir.use_(join.uses[0]).value;
    assert!(
        matches!(mir.value(phi).definition, Definition::Phi { .. }),
        "the landing pad must reach the join as a phi operand: {:#?}",
        mir.value(phi).definition
    );
    assert_eq!(
        oracle.value_at(
            mir.use_(join.uses[0]).storage,
            ProgramPoint::before(&mir, join.id).expect("join point")
        ),
        DefinitionState::Exact(phi)
    );

    let reaching = oracle.reaching_definitions(join.uses[0]);
    assert!(reaching.is_complete(), "{reaching:#?}");
    assert_eq!(reaching.phis(), &[phi]);
    assert!(
        !reaching
            .definitions()
            .iter()
            .any(|value| matches!(mir.value(*value).definition, Definition::Unreachable { .. })),
        "the proven edge must leave no unreachable root behind: {reaching:#?}"
    );
    let normal_path = mir
        .instructions()
        .iter()
        .find(|instruction| instruction.source_va == 0x504)
        .expect("protected definition")
        .outputs[0];
    assert!(
        reaching.definitions().contains(&handler),
        "the handler's definition must be in the reaching set: {reaching:#?}"
    );
    assert!(
        reaching.definitions().contains(&normal_path),
        "the normal path's definition must stay in the reaching set: {reaching:#?}"
    );
}
