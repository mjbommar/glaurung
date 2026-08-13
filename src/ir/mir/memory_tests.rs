use crate::ir::types::{CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
use crate::program::image::ProgramImage;

use super::{
    lower_verified_with_image, verify, BlockId, DefinitionOracle, MemoryAccessId, MemoryAccessKind,
    MemoryDefinition, MemoryRegion,
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

fn x86_image() -> ProgramImage {
    ProgramImage::from_path(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"),
    )
    .expect("index real x86-64 ELF")
}

#[test]
fn verified_mir_carries_memory_versions_from_store_to_load() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 8, 4);
    let llir = function(vec![(
        0x0800,
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
    let store = mir.instructions()[0]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("heap store effect");
    let load = mir.instructions()[1]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("heap load effect");

    assert_eq!(store.region, MemoryRegion::HeapUnknown);
    assert_eq!(store.output, Some(load.input));
    assert!(matches!(
        mir.memory_value(load.input).definition,
        MemoryDefinition::InstructionOutput { .. }
    ));
    let oracle = DefinitionOracle::new(&mir);
    assert_eq!(oracle.memory_uses(load.input), &[load.id]);
    assert!(matches!(
        oracle.memory_definition(load.input),
        Some(MemoryDefinition::InstructionOutput { .. })
    ));
    assert!(verify(&mir).is_empty());
}

#[test]
fn verifier_rejects_a_memory_use_with_the_wrong_region() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 8, 4);
    let llir = function(vec![(
        0x0900,
        vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: address,
        }],
        vec![],
    )]);

    let image = x86_image();
    let mut mir = lower_verified_with_image(&llir, &image).expect("verified memory MIR");
    let access = *mir.instructions()[0]
        .memory_effects
        .iter()
        .find(|id| mir.memory_accesses()[id.0].region == MemoryRegion::HeapUnknown)
        .expect("heap read effect");
    mir.memory_access_mut_for_test(access).region = MemoryRegion::Stack;

    let errors = verify(&mir);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("memory region mismatch")),
        "unexpected verifier errors: {errors:#?}"
    );
}

#[test]
fn verifier_reports_an_invalid_memory_owner_without_panicking() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 8, 4);
    let llir = function(vec![(
        0x0980,
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
    let mut mir = lower_verified_with_image(&llir, &image).expect("verified memory MIR");
    let output = mir.instructions()[0]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .and_then(|access| access.output)
        .expect("heap store output");
    mir.memory_value_mut_for_test(output).definition = MemoryDefinition::InstructionOutput {
        access: MemoryAccessId(usize::MAX),
    };

    let errors = verify(&mir);
    assert!(
        errors.iter().any(|error| error.contains("orphaned")),
        "unexpected verifier errors: {errors:#?}"
    );
}

#[test]
fn memory_phi_owns_both_diamond_states_in_mir() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 0, 4);
    let llir = function(vec![
        (0x0a00, vec![Op::Nop], vec![0x0a10, 0x0a20]),
        (
            0x0a10,
            vec![Op::Store {
                addr: address.clone(),
                src: Value::Const(1),
            }],
            vec![0x0a30],
        ),
        (0x0a20, vec![Op::Nop], vec![0x0a30]),
        (
            0x0a30,
            vec![Op::Load {
                dst: VReg::phys("rax"),
                addr: address,
            }],
            vec![],
        ),
    ]);

    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified diamond MIR");
    let (phi_id, incoming) = mir
        .memory_values()
        .iter()
        .find_map(|value| match &value.definition {
            MemoryDefinition::Phi {
                block,
                region: MemoryRegion::HeapUnknown,
                incoming,
            } if *block == BlockId(3) => Some((value.id, incoming)),
            _ => None,
        })
        .expect("heap memory phi");
    let load = mir.instructions()[3]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("join heap load");

    assert_eq!(incoming.len(), 2);
    assert_eq!(load.input, phi_id);
    assert!(verify(&mir).is_empty());
}

#[test]
fn unknown_call_clobber_is_the_reaching_memory_definition() {
    let address = MemOp::plain(Some(VReg::phys("rbx")), None, 0, 0, 8);
    let llir = function(vec![(
        0x0b00,
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
    let call = mir.instructions()[0]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("call heap clobber");
    let load = mir.instructions()[1]
        .memory_effects
        .iter()
        .map(|id| &mir.memory_accesses()[id.0])
        .find(|access| access.region == MemoryRegion::HeapUnknown)
        .expect("heap load");

    assert_eq!(call.kind, MemoryAccessKind::Clobber);
    assert_eq!(call.output, Some(load.input));
    assert!(verify(&mir).is_empty());
}
