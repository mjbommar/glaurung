use crate::ir::types::{CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
use crate::program::image::ProgramImage;
use crate::program::types::{
    ObjectTypeKey, TypeAuthority, TypeEvidence, TypeField, TypeShape, TypeStore,
};

use super::{
    lower_verified_with_image, verify, BlockId, DefinitionOracle, MemoryAccessId, MemoryAccessKind,
    MemoryDefinition, MemoryRegion, MemoryStateIdentity, ObjectId, ObjectIdentity, ObjectOrigin,
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

#[test]
fn mir_objects_retain_exact_cursor_lifetime_and_memory_state() {
    let llir = function(vec![(
        0x0c00,
        vec![
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 4, 4),
            },
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 8, 8),
            },
        ],
        vec![],
    )]);

    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified object MIR");
    let cursor = mir.use_(mir.instructions()[0].uses[0]).value;
    let object = mir
        .object_for_value(cursor)
        .expect("parameter-pointee object");

    assert_eq!(object.identity, ObjectIdentity::MirValue(cursor));
    assert_eq!(object.origins, vec![ObjectOrigin::ParameterPointee(cursor)]);
    assert_eq!(object.accesses.len(), 2);
    assert!(object
        .accesses
        .iter()
        .all(|access| access.cursor == ObjectIdentity::MirValue(cursor)));
    for access in &object.accesses {
        let memory_access = &mir.memory_accesses()[access.mir_access.expect("MIR access").0];
        assert_eq!(memory_access.object, Some(object.id));
        assert_eq!(
            access.memory_state,
            Some(MemoryStateIdentity::Mir(match access.role {
                crate::ir::memory_objects::AccessRole::Read => memory_access.input,
                crate::ir::memory_objects::AccessRole::Write => {
                    memory_access.output.expect("write state")
                }
            }))
        );
    }
    assert!(verify(&mir).is_empty());
}

#[test]
fn affine_copy_values_share_an_object_without_losing_cursor_lifetimes() {
    let llir = function(vec![(
        0x0d00,
        vec![
            Op::Assign {
                dst: VReg::phys("rbx"),
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 4, 4),
            },
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp::plain(Some(VReg::phys("rbx")), None, 0, 8, 8),
            },
        ],
        vec![],
    )]);

    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified affine object MIR");
    let root = mir.use_(mir.instructions()[0].uses[0]).value;
    let copy = mir.instructions()[0].outputs[0];
    let object = mir.object_for_value(root).expect("root object");

    assert_eq!(
        mir.object_for_value(copy).map(|object| object.id),
        Some(object.id)
    );
    assert_eq!(object.accesses.len(), 2);
    assert_eq!(
        object
            .accesses
            .iter()
            .map(|access| access.cursor.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            ObjectIdentity::MirValue(root),
            ObjectIdentity::MirValue(copy),
        ])
    );
    assert!(verify(&mir).is_empty());
}

#[test]
fn destructive_register_reuse_does_not_merge_distinct_object_lifetimes() {
    let llir = function(vec![(
        0x0e00,
        vec![
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 0, 8),
            },
            Op::Assign {
                dst: VReg::phys("rdi"),
                src: Value::Const(42),
            },
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 0, 8),
            },
        ],
        vec![],
    )]);

    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified split-lifetime MIR");
    let incoming = mir.use_(mir.instructions()[0].uses[0]).value;
    let replacement = mir.instructions()[1].outputs[0];

    assert_ne!(
        mir.object_for_value(incoming).map(|object| object.id),
        mir.object_for_value(replacement).map(|object| object.id)
    );
    assert_eq!(mir.objects().len(), 2);
    assert!(verify(&mir).is_empty());
}

#[test]
fn verifier_rejects_a_dangling_memory_object_link() {
    let llir = function(vec![(
        0x0f00,
        vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 0, 8),
        }],
        vec![],
    )]);

    let image = x86_image();
    let mut mir = lower_verified_with_image(&llir, &image).expect("verified object MIR");
    let primary = *mir.instructions()[0]
        .memory_effects
        .iter()
        .find(|id| mir.memory_accesses()[id.0].object.is_some())
        .expect("object-linked memory access");
    mir.memory_access_mut_for_test(primary).object = Some(ObjectId(usize::MAX));

    let errors = verify(&mir);
    assert!(
        errors.iter().any(|error| error.contains("invalid object")),
        "unexpected verifier errors: {errors:#?}"
    );
}

#[test]
fn loop_carried_affine_cursor_has_one_root_lifetime_and_stride() {
    let llir = function(vec![
        (0x1000, vec![Op::Nop], vec![0x1010]),
        (
            0x1010,
            vec![
                Op::Load {
                    dst: VReg::phys("rax"),
                    addr: MemOp::plain(Some(VReg::phys("rbx")), None, 0, 40, 4),
                },
                Op::Bin {
                    dst: VReg::phys("rbx"),
                    op: crate::ir::types::BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rbx")),
                    rhs: Value::Const(64),
                },
            ],
            vec![0x1010, 0x1020],
        ),
        (0x1020, vec![Op::Return], vec![]),
    ]);

    let image = x86_image();
    let mir = lower_verified_with_image(&llir, &image).expect("verified loop object MIR");
    let cursor = mir.use_(mir.instructions()[1].uses[0]).value;
    let object = mir.object_for_value(cursor).expect("loop cursor object");

    assert!(matches!(object.identity, ObjectIdentity::MirValue(_)));
    assert_eq!(object.stride, Some(64));
    assert_eq!(object.extent, Some(64));
    assert_eq!(object.accesses[0].offset, 40);
    assert_eq!(object.accesses[0].cursor, ObjectIdentity::MirValue(cursor));
    assert!(matches!(
        object.origins.as_slice(),
        [ObjectOrigin::ParameterPointee(_)]
    ));
    assert!(object.conflicts.is_empty());

    let mut types = TypeStore::default();
    let word = types
        .intern_anonymous(
            TypeShape::Primitive {
                name: "uint32_t".into(),
                size: 4,
                alignment: Some(4),
            },
            TypeEvidence::new(TypeAuthority::Inference, "MIR access width"),
        )
        .expect("intern field type");
    let record = types
        .intern_anonymous(
            TypeShape::Struct {
                fields: vec![TypeField {
                    name: "field_40".into(),
                    type_id: word,
                    offset: 40,
                }],
                size: 64,
                alignment: Some(4),
            },
            TypeEvidence::new(TypeAuthority::Inference, "MIR object layout"),
        )
        .expect("intern record layout");
    let object_key = ObjectTypeKey {
        function_entry: llir.entry_va,
        object: object.id,
    };
    types
        .bind_object_type(
            object_key,
            record,
            TypeEvidence::new(TypeAuthority::Inference, "MIR object binding"),
        )
        .expect("bind object layout");
    assert_eq!(
        types
            .object_type(object_key)
            .map(|binding| binding.selected()),
        Some(record)
    );
    assert!(types.verify().is_empty());
    assert!(verify(&mir).is_empty());
}
