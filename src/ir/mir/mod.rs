//! Verified typed mid-level identities over lifted LLIR.
//!
//! This module is intentionally introduced from its contracts inward. The
//! tests below describe the first production boundary: complete multi-output
//! identity, target-qualified storage, explicit poison/phi states, and a
//! verifier-backed definition query. LLIR remains the semantic operation
//! source until individual consumers migrate.

mod builder;
mod model;
mod query;
mod verify;

pub use builder::lower_verified;
pub use model::{
    BlockId, Definition, InstructionId, MirBlock, MirFunction, MirInstruction, MirStorage, MirUse,
    MirValue, StorageId, UseId, ValueId,
};
pub use query::DefinitionOracle;
pub use verify::verify;

#[cfg(test)]
mod tests {
    use crate::core::binary::{Arch, Endianness, Format};
    use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value, Width};
    use crate::target::TargetSpec;

    use super::{lower_verified, verify, Definition, DefinitionOracle};

    fn target(arch: Arch) -> TargetSpec {
        TargetSpec::from_image_metadata(arch, Endianness::Little, Format::ELF, false)
    }

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

    #[test]
    fn every_intrinsic_output_has_a_stable_value_and_use_def_edge() {
        let llir = function(vec![(
            0x1000,
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
                Op::Assign {
                    dst: VReg::Temp(0),
                    src: Value::Reg(VReg::phys("r1")),
                },
                Op::ReturnValue {
                    value: Value::Reg(VReg::Temp(0)),
                },
            ],
            vec![],
        )]);

        let mir = lower_verified(&llir, target(Arch::ARM)).expect("valid MIR");
        let intrinsic = &mir.instructions()[0];
        assert_eq!(intrinsic.outputs.len(), 2);
        assert_ne!(intrinsic.outputs[0], intrinsic.outputs[1]);
        assert!(matches!(
            mir.value(intrinsic.outputs[1]).definition,
            Definition::UnknownEffect {
                output_index: 1,
                ..
            }
        ));
        let copy = &mir.instructions()[1];
        assert_eq!(mir.use_(copy.uses[0]).value, intrinsic.outputs[1]);
        let oracle = DefinitionOracle::new(&mir);
        assert_eq!(oracle.uses(intrinsic.outputs[1]), &[copy.uses[0]]);
        assert!(matches!(
            oracle.definition(intrinsic.outputs[1]),
            Some(Definition::UnknownEffect {
                output_index: 1,
                ..
            })
        ));
    }

    #[test]
    fn arm_aliases_are_canonical_only_under_the_arm_target() {
        let llir = function(vec![(
            0x2000,
            vec![
                Op::Assign {
                    dst: VReg::phys("r13"),
                    src: Value::Const(0x1000),
                },
                Op::Assign {
                    dst: VReg::Temp(0),
                    src: Value::Reg(VReg::phys("sp")),
                },
                Op::Assign {
                    dst: VReg::Temp(1),
                    src: Value::Reg(VReg::phys("ip")),
                },
            ],
            vec![],
        )]);

        let arm = lower_verified(&llir, target(Arch::ARM)).expect("ARM MIR");
        let written = arm.value(arm.instructions()[0].outputs[0]).storage;
        let read = arm.use_(arm.instructions()[1].uses[0]).storage;
        assert_eq!(written, read, "r13 and sp are one ARM storage location");
        assert_eq!(
            arm.storages()[arm.use_(arm.instructions()[2].uses[0]).storage.0].register,
            VReg::phys("r12"),
            "the AAPCS ip alias uses r12 storage"
        );

        let x86 = lower_verified(&llir, target(Arch::X86_64)).expect("x86 MIR");
        let written = x86.value(x86.instructions()[0].outputs[0]).storage;
        let read = x86.use_(x86.instructions()[1].uses[0]).storage;
        assert_ne!(written, read, "ARM aliases must not leak into x86");
    }

    #[test]
    fn poison_on_one_diamond_arm_is_not_all_paths_defined() {
        let llir = function(vec![
            (0x3000, vec![Op::Nop], vec![0x3100, 0x3200]),
            (
                0x3100,
                vec![Op::Assign {
                    dst: VReg::phys("rax"),
                    src: Value::Const(7),
                }],
                vec![0x3300],
            ),
            (
                0x3200,
                vec![Op::Undef {
                    dst: VReg::phys("rax"),
                    reason: "architecturally undefined".into(),
                }],
                vec![0x3300],
            ),
            (
                0x3300,
                vec![Op::Bin {
                    dst: VReg::phys("rbx"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(1),
                }],
                vec![],
            ),
        ]);

        let mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let merged_use = mir.instructions().last().expect("merge instruction").uses[0];
        let reaching = mir.use_(merged_use).value;
        assert!(matches!(
            mir.value(reaching).definition,
            Definition::Phi { .. }
        ));
        let oracle = DefinitionOracle::new(&mir);
        assert!(!oracle.all_paths_defined(merged_use));
    }

    #[test]
    fn ordinary_instructions_transport_undefinedness() {
        let llir = function(vec![(
            0x3800,
            vec![
                Op::Undef {
                    dst: VReg::phys("rax"),
                    reason: "undefined source".into(),
                },
                Op::Bin {
                    dst: VReg::phys("rbx"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(1),
                },
                Op::ReturnValue {
                    value: Value::Reg(VReg::phys("rbx")),
                },
            ],
            vec![],
        )]);

        let mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let returned = mir.instructions()[2].uses[0];
        assert!(!DefinitionOracle::new(&mir).all_paths_defined(returned));
    }

    #[test]
    fn loop_carried_definition_cycle_with_a_defined_entry_is_defined() {
        let llir = function(vec![
            (
                0x3900,
                vec![Op::Assign {
                    dst: VReg::phys("rax"),
                    src: Value::Const(0),
                }],
                vec![0x3910],
            ),
            (
                0x3910,
                vec![Op::Assign {
                    dst: VReg::Temp(0),
                    src: Value::Reg(VReg::phys("rax")),
                }],
                vec![0x3920, 0x3930],
            ),
            (
                0x3920,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(1),
                }],
                vec![0x3910],
            ),
            (0x3930, vec![Op::Return], vec![]),
        ]);

        let mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let header_use = mir.instructions()[1].uses[0];
        assert!(matches!(
            mir.value(mir.use_(header_use).value).definition,
            Definition::Phi { .. }
        ));
        assert!(DefinitionOracle::new(&mir).all_paths_defined(header_use));
    }

    #[test]
    fn verifier_rejects_a_use_whose_value_has_different_storage() {
        let llir = function(vec![(
            0x4000,
            vec![
                Op::Assign {
                    dst: VReg::phys("rax"),
                    src: Value::Const(1),
                },
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("rax")),
                },
            ],
            vec![],
        )]);
        let mut mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let source_use = mir.instructions()[1].uses[0];
        let wrong_value = mir.instructions()[1].outputs[0];
        mir.use_mut_for_test(source_use).value = wrong_value;

        let errors = super::verify(&mir);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("storage mismatch")),
            "unexpected verifier errors: {errors:#?}"
        );
    }

    #[test]
    fn verifier_rejects_a_future_definition_as_a_reaching_value() {
        let llir = function(vec![(
            0x4800,
            vec![
                Op::Assign {
                    dst: VReg::Temp(0),
                    src: Value::Reg(VReg::phys("rax")),
                },
                Op::Assign {
                    dst: VReg::phys("rax"),
                    src: Value::Const(1),
                },
            ],
            vec![],
        )]);
        let mut mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let source_use = mir.instructions()[0].uses[0];
        let future_value = mir.instructions()[1].outputs[0];
        mir.use_mut_for_test(source_use).value = future_value;

        let errors = verify(&mir);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("does not dominate")),
            "unexpected verifier errors: {errors:#?}"
        );
    }

    #[test]
    fn verifier_rejects_a_storage_with_an_unstable_arena_id() {
        let llir = function(vec![(
            0x4900,
            vec![Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(1),
            }],
            vec![],
        )]);
        let mut mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let storage = mir.value(mir.instructions()[0].outputs[0]).storage;
        mir.storage_mut_for_test(storage).id = super::StorageId(99);

        let errors = verify(&mir);
        assert!(
            errors.iter().any(|error| error.contains("storage id")),
            "unexpected verifier errors: {errors:#?}"
        );
    }

    #[test]
    fn empty_llir_fails_closed_without_panicking() {
        let empty = LlirFunction {
            entry_va: 0,
            blocks: Vec::new(),
        };

        let errors = lower_verified(&empty, target(Arch::X86_64)).expect_err("invalid MIR");
        assert!(errors.iter().any(|error| error.contains("no blocks")));
    }

    #[test]
    fn disconnected_block_outputs_are_explicitly_unreachable() {
        let llir = function(vec![
            (0x5000, vec![Op::Return], vec![]),
            (
                0x5100,
                vec![
                    Op::Assign {
                        dst: VReg::Temp(0),
                        src: Value::Reg(VReg::phys("rax")),
                    },
                    Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Const(1),
                    },
                ],
                vec![],
            ),
        ]);

        let mir = lower_verified(&llir, target(Arch::X86_64)).expect("valid MIR");
        let unreachable = &mir.instructions()[1];
        let output = unreachable.outputs[0];
        assert!(matches!(
            mir.value(output).definition,
            Definition::Unreachable { .. }
        ));
        let oracle = DefinitionOracle::new(&mir);
        assert!(!oracle.all_paths_defined(unreachable.uses[0]));
    }

    #[test]
    fn real_x86_64_and_arm32_functions_lower_to_verified_mir() {
        use std::path::Path;

        use crate::analysis::cfg::{analyze_functions_image_with_seeds, Budgets};
        use crate::ir::lift_function::lift_function_from_image;
        use crate::program::image::ProgramImage;
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
            let mir = lower_verified(&llir, *image.target()).expect("verify real MIR");

            assert!(!mir.blocks().is_empty());
            assert!(!mir.instructions().is_empty());
            assert!(verify(&mir).is_empty());
        }
    }
}
