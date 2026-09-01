//! Frame-object partitioning over real compiled fixtures.
//!
//! Every behaviour claim here is measured on a real GCC build of a real
//! decompiler fixture. The synthetic LLIR cases at the end cover shapes the
//! fixtures do not exercise (an escaping frame pointer, a walking cursor).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use object::{Object, ObjectSymbol};

use super::{
    BoundaryEvidence, FrameCoordinate, MemoryObject, ObjectOrigin, ObjectPartition,
    PartitionConflict,
};
use crate::ir::mir::{lower_verified_with_image, MirFunction};
use crate::program::image::ProgramImage;

pub(super) struct RealFunction {
    pub(super) mir: MirFunction,
    _image: ProgramImage,
    _dir: tempfile::TempDir,
}

/// Compile one real fixture source and lower the named function to verified MIR.
pub(super) fn real_x86_function(
    name: &str,
    source_name: &str,
    source: &[u8],
    opt: &str,
) -> Option<RealFunction> {
    let dir = tempfile::tempdir().expect("temporary fixture build directory");
    let source_path = dir.path().join(source_name);
    let binary = dir.path().join("fixture.so");
    std::fs::File::create(&source_path)
        .and_then(|mut file| file.write_all(source))
        .expect("write the real fixture source");
    let build = match Command::new("gcc")
        .args(["-shared", "-fPIC", "-g", opt, "-o"])
        .arg(&binary)
        .arg(&source_path)
        .output()
    {
        Ok(build) => build,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::testing::missing_tool("gcc");
            return None;
        }
        Err(error) => panic!("launch GCC: {error}"),
    };
    assert!(
        build.status.success(),
        "compile the real fixture with GCC {opt}: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let data = std::fs::read(&binary).expect("read GCC output");
    let parsed = crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
    let entry = parsed
        .dynamic_symbols()
        .find(|symbol| symbol.name().ok() == Some(name))
        .map(|symbol| symbol.address())
        .unwrap_or_else(|| panic!("exported {name} symbol"));
    let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
        &data,
        &crate::analysis::cfg::Budgets::default(),
    );
    let function = functions
        .iter()
        .find(|function| function.entry_point.value == entry)
        .unwrap_or_else(|| panic!("discovered {name} function"));
    let mut lifted = crate::ir::lift_function::lift_function_from_bytes(
        &data,
        function,
        crate::core::binary::Arch::X86_64,
    )
    .unwrap_or_else(|error| panic!("lift {name}: {error}"));
    // Production lowers MIR from call-annotated LLIR, and an argument register
    // is where a frame address leaves the function.
    crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::SysVAmd64);
    let image = ProgramImage::from_path(&PathBuf::from(&binary)).expect("index the fixture ELF");
    let mir = lower_verified_with_image(&lifted, &image).expect("verified MIR");
    Some(RealFunction {
        mir,
        _image: image,
        _dir: dir,
    })
}

/// Compile one real fixture source and classify EVERY object of EVERY function
/// it defines, as `(function name, shape findings)`.
///
/// `None` when GCC is unavailable, matching [`real_x86_function`]. Individual
/// functions that fail to lift or verify are skipped: a census must not be an
/// assertion about the rest of the pipeline.
pub(super) fn real_x86_objects(
    source: &std::path::Path,
) -> Option<Vec<(String, Vec<super::ShapeFinding>)>> {
    let dir = tempfile::tempdir().expect("temporary fixture build directory");
    let binary = dir.path().join("fixture.so");
    let build = match Command::new("gcc")
        .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
        .arg(&binary)
        .arg(source)
        .output()
    {
        Ok(build) => build,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::testing::missing_tool("gcc");
            return None;
        }
        Err(error) => panic!("launch GCC: {error}"),
    };
    if !build.status.success() {
        return Some(Vec::new());
    }

    let data = std::fs::read(&binary).expect("read GCC output");
    let image = ProgramImage::from_path(&binary).expect("index the fixture ELF");
    let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
        &data,
        &crate::analysis::cfg::Budgets::default(),
    );
    let mut units = Vec::new();
    for function in &functions {
        let Ok(mut lifted) = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        ) else {
            continue;
        };
        crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::SysVAmd64);
        let Ok(mir) = lower_verified_with_image(&lifted, &image) else {
            continue;
        };
        let findings = mir
            .objects()
            .iter()
            .filter_map(|object| mir.object_shapes(object.id))
            .flatten()
            .collect::<Vec<_>>();
        units.push((format!("{:#x}", function.entry_point.value), findings));
    }
    Some(units)
}

pub(super) fn frame_object(mir: &MirFunction) -> &MemoryObject {
    let mut stack = mir.objects().iter().filter(|object| {
        object
            .origins
            .iter()
            .any(|origin| matches!(origin, ObjectOrigin::StackValue(_)))
    });
    let object = stack.next().expect("one stack-rooted MIR object");
    assert!(
        stack.next().is_none(),
        "the MIR model still keys the whole frame by one root pointer"
    );
    object
}

fn frame_partition(mir: &MirFunction) -> &ObjectPartition {
    let object = frame_object(mir);
    mir.object_partition(object.id)
        .expect("frame object partition")
}

fn abutting(partition: &ObjectPartition, start: i64, end: i64) -> Vec<i64> {
    partition
        .extents
        .iter()
        .find(|extent| extent.start == start && extent.end == end)
        .unwrap_or_else(|| panic!("extent [{start}, {end}) in {partition:#?}"))
        .boundaries
        .iter()
        .filter(|boundary| boundary.evidence == BoundaryEvidence::Abutting)
        .map(|boundary| boundary.at)
        .collect()
}

fn spanned(partition: &ObjectPartition, start: i64, end: i64) -> Vec<i64> {
    partition
        .extents
        .iter()
        .find(|extent| extent.start == start && extent.end == end)
        .unwrap_or_else(|| panic!("extent [{start}, {end}) in {partition:#?}"))
        .boundaries
        .iter()
        .filter(|boundary| boundary.evidence == BoundaryEvidence::Spanned)
        .map(|boundary| boundary.at)
        .collect()
}

/// `ua162_store_be32` stages four bytes then copies them out as one dword.
/// The three interior byte boundaries are spanned by the dword read, so the
/// staging array is one storage unit; the boundary to the neighbouring local
/// only abuts, so the array's outer extent stays a bound and not a claim.
#[test]
fn a_dword_copy_of_a_byte_staging_array_proves_it_is_one_storage_unit() {
    let Some(real) = real_x86_function(
        "ua162_store_be32",
        "162_unaligned_memcpy_access.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/162_unaligned_memcpy_access.c"),
        "-O0",
    ) else {
        return;
    };
    let partition = frame_partition(&real.mir);

    // Also the real control for `PartitionConflict::MergedPointer`: this frame
    // branches, so it has control-flow joins, and none of them merges a frame
    // coordinate the resolver could not place. An EMPTY conflict set is the
    // assertion that the merge rule does not fire on an ordinary frame.
    assert!(
        partition.conflicts.is_empty(),
        "no unmodelled frame access exists here: {:#?}",
        partition.conflicts
    );
    assert_eq!(spanned(partition, -44, 0), vec![-19, -18, -17]);
    assert_eq!(
        abutting(partition, -44, 0),
        vec![-40, -36, -32, -24, -20, -16, -8]
    );

    let bounds = partition
        .bounds_at(-20)
        .expect("bounds for the staging array");
    assert_eq!(bounds.at_least, (-20, -16));
    assert_eq!(bounds.at_most, (-44, 0));
    // The neighbouring 4-byte local abuts the array and is not absorbed by it.
    assert_eq!(
        partition
            .bounds_at(-24)
            .expect("bounds for the neighbour")
            .at_least,
        (-24, -20)
    );
}

/// The whole join, executed: a promoted-local frame coordinate in, an
/// evidence-backed byte extent out.
///
/// `ua162_store_be32` promotes seven frame locals, and the pass publishes each
/// one's coordinate in `StackLocalFacts::frame_coordinates` as `("rbp", disp)`.
/// The names below are the ones a real `-O0` decompilation of this function
/// mints (`local_18` ... `local_8`, i.e. `local_{disp:x}`); the assertion is
/// that MIR, which never saw a promoted local and keys the entire frame by one
/// root pointer, independently bounds each of those coordinates at exactly its
/// source width.
///
/// The two spellings are asserted to agree. `rbp` resolves through
/// `MemoryObject::base_offsets`, which had to prove the register held root-8;
/// `entry_rsp` resolves through the root itself at offset zero. That they land
/// on the same byte is the join's own consistency check.
#[test]
fn every_promoted_frame_coordinate_resolves_to_its_own_extent() {
    let Some(real) = real_x86_function(
        "ua162_store_be32",
        "162_unaligned_memcpy_access.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/162_unaligned_memcpy_access.c"),
        "-O0",
    ) else {
        return;
    };
    let frame = frame_object(&real.mir).id;
    let partition = frame_partition(&real.mir);

    // `mov %rsp,%rbp` after `push %rbp`: the frame register holds root-8, and
    // the entry stack pointer IS the root.
    assert_eq!(
        real.mir.resolve_frame_coordinate("rbp", 0),
        FrameCoordinate::Resolved {
            object: frame,
            offset: -8
        }
    );
    assert_eq!(
        real.mir.resolve_frame_coordinate("entry_rsp", 0),
        FrameCoordinate::Resolved {
            object: frame,
            offset: 0
        }
    );

    // (promoted name, its `frame_coordinates` displacement, its source width)
    let promoted = [
        ("local_24", -0x24, 4),
        ("local_20", -0x20, 4),
        ("local_1c", -0x1c, 4),
        ("local_18", -0x18, 8),
        ("local_10", -0x10, 4),
        ("local_c", -0xc, 4),
        ("local_8", -0x8, 8),
    ];
    for (name, disp, width) in promoted {
        let FrameCoordinate::Resolved { object, offset } =
            real.mir.resolve_frame_coordinate("rbp", disp)
        else {
            panic!("{name} did not resolve");
        };
        assert_eq!(object, frame, "{name}");
        assert_eq!(
            real.mir.resolve_frame_coordinate("entry_rsp", disp - 8),
            FrameCoordinate::Resolved { object, offset },
            "{name}: the two base spellings must name the same byte"
        );
        let bounds = partition
            .bounds_at(offset)
            .unwrap_or_else(|| panic!("{name} is not bounded"));
        assert_eq!(
            bounds.at_least,
            (offset, offset + width),
            "{name} at MIR offset {offset}"
        );
    }

    // Rule 8: a base this model never saw addressing anything is an explicit
    // unknown, not an offset of zero.
    assert_eq!(
        real.mir.resolve_frame_coordinate("r12", 0),
        FrameCoordinate::UnknownBase
    );
}

/// `pun_halves_swapped` writes a union as one dword and reads it as two
/// halves. The interior boundary at the half is spanned, so the union is one
/// unit; the separate `uint16_t swap` local abuts it and must stay separable.
#[test]
fn a_union_read_through_two_widths_is_not_split_at_the_half_boundary() {
    let Some(real) = real_x86_function(
        "pun_halves_swapped",
        "91_union_type_punning.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/91_union_type_punning.c"),
        "-O0",
    ) else {
        return;
    };
    let partition = frame_partition(&real.mir);

    assert!(partition.conflicts.is_empty(), "{:#?}", partition.conflicts);
    // An unaccessed hole between the spilled argument and the locals really
    // does split the frame into two covered runs.
    assert_eq!(
        partition
            .extents
            .iter()
            .map(|extent| (extent.start, extent.end))
            .collect::<Vec<_>>(),
        vec![(-28, -24), (-22, 0)]
    );
    assert_eq!(spanned(partition, -22, 0), vec![-18]);

    let union = partition.bounds_at(-20).expect("bounds for the union");
    assert_eq!(union.at_least, (-20, -16));
    assert_eq!(union.at_most, (-22, 0));
    let swap = partition.bounds_at(-22).expect("bounds for the swap local");
    assert_eq!(swap.at_least, (-22, -20));
}

/// `pass_large_by_value` copies a five-field struct into the outgoing argument
/// registers eight bytes at a time. Those wide reads span the boundary between
/// each copied pair, which is real evidence and nothing more: the pair edges
/// stay abutting.
///
/// It also proves the refusal is not academic. GCC leaves a frame-derived
/// pointer in `rcx` at the call, and the convention's conservative may-read
/// list says the callee may read it, so nothing here can be bounded even
/// though every extent is known.
#[test]
fn a_by_value_struct_transfer_spans_only_the_boundaries_it_copies_across() {
    let Some(real) = real_x86_function(
        "pass_large_by_value",
        "129_struct_by_value.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/129_struct_by_value.c"),
        "-O0",
    ) else {
        return;
    };
    let partition = frame_partition(&real.mir);

    // Rule 3 and rule 4: the conflict is added, the evidence is not removed.
    assert_eq!(spanned(partition, -44, -20), vec![-36, -28]);
    assert_eq!(abutting(partition, -44, -20), vec![-40, -32, -24]);

    assert!(
        partition
            .conflicts
            .contains(&PartitionConflict::EscapedRoot),
        "{:#?}",
        partition.conflicts
    );
    assert!(partition.bounds_at(-40).is_none());
}

/// `graph_bfs` holds `int32_t queue[16]` and `uint8_t seen[16]`, and reaches
/// both through a scaled index the MIR adapter does not model. The unobserved
/// bytes could join any two parts of the frame, so the partition keeps every
/// observed extent and refuses to bound any variable.
#[test]
fn an_unmodelled_indexed_frame_access_refuses_to_bound_any_variable() {
    let Some(real) = real_x86_function(
        "graph_bfs",
        "20_graph_bfs.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/20_graph_bfs.c"),
        "-O0",
    ) else {
        return;
    };
    let partition = frame_partition(&real.mir);

    assert!(partition
        .conflicts
        .contains(&PartitionConflict::UnmodeledAccess));
    // Rule 3: the observed evidence is retained, not destroyed by the conflict.
    assert!(!partition.extents.is_empty());
    for extent in &partition.extents {
        for offset in extent.start..extent.end {
            assert!(
                partition.bounds_at(offset).is_none(),
                "offset {offset} was bounded despite unmodelled indexed accesses"
            );
        }
    }
}

/// `alloca_in_loop` calls `alloca` inside a loop, so GCC emits a stack-probe
/// loop whose stack pointer is a phi, then `sub %rdx,%rsp` by a RUNTIME amount.
/// Bytes of this frame are written through a pointer with no constant relation
/// to the root, so nothing here can be bounded.
///
/// This is the case that proves the rule is not academic. A phi's incoming
/// edges are values held in the definition, not `MirUse` edges, so the escape
/// scan cannot reach them: before [`PartitionConflict::MergedPointer`] existed
/// this frame reported NO conflict at all and every extent in it looked bounded
/// while a runtime-sized allocation sat in the middle of it.
#[test]
fn a_runtime_sized_frame_adjustment_merged_at_a_loop_header_bounds_nothing() {
    let Some(real) = real_x86_function(
        "alloca_in_loop",
        "143_dynamic_frames.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/143_dynamic_frames.c"),
        "-O0",
    ) else {
        return;
    };
    let partition = frame_partition(&real.mir);

    assert!(
        partition
            .conflicts
            .contains(&PartitionConflict::MergedPointer),
        "{:#?}",
        partition.conflicts
    );
    // Rule 3: the conflict is added, the observed evidence is not destroyed.
    assert!(!partition.extents.is_empty());
    for extent in &partition.extents {
        for offset in extent.start..extent.end {
            assert!(
                partition.bounds_at(offset).is_none(),
                "offset {offset} was bounded despite a runtime-sized frame adjustment"
            );
        }
    }
}

/// `compound_literal_argument` builds a two-field object in its frame and hands
/// its address to a callee. The callee reads bytes this model only ever saw
/// written, so no extent of that frame can be bounded.
#[test]
fn a_frame_address_handed_to_a_callee_bounds_nothing() {
    let Some(real) = real_x86_function(
        "compound_literal_argument",
        "84_compound_literals.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/84_compound_literals.c"),
        "-O0",
    ) else {
        return;
    };
    let partition = frame_partition(&real.mir);

    assert!(
        partition
            .conflicts
            .contains(&PartitionConflict::EscapedRoot),
        "{:#?}",
        partition.conflicts
    );
    assert!(!partition.extents.is_empty());
    for extent in &partition.extents {
        for offset in extent.start..extent.end {
            assert!(partition.bounds_at(offset).is_none());
        }
    }
}

mod synthetic {
    use super::super::{ObjectOrigin, PartitionConflict};
    use crate::ir::mir::lower_verified_with_image;
    use crate::ir::types::{
        BinOp, CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value,
    };
    use crate::program::image::ProgramImage;

    fn x86_image() -> ProgramImage {
        ProgramImage::from_path(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"),
        )
        .expect("index real x86-64 ELF")
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

    fn frame_partition_conflicts(
        llir: &LlirFunction,
    ) -> std::collections::BTreeSet<PartitionConflict> {
        let image = x86_image();
        let mir = lower_verified_with_image(llir, &image).expect("verified MIR");
        let object = mir
            .objects()
            .iter()
            .find(|object| {
                object
                    .origins
                    .iter()
                    .any(|origin| matches!(origin, ObjectOrigin::StackValue(_)))
            })
            .expect("stack-rooted object");
        mir.object_partition(object.id)
            .expect("frame partition")
            .conflicts
            .clone()
    }

    /// A frame address handed to a callee can be written through by bytes this
    /// model never observes, so nothing about the frame stays bounded.
    #[test]
    fn a_frame_pointer_passed_to_a_call_escapes_the_partition() {
        let llir = function(vec![(
            0x1000,
            vec![
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 4),
                    src: Value::Const(1),
                },
                Op::Bin {
                    dst: VReg::phys("rdi"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-8),
                },
                Op::Call {
                    target: CallTarget::Direct(0x2000),
                    effects: Some(crate::ir::types::CallEffects {
                        result: Some(VReg::phys("rax")),
                        result_is_source_value: true,
                        args: vec![VReg::phys("rdi")],
                        proven_args: vec![VReg::phys("rdi")],
                        args_are_exact: true,
                        ..Default::default()
                    }),
                },
                Op::Return,
            ],
            vec![],
        )]);

        assert!(frame_partition_conflicts(&llir).contains(&PartitionConflict::EscapedRoot));
    }

    /// A register that addressed the frame at two different offsets names no
    /// fixed bytes, so the join must refuse it with a REASON. The evidence is
    /// retained on the object (rule 3), and `resolve_frame_coordinate` reports
    /// `AmbiguousBase` rather than dropping the register and answering
    /// `UnknownBase`, which would say the frame is not addressed through it.
    #[test]
    fn a_register_that_addressed_the_frame_twice_refuses_with_a_reason() {
        let llir = function(vec![(
            0x1000,
            vec![
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 4),
                    src: Value::Const(1),
                },
                Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-16),
                },
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rax")), None, 0, 0, 4),
                    src: Value::Const(2),
                },
                Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-32),
                },
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rax")), None, 0, 0, 4),
                    src: Value::Const(3),
                },
                Op::Return,
            ],
            vec![],
        )]);
        let image = x86_image();
        let mir = lower_verified_with_image(&llir, &image).expect("verified MIR");
        let object = mir
            .objects()
            .iter()
            .find(|object| {
                object
                    .origins
                    .iter()
                    .any(|origin| matches!(origin, ObjectOrigin::StackValue(_)))
            })
            .expect("stack-rooted object");

        // Rule 3: both observations are kept.
        assert_eq!(
            object
                .base_offsets
                .get("rax")
                .map(|offsets| offsets.iter().copied().collect::<Vec<_>>()),
            Some(vec![-32, -16])
        );
        assert_eq!(
            mir.resolve_frame_coordinate("rax", 0),
            crate::ir::memory_objects::FrameCoordinate::AmbiguousBase
        );
        // The unambiguous root spelling still resolves over the same frame.
        assert_eq!(
            mir.resolve_frame_coordinate("entry_rsp", -16),
            crate::ir::memory_objects::FrameCoordinate::Resolved {
                object: object.id,
                offset: -16
            }
        );
    }

    /// A cursor that walks the frame by a stride revisits every offset, so a
    /// constant-offset access no longer identifies fixed bytes.
    #[test]
    fn a_walking_frame_cursor_refuses_to_partition() {
        let llir = function(vec![
            (0x1000, vec![Op::Nop], vec![0x1010]),
            (
                0x1010,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, 8, 4),
                        src: Value::Const(1),
                    },
                    Op::Bin {
                        dst: VReg::phys("rsp"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("rsp")),
                        rhs: Value::Const(16),
                    },
                ],
                vec![0x1010, 0x1020],
            ),
            (0x1020, vec![Op::Return], vec![]),
        ]);

        assert!(frame_partition_conflicts(&llir).contains(&PartitionConflict::UnboundedCursor));
    }

    /// Two frame addresses merged at a control-flow join produce a pointer with
    /// no single coordinate. Every store through it lands in the frame, at an
    /// offset this adapter cannot name, so the frame's own extents no longer
    /// account for every byte written to it.
    ///
    /// A phi's incoming edges are NOT `MirUse`s, so the escape scan over
    /// `function.uses()` cannot see this: without an explicit rule the frame
    /// partition reports no conflict and confidently bounds variables whose
    /// bytes were overwritten behind its back.
    #[test]
    fn two_frame_addresses_merged_at_a_join_refuse_to_partition() {
        let llir = function(vec![
            (
                0x1000,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 4),
                        src: Value::Const(1),
                    },
                    Op::Cmp {
                        dst: VReg::phys("zf"),
                        op: crate::ir::types::CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(0),
                    },
                ],
                vec![0x1010, 0x1020],
            ),
            (
                0x1010,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-16),
                }],
                vec![0x1030],
            ),
            (
                0x1020,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-32),
                }],
                vec![0x1030],
            ),
            (
                0x1030,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rax")), None, 0, 0, 4),
                        src: Value::Const(7),
                    },
                    Op::Return,
                ],
                vec![],
            ),
        ]);

        assert!(
            frame_partition_conflicts(&llir).contains(&PartitionConflict::MergedPointer),
            "{:#?}",
            frame_partition_conflicts(&llir)
        );
    }

    /// The control for the rule above: when both incoming edges carry the SAME
    /// coordinate the merged pointer still names fixed bytes, the adapter
    /// places the access in the frame's own coordinate, and nothing is refused.
    #[test]
    fn a_join_of_two_equal_frame_addresses_still_partitions() {
        let llir = function(vec![
            (
                0x1000,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 4),
                        src: Value::Const(1),
                    },
                    Op::Cmp {
                        dst: VReg::phys("zf"),
                        op: crate::ir::types::CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(0),
                    },
                ],
                vec![0x1010, 0x1020],
            ),
            (
                0x1010,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-16),
                }],
                vec![0x1030],
            ),
            (
                0x1020,
                vec![Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rsp")),
                    rhs: Value::Const(-16),
                }],
                vec![0x1030],
            ),
            (
                0x1030,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rax")), None, 0, 0, 4),
                        src: Value::Const(7),
                    },
                    Op::Return,
                ],
                vec![],
            ),
        ]);

        assert!(frame_partition_conflicts(&llir).is_empty());
    }
}

/// A corpus-wide census of WHY a frame refuses to partition, and of what is
/// left to bound when it does not.
///
/// Ignored because it compiles every C fixture and lowers every function in
/// each. Run it when the refusal rules change:
///
/// ```text
/// cargo test --features python-ext frame_partition_census -- --ignored --nocapture
/// ```
///
/// It exists because the shape of these refusals — not their count — is what
/// decides whether an aggregate consumer can be migrated to MIR evidence at
/// all, and that shape is easy to reason about wrongly. Measured 2026-08-15
/// over 173 fixture sources at `-O0`: 1179 stack-rooted objects, 1120 of them
/// with an EMPTY conflict set, and **not one of those 1120 carries a single
/// indexed access**. That is not a coincidence and it is not a coverage
/// problem: `memory_objects/mir.rs` refuses the whole frame root the moment it
/// sees a scaled index (`UnmodeledAccess`) or a frame pointer in an operand it
/// does not interpret (`EscapedRoot`), and those two events are precisely the
/// triggers for every place `stack_locals` GUESSES a frame extent. The
/// assertion below is that structural fact, not the raw counts, which move
/// with the corpus.
#[test]
#[ignore]
fn frame_partition_census() {
    use std::collections::BTreeMap;

    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
    let mut sources = std::fs::read_dir(&root)
        .expect("the fixture source directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "c"))
        .collect::<Vec<_>>();
    sources.sort();

    let mut tally = BTreeMap::<String, usize>::new();
    let mut frames = 0usize;
    let mut clean = 0usize;
    let mut clean_with_index = Vec::new();
    for source in &sources {
        let stem = source
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("?");
        let Some(units) = real_x86_frame_partitions(source) else {
            return;
        };
        for (function, indexed, conflicts) in units {
            frames += 1;
            if conflicts.is_empty() {
                clean += 1;
                *tally.entry("clean".to_string()).or_default() += 1;
                if indexed > 0 {
                    clean_with_index.push(format!("{stem}:{function} indexed={indexed}"));
                }
                continue;
            }
            for conflict in &conflicts {
                *tally.entry(format!("{conflict:?}")).or_default() += 1;
            }
        }
    }

    println!(
        "{} fixture sources, {frames} stack-rooted objects",
        sources.len()
    );
    for (reason, count) in &tally {
        println!("{count:6}  {reason}");
    }
    assert!(frames > 0, "the census must observe some frames");
    assert!(
        clean > 0,
        "an ordinary scalar frame must still partition: {tally:#?}"
    );
    // The load-bearing claim. An indexed access is the ONLY evidence
    // `shape::ObjectShape::Array` is built from, and it is also the evidence
    // that makes `partition_object` refuse. A frame therefore never carries
    // both a proven array and a bounded extent, which is why the frame-array
    // extent `stack_locals::seed_indexed_stack_objects` guesses cannot be
    // answered from this model.
    assert!(
        clean_with_index.is_empty(),
        "a bounded frame cannot contain an indexed access: {clean_with_index:#?}"
    );
}

/// `(function entry, indexed access count, partition conflicts)` for every
/// stack-rooted object of every function defined in one fixture source.
///
/// `None` when GCC is unavailable, matching [`real_x86_function`].
fn real_x86_frame_partitions(
    source: &std::path::Path,
) -> Option<Vec<(String, usize, std::collections::BTreeSet<PartitionConflict>)>> {
    let dir = tempfile::tempdir().expect("temporary fixture build directory");
    let binary = dir.path().join("fixture.so");
    let build = match Command::new("gcc")
        .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
        .arg(&binary)
        .arg(source)
        .output()
    {
        Ok(build) => build,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::testing::missing_tool("gcc");
            return None;
        }
        Err(error) => panic!("launch GCC: {error}"),
    };
    if !build.status.success() {
        return Some(Vec::new());
    }

    let data = std::fs::read(&binary).expect("read GCC output");
    let image = ProgramImage::from_path(&binary).expect("index the fixture ELF");
    let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
        &data,
        &crate::analysis::cfg::Budgets::default(),
    );
    let mut units = Vec::new();
    for function in &functions {
        let Ok(mut lifted) = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        ) else {
            continue;
        };
        crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::SysVAmd64);
        let Ok(mir) = lower_verified_with_image(&lifted, &image) else {
            continue;
        };
        for object in mir.objects() {
            if !object
                .origins
                .iter()
                .any(|origin| matches!(origin, ObjectOrigin::StackValue(_)))
            {
                continue;
            }
            let Some(partition) = mir.object_partition(object.id) else {
                continue;
            };
            units.push((
                format!("{:#x}", function.entry_point.value),
                object.indexed_accesses.len(),
                partition.conflicts.clone(),
            ));
        }
    }
    Some(units)
}
