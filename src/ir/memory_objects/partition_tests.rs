//! Frame-object partitioning over real compiled fixtures.
//!
//! Every behaviour claim here is measured on a real GCC build of a real
//! decompiler fixture. The synthetic LLIR cases at the end cover shapes the
//! fixtures do not exercise (an escaping frame pointer, a walking cursor).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use object::{Object, ObjectSymbol};

use super::{BoundaryEvidence, MemoryObject, ObjectOrigin, ObjectPartition, PartitionConflict};
use crate::ir::mir::{lower_verified_with_image, MirFunction};
use crate::program::image::ProgramImage;

struct RealFunction {
    mir: MirFunction,
    _image: ProgramImage,
    _dir: tempfile::TempDir,
}

/// Compile one real fixture source and lower the named function to verified MIR.
fn real_x86_function(
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
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
    .unwrap_or_else(|| panic!("lift {name}"));
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

fn frame_object(mir: &MirFunction) -> &MemoryObject {
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
}
