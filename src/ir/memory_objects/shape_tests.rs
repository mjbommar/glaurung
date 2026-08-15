//! Shape classification measured on real compiled fixtures.
//!
//! Every claim below — and every refusal — is read off a real GCC build of a
//! real `tests/decompiler_fixtures/src` source through the same harness the
//! partition tests use. The synthetic LLIR cases at the end cover the two
//! index shapes no fixture in the corpus emits.

use super::partition_tests::{frame_object, real_x86_function};
use super::shape::{ObjectShape, ShapeFinding, ShapeRefusal};
use crate::ir::mir::MirFunction;

fn shapes(mir: &MirFunction) -> Vec<ShapeFinding> {
    let object = frame_object(mir).id;
    mir.object_shapes(object).expect("frame object shapes")
}

/// Every `Array` finding in the frame, as `(offset, element)`.
fn arrays(findings: &[ShapeFinding]) -> Vec<(i64, u8)> {
    findings
        .iter()
        .filter_map(|finding| match finding.shape {
            ObjectShape::Array { element } => Some((finding.start, element)),
            _ => None,
        })
        .collect()
}

/// The finding for the covered run starting at `start`, whatever it says.
fn run(findings: &[ShapeFinding], start: i64, end: i64) -> &ObjectShape {
    &findings
        .iter()
        .find(|finding| finding.start == start && finding.end == Some(end))
        .unwrap_or_else(|| panic!("a covered run [{start}, {end}) in {findings:#?}"))
        .shape
}

/// The shape of one cell inside a `Cells` run.
fn cell(shape: &ObjectShape, start: i64, end: i64) -> &ObjectShape {
    let ObjectShape::Cells { cells } = shape else {
        panic!("not a cell decomposition: {shape:#?}");
    };
    &cells
        .iter()
        .find(|cell| cell.start == start && cell.end == Some(end))
        .unwrap_or_else(|| panic!("a cell [{start}, {end}) in {cells:#?}"))
        .shape
}

/// `graph_bfs` holds `int32_t queue[16]` and `uint8_t seen[16]` in one frame
/// and reaches both through a scaled index. Two arrays, two element strides,
/// two proven bases — recovered from address encodings alone, with no debug
/// information and no size heuristic.
///
/// It is also its own control. The same frame holds `head`, `tail` and `count`
/// as three ADJACENT four-byte locals at [-124, -112), which is a uniform
/// four-byte tiling and exactly the coincidence a stride-inventing classifier
/// turns into `int32_t[3]`. Nothing indexes them, so nothing here claims an
/// array over them.
#[test]
fn two_arrays_in_one_frame_recover_their_strides_and_their_bases() {
    let Some(real) = real_x86_function(
        "graph_bfs",
        "20_graph_bfs.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/20_graph_bfs.c"),
        "-O0",
    ) else {
        return;
    };
    let findings = shapes(&real.mir);

    // `queue` at frame-104 with 4-byte elements, `seen` at frame-40 with
    // 1-byte elements. Those are the only two arrays in the function, and the
    // source declares exactly two.
    assert_eq!(arrays(&findings), vec![(-104, 4), (-40, 1)]);

    // Rule 8: the element COUNT is an explicit absence, not a guess. Nothing
    // in the address arithmetic bounds the index.
    for finding in &findings {
        if matches!(finding.shape, ObjectShape::Array { .. }) {
            assert_eq!(finding.end, None, "{finding:#?}");
        }
    }

    // The indexed accesses are still refused for bounding (they are what makes
    // the partition refuse), so every covered run stays unclassified — the
    // three adjacent scalars among them.
    assert_eq!(
        run(&findings, -124, -104),
        &ObjectShape::Unclassified(ShapeRefusal::UnboundedObject)
    );
}

/// The evidence a real union produces and the evidence a real byte array read
/// through a wider load produces are THE SAME, so the classifier must not name
/// either one.
///
/// `pun_halves_swapped` declares `union Punner` and writes it as a `uint32_t`
/// while reading it as two `uint16_t` halves. `ua162_store_be32` declares a
/// `uint8_t` staging buffer, writes it byte by byte, and copies it out as one
/// `uint32_t`. Different C, different intent, identical footprints over four
/// bytes — and, here, an identical verdict. Choosing `union` for the first
/// would fabricate an aliasing the second does not have; choosing `struct` for
/// the second would fabricate a size the first does not have.
#[test]
fn a_union_and_a_punned_byte_array_are_indistinguishable_and_both_refuse() {
    let Some(union_fn) = real_x86_function(
        "pun_halves_swapped",
        "91_union_type_punning.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/91_union_type_punning.c"),
        "-O0",
    ) else {
        return;
    };
    let Some(array_fn) = real_x86_function(
        "ua162_store_be32",
        "162_unaligned_memcpy_access.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/162_unaligned_memcpy_access.c"),
        "-O0",
    ) else {
        return;
    };

    let union_cell = cell(run(&shapes(&union_fn.mir), -22, 0), -20, -16).clone();
    let array_cell = cell(run(&shapes(&array_fn.mir), -44, 0), -20, -16).clone();

    assert_eq!(
        union_cell,
        ObjectShape::Overlapping { container: Some(4) },
        "the union is one four-byte storage unit, also reached in halves"
    );
    assert_eq!(
        union_cell, array_cell,
        "a union and a punned byte array must reach the same verdict"
    );
}

/// The same four bytes, indexed instead of punned. `pun_byte_of_word` reads
/// `punner.bytes[index]`, so the union member that IS an array is recovered as
/// one — while the covered run around it stays refused, because the indexed
/// access is exactly what the partition cannot place.
#[test]
fn an_indexed_union_member_recovers_as_an_array_without_bounding_the_union() {
    let Some(real) = real_x86_function(
        "pun_byte_of_word",
        "91_union_type_punning.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/91_union_type_punning.c"),
        "-O0",
    ) else {
        return;
    };
    let findings = shapes(&real.mir);

    assert_eq!(arrays(&findings), vec![(-20, 1)]);
    assert_eq!(
        run(&findings, -20, 0),
        &ObjectShape::Unclassified(ShapeRefusal::UnboundedObject)
    );
}

/// A bitfield container is invisible as a bitfield. `struct Flags` packs four
/// fields into four bytes, and every machine access names the whole container
/// or a byte of it; the field edges live in mask and shift arithmetic over the
/// loaded VALUE, which is not a memory footprint and never reaches this model.
///
/// So the classifier reports one four-byte storage unit reached at several
/// widths — the same verdict as the union above — and claims no bitfield. That
/// is the honest answer: there is no bitfield evidence here to classify.
#[test]
fn a_bitfield_container_is_one_storage_unit_and_no_bitfield_is_claimed() {
    let Some(real) = real_x86_function(
        "bitfield_extract",
        "90_bitfields.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/90_bitfields.c"),
        "-O0",
    ) else {
        return;
    };
    let findings = shapes(&real.mir);

    assert_eq!(
        cell(run(&findings, -12, 0), -12, -8),
        &ObjectShape::Overlapping { container: Some(4) }
    );
    assert!(arrays(&findings).is_empty(), "{findings:#?}");
}

/// The control that a decompiler doing nothing cannot pass in reverse: a frame
/// of ordinary locals must decompose into exactly its locals, and must not
/// become an array because several of them happen to be the same width.
///
/// `ua162_store_be32` lays out eight storage units in one covered run,
/// including three consecutive four-byte cells at [-44, -32). A classifier
/// that reads a repeated width as a stride calls that `int32_t[3]`.
#[test]
fn adjacent_same_width_locals_stay_separate_cells_and_never_become_an_array() {
    let Some(real) = real_x86_function(
        "ua162_store_be32",
        "162_unaligned_memcpy_access.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/162_unaligned_memcpy_access.c"),
        "-O0",
    ) else {
        return;
    };
    let findings = shapes(&real.mir);
    let ObjectShape::Cells { cells } = run(&findings, -44, 0) else {
        panic!("{findings:#?}");
    };

    assert_eq!(
        cells
            .iter()
            .map(|cell| (cell.start, cell.end, cell.shape.clone()))
            .collect::<Vec<_>>(),
        vec![
            (-44, Some(-40), ObjectShape::Scalar { width: 4 }),
            (-40, Some(-36), ObjectShape::Scalar { width: 4 }),
            (-36, Some(-32), ObjectShape::Scalar { width: 4 }),
            (-32, Some(-24), ObjectShape::Scalar { width: 8 }),
            (-24, Some(-20), ObjectShape::Scalar { width: 4 }),
            (
                -20,
                Some(-16),
                ObjectShape::Overlapping { container: Some(4) }
            ),
            (-16, Some(-8), ObjectShape::Scalar { width: 8 }),
            (-8, Some(0), ObjectShape::Scalar { width: 8 }),
        ]
    );
    assert!(arrays(&findings).is_empty(), "{findings:#?}");
}

/// A refusal one layer down is a refusal here. `alloca_in_loop` adjusts its
/// stack pointer by a runtime amount merged at a loop header, so the partition
/// bounds nothing in that frame; no region of it is a region of anything in
/// particular, and every finding says so with the reason.
#[test]
fn a_frame_the_partition_refused_carries_no_shape_claim_at_all() {
    let Some(real) = real_x86_function(
        "alloca_in_loop",
        "143_dynamic_frames.c",
        include_bytes!("../../../tests/decompiler_fixtures/src/143_dynamic_frames.c"),
        "-O0",
    ) else {
        return;
    };
    let findings = shapes(&real.mir);

    assert!(!findings.is_empty(), "the observed runs are retained");
    for finding in &findings {
        assert_eq!(
            finding.shape,
            ObjectShape::Unclassified(ShapeRefusal::UnboundedObject),
            "{finding:#?}"
        );
    }
}

mod synthetic {
    use super::super::shape::{ObjectShape, ShapeFinding, ShapeRefusal};
    use super::super::ObjectOrigin;
    use crate::ir::mir::lower_verified_with_image;
    use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
    use crate::program::image::ProgramImage;

    fn frame_shapes(ops: Vec<(u64, Vec<Op>, Vec<u64>)>) -> Vec<ShapeFinding> {
        let llir = LlirFunction {
            entry_va: ops.first().map_or(0, |block| block.0),
            blocks: ops
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
        };
        let image = ProgramImage::from_path(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"),
        )
        .expect("index real x86-64 ELF");
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
        mir.object_shapes(object.id).expect("frame object shapes")
    }

    fn indexed_shape(findings: &[ShapeFinding], start: i64) -> &ObjectShape {
        &findings
            .iter()
            .find(|finding| finding.start == start && finding.end.is_none())
            .unwrap_or_else(|| panic!("an indexed region at {start} in {findings:#?}"))
            .shape
    }

    /// One anchoring store, so the frame object exists at all.
    fn anchor() -> Op {
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 4),
            src: Value::Const(1),
        }
    }

    /// `(%rsp,%rax,16)` with a four-byte load. The stride is real, but the
    /// access reads a quarter of the unit it strides over, so the unit is not
    /// proven: an array of 16-byte elements whose first field is read, and a
    /// four-byte-element array walked by a pre-multiplied index, encode the
    /// same instruction.
    #[test]
    fn an_index_that_reads_part_of_its_unit_refuses_with_a_reason() {
        let findings = frame_shapes(vec![(
            0x1000,
            vec![
                anchor(),
                Op::Load {
                    dst: VReg::phys("rdx"),
                    addr: MemOp::plain(
                        Some(VReg::phys("rsp")),
                        Some(VReg::phys("rax")),
                        16,
                        -64,
                        4,
                    ),
                },
                Op::Return,
            ],
            vec![],
        )]);

        assert_eq!(
            indexed_shape(&findings, -64),
            &ObjectShape::Unclassified(ShapeRefusal::UnprovenIndexStride)
        );
    }

    /// Two runtime indices scale into the same byte with different strides.
    /// Both observations are retained on the object and neither wins: rule 3
    /// keeps the evidence, rule 8 makes the failure explicit.
    #[test]
    fn two_index_strides_at_one_offset_refuse_with_a_reason() {
        let findings = frame_shapes(vec![(
            0x1000,
            vec![
                anchor(),
                Op::Load {
                    dst: VReg::phys("rdx"),
                    addr: MemOp::plain(Some(VReg::phys("rsp")), Some(VReg::phys("rax")), 4, -64, 4),
                },
                Op::Load {
                    dst: VReg::phys("rcx"),
                    addr: MemOp::plain(Some(VReg::phys("rsp")), Some(VReg::phys("rax")), 8, -64, 8),
                },
                Op::Return,
            ],
            vec![],
        )]);

        assert_eq!(
            indexed_shape(&findings, -64),
            &ObjectShape::Unclassified(ShapeRefusal::ConflictingIndexStrides)
        );
    }

    /// The control for the two above: one stride, read at its own width, is an
    /// array. Without this the two refusals could be satisfied by a classifier
    /// that never claims anything.
    #[test]
    fn one_index_stride_read_at_its_own_width_is_an_array() {
        let findings = frame_shapes(vec![(
            0x1000,
            vec![
                anchor(),
                Op::Load {
                    dst: VReg::phys("rdx"),
                    addr: MemOp::plain(Some(VReg::phys("rsp")), Some(VReg::phys("rax")), 4, -64, 4),
                },
                Op::Return,
            ],
            vec![],
        )]);

        assert_eq!(
            indexed_shape(&findings, -64),
            &ObjectShape::Array { element: 4 }
        );
    }

    /// A cursor walking the frame by a stride revisits every offset, so the
    /// object's byte coordinate names no fixed bytes and the base of an indexed
    /// region is anchored to nothing. The array evidence is retained on the
    /// object; the CLAIM is withheld.
    #[test]
    fn a_walking_cursor_withholds_the_array_its_index_seems_to_prove() {
        let findings = frame_shapes(vec![
            (0x1000, vec![anchor()], vec![0x1010]),
            (
                0x1010,
                vec![
                    Op::Load {
                        dst: VReg::phys("rdx"),
                        addr: MemOp::plain(
                            Some(VReg::phys("rsp")),
                            Some(VReg::phys("rax")),
                            4,
                            -64,
                            4,
                        ),
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

        assert!(
            !findings
                .iter()
                .any(|finding| matches!(finding.shape, ObjectShape::Array { .. })),
            "{findings:#?}"
        );
    }
}

/// A corpus-wide census of what the classifier claims and what it refuses.
///
/// Ignored because it compiles every C fixture in the corpus and lowers every
/// function in each. Run it when the classification rules change:
///
/// ```text
/// cargo test --features python-ext shape_census -- --ignored --nocapture
/// ```
///
/// It exists because the rules above are easy to reason about wrongly. The
/// first draft of this patch asserted in prose that no fixture emits a scaled
/// index whose scale differs from its access width; a disassembly scan of the
/// corpus found thirty that do. A census is cheaper than being wrong in a
/// design document.
#[test]
#[ignore]
fn shape_census() {
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
    let mut arrays = Vec::new();
    let mut unproven = Vec::new();
    for source in &sources {
        let stem = source
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("?");
        let Some(units) = super::partition_tests::real_x86_objects(source) else {
            continue;
        };
        for (function, findings) in units {
            // Cells are counted at their own level too: `Overlapping` — the
            // union/pun/bitfield-container refusal — only ever appears inside a
            // decomposition, so a top-level-only tally would report zero of the
            // most interesting verdict in the module.
            let mut queue = findings
                .into_iter()
                .map(|finding| (0, finding))
                .collect::<Vec<_>>();
            while let Some((depth, finding)) = queue.pop() {
                let key = match &finding.shape {
                    ObjectShape::Scalar { .. } => "Scalar",
                    ObjectShape::Array { element } => {
                        arrays.push(format!("{stem}:{function} +{} x{element}", finding.start));
                        "Array"
                    }
                    ObjectShape::Cells { cells } => {
                        queue.extend(cells.iter().map(|cell| (depth + 1, cell.clone())));
                        "Cells"
                    }
                    ObjectShape::Overlapping { .. } => "Overlapping",
                    ObjectShape::Unclassified(ShapeRefusal::UnboundedObject) => "UnboundedObject",
                    ObjectShape::Unclassified(ShapeRefusal::UnprovenIndexStride) => {
                        unproven.push(format!("{stem}:{function} +{}", finding.start));
                        "UnprovenIndexStride"
                    }
                    ObjectShape::Unclassified(ShapeRefusal::ConflictingIndexStrides) => {
                        "ConflictingIndexStrides"
                    }
                };
                let level = if depth == 0 { "run" } else { "cell" };
                *tally.entry(format!("{level} {key}")).or_default() += 1;
            }
        }
    }

    println!("{} fixture sources", sources.len());
    for (shape, count) in &tally {
        println!("{count:6}  {shape}");
    }
    println!("--- arrays ({})", arrays.len());
    for array in &arrays {
        println!("  {array}");
    }
    println!("--- UnprovenIndexStride ({})", unproven.len());
    for one in &unproven {
        println!("  {one}");
    }
}
