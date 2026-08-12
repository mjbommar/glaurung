use super::llir::infer_from_llir;
use super::{infer_from_ast, AccessRole, AccessSource, LayoutConflict};
use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::memory_ssa::{compute_memory_ssa, MemoryRegion};
use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
use crate::ir::use_def::InstrAddr;

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn x86_image() -> crate::program::image::ProgramImage {
    crate::program::image::ProgramImage::from_path(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"),
    )
    .expect("index real x86-64 ELF")
}

fn cursor_address(name: &str, offset: i64) -> Expr {
    Expr::Bin {
        op: BinOp::Add,
        lhs: Box::new(Expr::Reg(reg(name))),
        rhs: Box::new(Expr::Const(offset)),
    }
}

fn cursor_step(name: &str, stride: i64) -> Stmt {
    Stmt::Store {
        addr: Expr::Reg(reg(name)),
        src: cursor_address(name, stride),
        size: 8,
    }
}

fn object_cursor_body(name: &str, stride: i64) -> Vec<Stmt> {
    vec![
        Stmt::Store {
            addr: Expr::Reg(reg(name)),
            src: Expr::Deref {
                addr: Box::new(Expr::Addr(0x4000)),
                size: 8,
            },
            size: 8,
        },
        Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Store {
                    addr: cursor_address(name, 44),
                    src: Expr::Const(7),
                    size: 4,
                },
                Stmt::Store {
                    addr: cursor_address(name, 40),
                    src: Expr::Const(3),
                    size: 4,
                },
                cursor_step(name, stride),
            ],
        },
    ]
}

fn function(body: Vec<Stmt>) -> Function {
    Function {
        name: "walk_records".into(),
        entry_va: 0x1000,
        body,
    }
}

#[test]
fn promoted_cursor_recovers_one_object_stride_and_ordered_access_paths() {
    let model = infer_from_ast(&function(object_cursor_body("local_8", 64)));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("cursor object");

    assert_eq!(object.extent, Some(64));
    assert_eq!(object.stride, Some(64));
    assert!(object.conflicts.is_empty());
    assert_eq!(
        object
            .accesses
            .iter()
            .map(|access| (access.offset, access.width, access.role))
            .collect::<Vec<_>>(),
        vec![(40, 4, AccessRole::Write), (44, 4, AccessRole::Write)]
    );
    assert!(model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn access_past_stride_fails_closed_instead_of_inventing_an_extent() {
    let mut body = object_cursor_body("local_8", 64);
    let Stmt::While {
        body: loop_body, ..
    } = &mut body[1]
    else {
        panic!("fixture loop");
    };
    loop_body.insert(
        0,
        Stmt::Store {
            addr: cursor_address("local_8", 60),
            src: Expr::Const(0),
            size: 8,
        },
    );

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert_eq!(object.extent, None);
    assert!(object.conflicts.contains(&LayoutConflict::AccessPastStride));
    assert!(!model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn conflicting_cursor_steps_remain_explicit_layout_conflicts() {
    let mut body = object_cursor_body("local_8", 64);
    let Stmt::While {
        body: loop_body, ..
    } = &mut body[1]
    else {
        panic!("fixture loop");
    };
    loop_body.push(cursor_step("local_8", 32));

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert_eq!(object.stride, None);
    assert!(object
        .conflicts
        .contains(&LayoutConflict::ConflictingStrides));
    assert!(!model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn integer_use_rejects_an_otherwise_pointer_shaped_cursor() {
    let mut body = object_cursor_body("local_8", 64);
    body.push(Stmt::Assign {
        dst: reg("var0"),
        src: Expr::Bin {
            op: BinOp::Xor,
            lhs: Box::new(Expr::Reg(reg("local_8"))),
            rhs: Box::new(Expr::Const(0x55)),
        },
    });

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert!(object.conflicts.contains(&LayoutConflict::NonAddressUse));
    assert!(!model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn access_path_collection_is_register_spelling_and_pointer_width_independent() {
    let model = infer_from_ast(&function(object_cursor_body("local_4", 48)));
    let object = model
        .object_for_base(&reg("local_4"))
        .expect("cursor object");

    // Neither a 32-bit-looking promoted slot name nor a non-eight-byte object
    // stride changes the byte-offset proof.
    assert_eq!(object.extent, Some(48));
    assert!(object.conflicts.is_empty());
    assert!(model.has_conflict_free_extent(&reg("local_4")));
}

#[test]
fn distinct_call_result_origins_do_not_collapse_into_one_object() {
    let call = |target| Expr::Call {
        target: Box::new(Expr::Addr(target)),
        args: Vec::new(),
        call_spec: None,
        result_width: Some(8),
    };
    let mut body = object_cursor_body("local_8", 64);
    body[0] = Stmt::Store {
        addr: Expr::Reg(reg("local_8")),
        src: call(0x2000),
        size: 8,
    };
    body.insert(
        1,
        Stmt::Store {
            addr: Expr::Reg(reg("local_8")),
            src: call(0x3000),
            size: 8,
        },
    );

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert!(object
        .conflicts
        .contains(&LayoutConflict::ConflictingOrigins));
    assert!(!model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn exact_self_copy_does_not_invent_a_conflicting_origin() {
    let mut body = object_cursor_body("local_8", 64);
    body.insert(
        1,
        Stmt::Store {
            addr: Expr::Reg(reg("local_8")),
            src: Expr::Reg(reg("local_8")),
            size: 8,
        },
    );

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert!(object.conflicts.is_empty());
    assert!(model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn zero_width_access_fails_closed() {
    let mut body = object_cursor_body("local_8", 64);
    let Stmt::While {
        body: loop_body, ..
    } = &mut body[1]
    else {
        panic!("fixture loop");
    };
    loop_body.insert(
        0,
        Stmt::Store {
            addr: cursor_address("local_8", 12),
            src: Expr::Const(0),
            size: 0,
        },
    );

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert!(object.conflicts.contains(&LayoutConflict::ZeroWidthAccess));
    assert!(!model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn scalar_redefinition_is_an_explicit_object_conflict() {
    let mut body = object_cursor_body("local_8", 64);
    body.insert(
        1,
        Stmt::Store {
            addr: Expr::Reg(reg("local_8")),
            src: Expr::Const(42),
            size: 8,
        },
    );

    let model = infer_from_ast(&function(body));
    let object = model
        .object_for_base(&reg("local_8"))
        .expect("observed object");

    assert!(object
        .conflicts
        .contains(&LayoutConflict::UnclassifiedDefinition));
    assert!(!model.has_conflict_free_extent(&reg("local_8")));
}

#[test]
fn llir_accesses_retain_instruction_and_memory_version_provenance() {
    let llir = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1004,
            instrs: vec![
                LlirInstr {
                    va: 0x1000,
                    op: Op::Store {
                        addr: MemOp::plain(Some(reg("rbx")), None, 0, 4, 4),
                        src: Value::Const(1),
                    },
                },
                LlirInstr {
                    va: 0x1001,
                    op: Op::Load {
                        dst: reg("rax"),
                        addr: MemOp::plain(Some(reg("rbx")), None, 0, 8, 8),
                    },
                },
            ],
            succs: vec![],
        }],
    };
    let image = x86_image();
    let memory = compute_memory_ssa(&llir, &image);

    let model = infer_from_llir(&llir, &memory, &image).expect("verified LLIR object model");
    let object = model.object_for_base(&reg("rbx")).expect("rbx object");

    assert_eq!(object.accesses.len(), 2);
    assert_eq!(object.accesses[0].offset, 4);
    assert_eq!(object.accesses[0].role, AccessRole::Write);
    assert_eq!(
        object.accesses[0].memory_region,
        Some(MemoryRegion::HeapUnknown)
    );
    assert_eq!(
        object.accesses[0].source,
        AccessSource::LlirInstruction(InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        })
    );
    assert_eq!(
        object.accesses[0].memory_version,
        memory
            .access_at(
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 0,
                },
                MemoryRegion::HeapUnknown
            )
            .and_then(|access| access.output)
    );
    assert_eq!(object.accesses[1].offset, 8);
    assert_eq!(object.accesses[1].role, AccessRole::Read);
    assert_eq!(
        object.accesses[1].memory_version,
        memory
            .access_at(
                InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
                MemoryRegion::HeapUnknown
            )
            .map(|access| access.input)
    );
    assert!(object.conflicts.contains(&LayoutConflict::MissingOrigin));
    assert!(object.conflicts.contains(&LayoutConflict::MissingStride));
}

#[test]
fn llir_adapter_rejects_a_memory_sidecar_from_another_function() {
    let llir = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1004,
            instrs: vec![LlirInstr {
                va: 0x1000,
                op: Op::Load {
                    dst: reg("rax"),
                    addr: MemOp::plain(Some(reg("rbx")), None, 0, 0, 8),
                },
            }],
            succs: vec![],
        }],
    };
    let image = x86_image();
    let memory = compute_memory_ssa(
        &LlirFunction {
            entry_va: 0x2000,
            blocks: vec![LlirBlock {
                start_va: 0x2000,
                end_va: 0x2004,
                instrs: vec![],
                succs: vec![],
            }],
        },
        &image,
    );

    assert!(infer_from_llir(&llir, &memory, &image).is_err());
}
