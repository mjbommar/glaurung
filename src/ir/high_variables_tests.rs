use super::refine_pointer_high_variables;
use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};
use crate::ir::types::{BinOp, VReg};
use crate::ir::types_recover::{TypeHint, TypeMap};

fn pointer_width(types: &TypeMap, name: &str) -> Option<u8> {
    match types.get(&VReg::phys(name)) {
        Some(TypeHint::Pointer { pointee_width }) => Some(pointee_width),
        _ => None,
    }
}

#[test]
fn exact_integer_value_width_survives_pointer_refinement() {
    let function = Function {
        name: "negative_cases".into(),
        entry_va: 0,
        body: vec![Stmt::Assign {
            dst: VReg::phys("var0"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                rhs: Box::new(Expr::Const(3)),
            },
        }],
    };
    let mut types = TypeMap::default();
    types.upsert_public(
        VReg::phys("var0"),
        TypeHint::Int {
            signed: false,
            width: 4,
        },
    );

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(
        types.get(&VReg::phys("var0")),
        Some(TypeHint::Int {
            signed: false,
            width: 4,
        })
    );
}

#[test]
fn known_call_and_literal_flow_through_exact_copy_chain() {
    let function = Function {
        name: "f".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "getenv@plt".into(),
                },
                args: vec![Expr::StringLit {
                    value: "PATH".into(),
                }],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
            Stmt::Store {
                addr: Expr::Reg(VReg::phys("local_8")),
                src: Expr::Reg(VReg::phys("var1")),
                size: 8,
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::StringLit {
                    value: "/tmp/fallback".into(),
                },
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var1"), Some(1));
    assert_eq!(pointer_width(&types, "local_8"), Some(1));
    assert_eq!(pointer_width(&types, "var2"), Some(1));
}

#[test]
fn recovered_callee_pointer_result_flows_through_an_exact_copy() {
    let recovered = CallPrototype {
        return_type: "void *".into(),
        parameter_types: vec![],
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    let function = Function {
        name: "copy_project_pointer".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "project_device".into(),
                },
                args: vec![],
                dst: Some(VReg::phys("var1")),
                call_spec: Some(CallSiteSpec {
                    callee_prototype: Some(recovered.clone()),
                    call_prototype: recovered,
                }),
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Reg(VReg::phys("var1")),
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var1"), Some(0));
    assert_eq!(pointer_width(&types, "var2"), Some(0));
}

#[test]
fn null_initialized_local_accepts_a_later_character_pointer() {
    let function = Function {
        name: "save_locale".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("local_8"),
                src: Expr::Const(0),
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strdup@plt".into(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0"))],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
            Stmt::Assign {
                dst: VReg::phys("local_8"),
                src: Expr::Reg(VReg::phys("var1")),
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var1"), Some(1));
    assert_eq!(pointer_width(&types, "local_8"), Some(1));
}

#[test]
fn authoritative_call_parameter_refines_a_direct_function_argument() {
    let function = Function {
        name: "find_name".into(),
        entry_va: 0,
        body: vec![Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: "strcmp@plt".into(),
            },
            args: vec![
                Expr::Reg(VReg::phys("arg0")),
                Expr::StringLit {
                    value: "known".into(),
                },
            ],
            dst: Some(VReg::phys("var1")),
            call_spec: None,
        }],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), Some(1));
}

#[test]
fn authoritative_character_use_does_not_retype_an_unknown_call_temporary() {
    // A consumer contract proves how this value is used at one boundary,
    // not the source-level return type of an otherwise unknown helper.
    // Keep the ephemeral call result scalar and put any required cast at
    // the call boundary; promoted locals may still recover independently
    // when all of their definitions and uses establish one source type.
    let function = Function {
        name: "consume_unknown_result".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "project_value".into(),
                },
                args: vec![],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strlen@plt".into(),
                },
                args: vec![Expr::Reg(VReg::phys("var1"))],
                dst: Some(VReg::phys("var2")),
                call_spec: None,
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var1"), None);
}

#[test]
fn recovered_direct_callee_parameter_refines_a_forwarded_argument() {
    let recovered = CallPrototype {
        return_type: "int".into(),
        parameter_types: vec!["int *".into()],
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    let function = Function {
        name: "forward_pointer".into(),
        entry_va: 0,
        body: vec![Stmt::Call {
            target: Expr::Named {
                va: 0x2000,
                name: "read_first".into(),
            },
            args: vec![Expr::Reg(VReg::phys("arg0"))],
            dst: Some(VReg::phys("ret")),
            call_spec: Some(CallSiteSpec {
                call_prototype: recovered.clone(),
                callee_prototype: Some(recovered),
            }),
        }],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), Some(4));
}

#[test]
fn recovered_callee_pointer_flows_back_through_one_exact_parameter_copy() {
    // Real shape: diffutils `lf_skip(struct line_filter *lf, lin lines)`.
    // The incoming pointer is copied to a numbered value, used in raw byte
    // address arithmetic, and passed to a helper whose recovered contract
    // is the only source-level pointer witness. Keep the numbered value a
    // machine word so `+ 8` remains byte-addressed, but recover the source
    // parameter transported into it.
    let recovered = CallPrototype {
        return_type: "int".into(),
        parameter_types: vec!["long *".into()],
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    let function = Function {
        name: "lf_skip_shape".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Reg(VReg::phys("arg0")),
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "refill".into(),
                },
                args: vec![Expr::Reg(VReg::phys("var2"))],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    call_prototype: recovered.clone(),
                    callee_prototype: Some(recovered),
                }),
            },
            Stmt::Assign {
                dst: VReg::phys("var3"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("var2"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), Some(8));
    assert_eq!(pointer_width(&types, "var2"), None);
}

#[test]
fn conflicting_alias_contracts_do_not_randomly_retype_their_parameter() {
    let recovered = CallPrototype {
        return_type: "int".into(),
        parameter_types: vec!["long *".into()],
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    let function = Function {
        name: "conflicting_alias_contracts".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::Reg(VReg::phys("arg0")),
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Reg(VReg::phys("arg0")),
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strcmp@plt".into(),
                },
                args: vec![
                    Expr::Reg(VReg::phys("var1")),
                    Expr::StringLit {
                        value: "known".into(),
                    },
                ],
                dst: Some(VReg::phys("cmp")),
                call_spec: None,
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "consume_longs".into(),
                },
                args: vec![Expr::Reg(VReg::phys("var2"))],
                dst: Some(VReg::phys("ret")),
                call_spec: Some(CallSiteSpec {
                    call_prototype: recovered.clone(),
                    callee_prototype: Some(recovered),
                }),
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), None);
}

#[test]
fn recovered_callee_pointer_rejects_a_copy_with_conflicting_origins() {
    let recovered = CallPrototype {
        return_type: "int".into(),
        parameter_types: vec!["long *".into()],
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    };
    let function = Function {
        name: "overwritten_forwarder".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Reg(VReg::phys("arg0")),
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Reg(VReg::phys("arg1")),
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0x2000,
                    name: "consume_pointer".into(),
                },
                args: vec![Expr::Reg(VReg::phys("var2"))],
                dst: None,
                call_spec: Some(CallSiteSpec {
                    call_prototype: recovered.clone(),
                    callee_prototype: Some(recovered),
                }),
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), None);
    assert_eq!(pointer_width(&types, "arg1"), None);
}

#[test]
fn integer_arithmetic_blocks_call_parameter_pointer_refinement() {
    let function = Function {
        name: "tagged_name".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strcmp@plt".into(),
                },
                args: vec![
                    Expr::Reg(VReg::phys("arg0")),
                    Expr::StringLit {
                        value: "known".into(),
                    },
                ],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
            Stmt::Assign {
                dst: VReg::phys("local_30"),
                src: Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(7)),
                },
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), None);
}

#[test]
fn character_arithmetic_does_not_retype_an_abi_parameter() {
    // The promoted-local exception must not become a second ABI prototype
    // inference path. An argument consumed as text and incremented may be
    // a source pointer, but proving that belongs to value-keyed prototype
    // recovery; this pass only owns high/local declaration refinement.
    let function = Function {
        name: "copy_text".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strlen@plt".into(),
                },
                args: vec![Expr::Reg(VReg::phys("arg0"))],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), None);
}

#[test]
fn unsafe_pointer_input_does_not_retype_its_machine_copy() {
    // A separately recovered ABI spelling may already call the argument a
    // pointer. If this pass rejects its additive use, it must not leak that
    // rejected interpretation into a numbered machine temporary. The
    // source-level parameter spelling remains owned by prototype recovery.
    let function = Function {
        name: "copy_text".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::Reg(VReg::phys("arg0")),
            },
            Stmt::Assign {
                dst: VReg::phys("arg0"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
            Stmt::Store {
                addr: Expr::Reg(VReg::phys("var1")),
                src: Expr::Const(0),
                size: 1,
            },
        ],
    };
    let mut types = TypeMap::default();
    types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 1 });

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "arg0"), Some(1));
    assert_eq!(pointer_width(&types, "var1"), None);
}

#[test]
fn character_pointer_arithmetic_preserves_proven_copied_pointers() {
    // Real shape: gzip O0 `get_method` advances one character pointer and
    // subtracts its copied base. Both operations are valid byte-scaled C
    // pointer arithmetic and must not erase independent `char *` evidence.
    let function = Function {
        name: "character_cursor".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "project_base".into(),
                },
                args: vec![],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
            Stmt::Assign {
                dst: VReg::phys("local_30"),
                src: Expr::Reg(VReg::phys("var1")),
            },
            Stmt::Assign {
                dst: VReg::phys("local_20"),
                src: Expr::Reg(VReg::phys("local_30")),
            },
            Stmt::Store {
                addr: Expr::Lea {
                    base: Some(VReg::phys("local_30")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    segment: None,
                },
                src: Expr::Const(0),
                size: 1,
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("local_30"))),
                    rhs: Box::new(Expr::Const(1)),
                },
            },
            Stmt::Assign {
                dst: VReg::phys("var3"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(VReg::phys("local_30"))),
                    rhs: Box::new(Expr::Reg(VReg::phys("local_20"))),
                },
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "strlen@plt".into(),
                },
                args: vec![Expr::Reg(VReg::phys("local_30"))],
                dst: Some(VReg::phys("var4")),
                call_spec: None,
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "memmove@plt".into(),
                },
                args: vec![
                    Expr::Reg(VReg::phys("local_20")),
                    Expr::Reg(VReg::phys("local_30")),
                    Expr::Const(4),
                ],
                dst: Some(VReg::phys("var5")),
                call_spec: None,
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "local_30"), Some(1));
    assert_eq!(pointer_width(&types, "local_20"), Some(1));
}

#[test]
fn multiply_defined_promoted_local_rejects_opaque_and_concrete_pointer_lifetimes() {
    // Real negative shape: coreutils `dopass` reuses one promoted stack
    // slot for an opaque helper result and `errno`. Without reaching
    // definitions, merging those lifetimes into `int *` is unsound.
    let function = Function {
        name: "reused_slot".into(),
        entry_va: 0,
        body: vec![
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "malloc@plt".into(),
                },
                args: vec![Expr::Const(8)],
                dst: Some(VReg::phys("local_850")),
                call_spec: None,
            },
            Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "__errno_location@plt".into(),
                },
                args: vec![],
                dst: Some(VReg::phys("local_850")),
                call_spec: None,
            },
        ],
    };
    let mut types = TypeMap::default();

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "local_850"), None);
}

#[test]
fn conflicting_definition_or_integer_use_blocks_pointer_declaration() {
    let function = Function {
        name: "f".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::StringLit { value: "a".into() },
            },
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Const(7),
            },
            Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::StringLit { value: "b".into() },
            },
            Stmt::Assign {
                dst: VReg::phys("var2"),
                src: Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(Expr::Reg(VReg::phys("var1"))),
                    rhs: Box::new(Expr::Const(-16)),
                },
            },
        ],
    };
    let mut types = TypeMap::default();
    // A legacy storage-keyed collision must not bypass the exact
    // multi-definition proof merely because it is already a pointer.
    types.upsert_public(VReg::phys("var0"), TypeHint::Pointer { pointee_width: 1 });

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var0"), None);
    assert_eq!(pointer_width(&types, "var1"), None);
}

#[test]
fn structural_stack_register_type_does_not_seed_a_source_pointer() {
    let function = Function {
        name: "f".into(),
        entry_va: 0,
        body: vec![Stmt::Assign {
            dst: VReg::phys("var0"),
            src: Expr::Reg(VReg::phys("sp")),
        }],
    };
    let mut types = TypeMap::default();
    types.upsert_public(VReg::phys("sp"), TypeHint::Pointer { pointee_width: 4 });

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var0"), None);
}

#[test]
fn select_accepts_null_but_rejects_incompatible_pointer_arms() {
    let function = Function {
        name: "f".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Select {
                    cond: Box::new(Expr::Const(1)),
                    if_true: Box::new(Expr::StringLit { value: "p".into() }),
                    if_false: Box::new(Expr::Const(0)),
                    width: 8,
                },
            },
            Stmt::Assign {
                dst: VReg::phys("local_8"),
                src: Expr::Select {
                    cond: Box::new(Expr::Const(1)),
                    if_true: Box::new(Expr::Reg(VReg::phys("var0"))),
                    if_false: Box::new(Expr::Reg(VReg::phys("arg0"))),
                    width: 8,
                },
            },
        ],
    };
    let mut types = TypeMap::default();
    types.upsert_public(VReg::phys("arg0"), TypeHint::Pointer { pointee_width: 4 });

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "var0"), Some(1));
    assert_eq!(pointer_width(&types, "local_8"), None);
}

#[test]
fn pointer_copy_into_conflicted_word_keeps_explicit_machine_cast() {
    let function = Function {
        name: "f".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::StringLit { value: "p".into() },
            },
            Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::Reg(VReg::phys("var0")),
            },
            Stmt::Assign {
                dst: VReg::phys("var1"),
                src: Expr::Const(1),
            },
        ],
    };
    let mut types = TypeMap::default();
    refine_pointer_high_variables(&function, &mut types);

    let rendered = crate::ir::ast::render_decbench_typed(&function, Some(&types), None);

    assert!(rendered.contains("char * var0;"), "{rendered}");
    assert!(rendered.contains("long var1;"), "{rendered}");
    assert!(rendered.contains("var1 = (long)var0;"), "{rendered}");
}

#[test]
fn pointer_stored_through_width_only_memory_is_explicitly_represented() {
    let function = Function {
        name: "f".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::StringLit { value: "p".into() },
            },
            Stmt::Store {
                addr: Expr::Addr(0x1000),
                src: Expr::Reg(VReg::phys("var0")),
                size: 4,
            },
        ],
    };
    let mut types = TypeMap::default();
    refine_pointer_high_variables(&function, &mut types);

    let rendered = crate::ir::ast::render_decbench_typed(&function, Some(&types), None);

    assert!(
        rendered
            .contains("static unsigned char glaurung_global_1000[4] __attribute__((aligned(16)));"),
        "the original image address needs portable storage:\n{rendered}"
    );
    assert!(
        rendered.contains("*(int *)(&glaurung_global_1000[0]) = (int)((long)var0);"),
        "the 4-byte pointer-to-integer store must remain explicit:\n{rendered}"
    );
    assert!(!rendered.contains("*(int *)(0x1000)"), "{rendered}");
}

#[test]
fn proven_aggregate_cursor_becomes_a_byte_pointer_without_scaling_its_stride() {
    let cursor = VReg::phys("local_8");
    let offset = |value| Expr::Bin {
        op: BinOp::Add,
        lhs: Box::new(Expr::Reg(cursor.clone())),
        rhs: Box::new(Expr::Const(value)),
    };
    let function = Function {
        name: "walk_records".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Store {
                addr: Expr::Reg(cursor.clone()),
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
                        addr: offset(44),
                        src: Expr::Const(7),
                        size: 4,
                    },
                    Stmt::Store {
                        addr: offset(40),
                        src: Expr::Const(3),
                        size: 4,
                    },
                    Stmt::Store {
                        addr: Expr::Reg(cursor.clone()),
                        src: offset(64),
                        size: 8,
                    },
                ],
            },
        ],
    };
    let mut types = TypeMap::default();
    types.upsert_public(
        cursor,
        TypeHint::Int {
            signed: true,
            width: 8,
        },
    );

    refine_pointer_high_variables(&function, &mut types);
    let rendered = crate::ir::ast::render_decbench_typed(&function, Some(&types), None);

    assert_eq!(pointer_width(&types, "local_8"), Some(1));
    assert!(
        rendered.contains("char * local_8 = (char *)("),
        "{rendered}"
    );
    assert!(rendered.contains("(local_8 + 64)"), "{rendered}");
    assert!(!rendered.contains("local_8 + 256"), "{rendered}");
}

#[test]
fn unbounded_dereferenced_word_does_not_become_an_aggregate_cursor() {
    let function = Function {
        name: "one_load".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: VReg::phys("local_8"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Addr(0x4000)),
                    size: 8,
                },
            },
            Stmt::Store {
                addr: Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Reg(VReg::phys("local_8"))),
                    rhs: Box::new(Expr::Const(4)),
                },
                src: Expr::Const(1),
                size: 4,
            },
        ],
    };
    let mut types = TypeMap::default();
    types.upsert_public(
        VReg::phys("local_8"),
        TypeHint::Int {
            signed: true,
            width: 8,
        },
    );

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "local_8"), None);
}

#[test]
fn aggregate_cursor_waits_for_its_pointer_origin_in_the_same_fixed_point() {
    let origin = VReg::phys("local_10");
    let cursor = VReg::phys("local_8");
    let offset = |value| Expr::Bin {
        op: BinOp::Add,
        lhs: Box::new(Expr::Reg(cursor.clone())),
        rhs: Box::new(Expr::Const(value)),
    };
    let function = Function {
        name: "walk_copied_records".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Store {
                addr: Expr::Reg(origin.clone()),
                src: Expr::StringLit {
                    value: "storage".into(),
                },
                size: 8,
            },
            Stmt::Store {
                addr: Expr::Reg(cursor.clone()),
                src: Expr::Reg(origin.clone()),
                size: 8,
            },
            Stmt::Store {
                addr: offset(40),
                src: Expr::Const(3),
                size: 4,
            },
            Stmt::Store {
                addr: Expr::Reg(cursor.clone()),
                src: offset(64),
                size: 8,
            },
        ],
    };
    let mut types = TypeMap::default();
    for register in [origin, cursor] {
        types.upsert_public(
            register,
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );
    }

    refine_pointer_high_variables(&function, &mut types);

    assert_eq!(pointer_width(&types, "local_10"), Some(1));
    assert_eq!(pointer_width(&types, "local_8"), Some(1));
}
