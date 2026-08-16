use super::*;

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn bin(op: crate::ir::types::BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Bin {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn lea(base: &str, displacement: i64) -> Expr {
    Expr::Lea {
        base: Some(reg(base)),
        index: None,
        scale: 0,
        disp: displacement,
        segment: None,
    }
}

fn deref(base: &str, displacement: i64, size: u8) -> Expr {
    Expr::Deref {
        addr: Box::new(lea(base, displacement)),
        size,
    }
}

fn sub(base: &str, amount: i64) -> Expr {
    bin(
        crate::ir::types::BinOp::Sub,
        Expr::Reg(reg(base)),
        Expr::Const(amount),
    )
}

fn add(base: &str, amount: i64) -> Expr {
    bin(
        crate::ir::types::BinOp::Add,
        Expr::Reg(reg(base)),
        Expr::Const(amount),
    )
}

/// The recovered body of `pass_large_by_value` from
/// `tests/decompiler_fixtures/src/129_struct_by_value.c`, compiled at `-O0`
/// with `arm-linux-gnueabihf-gcc -march=armv7-a -mfpu=vfpv3-d16`.
///
/// The two encodings choose different frame registers — A32 keeps AAPCS's `fp`
/// (r11) while Thumb-2 uses `r7` — and different frame-pointer displacements,
/// but they describe ONE source frame. `seed`'s home is at CFA-36 and the
/// `struct Large value` DWARF proves at CFA-28 in both. Anything the shared
/// entry-stack coordinate model recovers for one encoding it must recover for
/// the other.
///
/// `frame_register_origin` is the frame register's value in entry-SP
/// coordinates: A32 establishes `fp = sp + 4` before allocating the frame
/// (CFA-4), Thumb establishes `r7 = sp + 8` after it (CFA-40).
/// `epilogue_through_temporaries` reproduces Thumb's `adds r7, #32` lowering,
/// whose operands are registers rather than a foldable constant.
fn struct_by_value_frame(
    frame_register: &str,
    frame_register_origin: i64,
    epilogue_through_temporaries: bool,
) -> Function {
    let home = -36 - frame_register_origin;
    let aggregate = -28 - frame_register_origin;
    let establish = Stmt::Assign {
        dst: reg(frame_register),
        src: add("sp", frame_register_origin + 48),
    };
    let allocate = Stmt::Assign {
        dst: reg("sp"),
        src: sub("sp", 40),
    };
    let mut body = vec![
        Stmt::Assign {
            dst: reg("sp"),
            src: sub("sp", 8),
        },
        Stmt::Store {
            addr: lea("sp", 0),
            src: Expr::Reg(reg(frame_register)),
            size: 4,
        },
        Stmt::Store {
            addr: lea("sp", 4),
            src: Expr::Reg(reg("lr")),
            size: 4,
        },
    ];
    if epilogue_through_temporaries {
        body.push(allocate);
        body.push(establish);
    } else {
        // A32 fixes the frame register from the post-push SP, so its
        // establishing constant is relative to `entry_sp - 8`, not `- 48`.
        body.push(Stmt::Assign {
            dst: reg(frame_register),
            src: add("sp", frame_register_origin + 8),
        });
        body.push(allocate);
    }
    // `seed`'s argument home. DWARF describes it as a formal parameter, not a
    // stack object, so only the coordinate model can recover it.
    body.push(Stmt::Store {
        addr: lea(frame_register, home),
        src: Expr::Reg(reg("r0")),
        size: 4,
    });
    for field in 0..5i64 {
        body.push(Stmt::Assign {
            dst: reg("r3"),
            src: deref(frame_register, home, 4),
        });
        body.push(Stmt::Store {
            addr: lea(frame_register, aggregate + field * 4),
            src: Expr::Reg(reg("r3")),
            size: 4,
        });
    }
    body.push(Stmt::Assign {
        dst: reg("r3"),
        src: add(frame_register, aggregate),
    });
    body.push(Stmt::Call {
        target: Expr::Addr(0x1000),
        args: vec![Expr::Deref {
            addr: Box::new(lea("r3", 0)),
            size: 4,
        }],
        dst: Some(reg("r0")),
        call_spec: None,
    });
    if epilogue_through_temporaries {
        body.push(Stmt::Assign {
            dst: reg("t41"),
            src: Expr::Reg(reg(frame_register)),
        });
        body.push(Stmt::Assign {
            dst: reg("t45"),
            src: Expr::Const(-8 - frame_register_origin),
        });
        body.push(Stmt::Assign {
            dst: reg(frame_register),
            src: bin(
                crate::ir::types::BinOp::Add,
                Expr::Reg(reg("t41")),
                Expr::Reg(reg("t45")),
            ),
        });
        body.push(Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Reg(reg(frame_register)),
        });
    } else {
        body.push(Stmt::Assign {
            dst: reg("sp"),
            src: sub(frame_register, frame_register_origin + 8),
        });
    }
    body.push(Stmt::Assign {
        dst: reg(frame_register),
        src: deref("sp", 0, 4),
    });
    body.push(Stmt::Assign {
        dst: reg("sp"),
        src: add("sp", 8),
    });
    body.push(Stmt::Return { value: None });
    Function {
        name: "pass_large_by_value".into(),
        entry_va: 0,
        body,
    }
}

/// `struct Large value` as GCC's DWARF describes it in BOTH encodings:
/// `DW_AT_frame_base` is `DW_OP_call_frame_cfa` and the location is
/// `DW_OP_fbreg -28`.
fn struct_large_cfa_hint() -> [StackObjectHint; 1] {
    [StackObjectHint {
        cfa_relative: true,
        base: "entry_sp".into(),
        disp: -28,
        size: 20,
        aggregate: true,
        source_name: Some("value".into()),
        c_type: Some("struct Large".into()),
    }]
}

/// Every promoted name a store in this body writes, in body order.
fn promoted_store_targets(function: &Function) -> Vec<String> {
    function
        .body
        .iter()
        .filter_map(|statement| match statement {
            Stmt::Store { addr, .. } => Some(addr),
            _ => None,
        })
        .map(|addr| match addr {
            Expr::Reg(VReg::Phys(name)) => name.clone(),
            Expr::StackAddr { object, .. } => format!("&{object:?}"),
            Expr::Bin { lhs, rhs, .. } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::StackAddr { object: o, .. }, Expr::Const(offset)) => {
                    format!("&{o:?}+{offset}")
                }
                _ => "<unpromoted>".to_string(),
            },
            _ => "<unpromoted>".to_string(),
        })
        .collect()
}

#[test]
fn thumb_frame_register_shares_the_a32_entry_stack_coordinates() {
    // A32 names the AAPCS frame register `fp`; Thumb-2 names it `r7`. Design
    // rule 11 makes ARM32 a conformance architecture, so one source frame must
    // recover one set of source coordinates regardless of which encoding GCC
    // chose. `seed`'s home is CFA-36 (`local_24`) and `value` is the DWARF
    // aggregate at CFA-28 (`local_1c`) in both.
    let mut a32 = struct_by_value_frame("fp", -4, false);
    let mut thumb = struct_by_value_frame("r7", -40, true);

    let a32_facts = promote_stack_locals_with_facts(
        &mut a32,
        Some(CallConv::ArmHardFloat),
        Some(1),
        &struct_large_cfa_hint(),
    );
    let thumb_facts = promote_stack_locals_with_facts(
        &mut thumb,
        Some(CallConv::ArmHardFloat),
        Some(1),
        &struct_large_cfa_hint(),
    );

    assert_eq!(
        a32_facts.frame_coordinates.get("local_24"),
        Some(&("entry_sp".to_string(), -36)),
        "the A32 control lost the argument home: {a32:#?}"
    );
    assert_eq!(
        thumb_facts.frame_coordinates.get("local_24"),
        Some(&("entry_sp".to_string(), -36)),
        "Thumb's r7 frame register never reached the entry-stack coordinate: {thumb:#?}"
    );
    assert_eq!(
        thumb_facts.source_names.get("local_1c").map(String::as_str),
        Some("value"),
        "Thumb lost the DWARF aggregate identity: {thumb:#?}"
    );
    assert_eq!(
        thumb_facts.source_names.get("local_1c"),
        a32_facts.source_names.get("local_1c"),
        "the two encodings named the DWARF aggregate differently"
    );
    // The first two stores are the callee-save `push`, whose slot genuinely
    // differs between the encodings — A32's `fp` lives at CFA-4, Thumb's `r7`
    // at CFA-40. Every store that follows writes SOURCE storage, and those must
    // agree exactly: one argument home followed by five fields of one
    // twenty-byte aggregate, never a frame-wide byte array.
    assert_eq!(
        &promoted_store_targets(&a32)[2..],
        &promoted_store_targets(&thumb)[2..],
        "A32 and Thumb disagreed about one source frame:\nA32: {a32:#?}\nThumb: {thumb:#?}"
    );
    assert_eq!(
        &promoted_store_targets(&thumb)[2..],
        &[
            "local_24".to_string(),
            "&Phys(\"local_1c\")".to_string(),
            "&Phys(\"local_1c\")+4".to_string(),
            "&Phys(\"local_1c\")+8".to_string(),
            "&Phys(\"local_1c\")+12".to_string(),
            "&Phys(\"local_1c\")+16".to_string(),
        ],
        "Thumb did not recover the source frame: {thumb:#?}"
    );
}

#[test]
fn thumb_scratch_r7_is_not_a_frame_anchor() {
    // The negative control. Without a prologue that derives r7 from sp, r7 is
    // an ordinary callee-saved register — `-O2` Thumb uses it as one — and
    // `[r7+8]` is a pointer dereference, not frame storage. Promoting it would
    // invent a local out of a caller's heap object.
    let mut function = Function {
        name: "scratch_r7".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: reg("r7"),
                src: Expr::Reg(reg("r0")),
            },
            Stmt::Store {
                addr: lea("r7", 8),
                src: Expr::Const(1),
                size: 4,
            },
            Stmt::Assign {
                dst: reg("r1"),
                src: deref("r7", 12, 4),
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("r1"))),
            },
        ],
    };

    promote_stack_locals_typed(&mut function, Some(CallConv::ArmHardFloat));

    assert!(
        matches!(
            &function.body[1],
            Stmt::Store {
                addr: Expr::Lea { base: Some(VReg::Phys(name)), .. },
                ..
            } if name == "r7"
        ),
        "a scratch r7 dereference became frame storage: {function:#?}"
    );
    assert!(
        matches!(
            &function.body[2],
            Stmt::Assign { src: Expr::Deref { addr, .. }, .. }
                if matches!(addr.as_ref(), Expr::Lea { base: Some(VReg::Phys(name)), .. } if name == "r7")
        ),
        "a scratch r7 load became frame storage: {function:#?}"
    );
}

#[test]
fn frame_epilogue_does_not_turn_the_frame_pointer_into_a_byte_array() {
    use crate::ir::types::BinOp;

    // The complete GCC Cortex-M -O0 frame shape copies r7 through a
    // temporary while calculating the epilogue SP. Once the body has exposed
    // several scalar frame slots, that bookkeeping copy must not be mistaken
    // for an escaping array cursor. Doing so collapses the spilled `int wait`
    // and byte local `char c` into one `local_18[24]`.
    let mut function = Function {
        name: "console_getc".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(BinOp::Sub, Expr::Reg(reg("sp")), Expr::Const(4)),
            },
            Stmt::Store {
                addr: lea("sp", 0),
                src: Expr::Reg(reg("r7")),
                size: 4,
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(BinOp::Sub, Expr::Reg(reg("sp")), Expr::Const(20)),
            },
            Stmt::Assign {
                dst: reg("r7#1"),
                src: bin(BinOp::Add, Expr::Reg(reg("sp")), Expr::Const(0)),
            },
            Stmt::Store {
                addr: lea("r7#1", 4),
                src: Expr::Reg(reg("r0")),
                size: 4,
            },
            Stmt::Store {
                addr: lea("r7#1", 15),
                src: Expr::Const(0),
                size: 1,
            },
            Stmt::Assign {
                dst: reg("r3#1"),
                src: deref("r7#1", 15, 1),
            },
            Stmt::Assign {
                dst: reg("t43"),
                src: Expr::Reg(reg("r7#1")),
            },
            Stmt::Assign {
                dst: reg("t44"),
                src: Expr::Const(20),
            },
            Stmt::Assign {
                dst: reg("r7#2"),
                src: bin(BinOp::Add, Expr::Reg(reg("t43")), Expr::Reg(reg("t44"))),
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: Expr::Reg(reg("r7#2")),
            },
            Stmt::Assign {
                dst: reg("r7#3"),
                src: deref("sp", 0, 4),
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(BinOp::Add, Expr::Reg(reg("sp")), Expr::Const(4)),
            },
            Stmt::Return { value: None },
        ],
    };

    let sizes = promote_stack_locals_typed(&mut function, Some(CallConv::Arm));

    assert!(
        matches!(
            &function.body[5],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_9"
        ),
        "the byte local was absorbed into the machine frame: {function:#?}"
    );
    assert_eq!(sizes.get("local_9"), Some(&1));
    assert!(
        !sizes.contains_key("local_18"),
        "the machine frame must not become a source byte array: {function:#?}"
    );
}

#[test]
fn a32_frame_pointer_address_rejoins_the_entry_cfa_object() {
    // A32's canonical prologue establishes fp at entry_sp-4 before allocating
    // the local frame. DWARF says parents begins at CFA-332, while the machine
    // spells the same address fp-328. The terminal fp restore must not make the
    // earlier reaching frame definition globally ambiguous.
    let mut function = Function {
        name: "rb_validate_a32_o0".into(),
        entry_va: 0,
        body: vec![
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(
                    crate::ir::types::BinOp::Sub,
                    Expr::Reg(reg("sp")),
                    Expr::Const(8),
                ),
            },
            Stmt::Assign {
                dst: reg("fp"),
                src: bin(
                    crate::ir::types::BinOp::Add,
                    Expr::Reg(reg("sp")),
                    Expr::Const(4),
                ),
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(
                    crate::ir::types::BinOp::Sub,
                    Expr::Reg(reg("sp")),
                    Expr::Const(384),
                ),
            },
            Stmt::Call {
                target: Expr::Addr(0x1000),
                args: vec![lea("fp", -328), Expr::Const(0), Expr::Const(64)],
                dst: None,
                call_spec: None,
            },
            Stmt::Assign {
                dst: reg("sp"),
                src: bin(
                    crate::ir::types::BinOp::Sub,
                    Expr::Reg(reg("fp")),
                    Expr::Const(4),
                ),
            },
            Stmt::Assign {
                dst: reg("fp"),
                src: Expr::Deref {
                    addr: Box::new(lea("sp", 0)),
                    size: 4,
                },
            },
            Stmt::Return { value: None },
        ],
    };

    promote_stack_locals_typed_with_parameter_count_and_objects(
        &mut function,
        Some(CallConv::ArmHardFloat),
        Some(3),
        &[StackObjectHint {
            cfa_relative: true,
            base: "entry_sp".into(),
            disp: -332,
            size: 64,
            aggregate: true,
            source_name: None,
            c_type: None,
        }],
    );

    assert!(
        matches!(
            &function.body[3],
            Stmt::Call { args, .. }
                if matches!(args.as_slice(), [
                    Expr::StackAddr { object, size: 64 },
                    Expr::Const(0),
                    Expr::Const(64),
                ] if object == &reg("local_14c"))
        ),
        "fp-relative call address did not rejoin CFA-332: {function:#?}"
    );
}

#[test]
fn a32_fallthrough_branch_restore_invalidates_the_frame_coordinate() {
    // A dead-looking fp overwrite at the end of a nested branch is not
    // terminal when the branch falls through to an outer fp-relative use.
    // Treating it like an epilogue restore would preserve a stale coordinate
    // on one path and unsafely promote the later access.
    let body = vec![
        Stmt::Assign {
            dst: reg("sp"),
            src: bin(
                crate::ir::types::BinOp::Sub,
                Expr::Reg(reg("sp")),
                Expr::Const(8),
            ),
        },
        Stmt::Assign {
            dst: reg("fp"),
            src: bin(
                crate::ir::types::BinOp::Add,
                Expr::Reg(reg("sp")),
                Expr::Const(4),
            ),
        },
        Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![Stmt::Assign {
                dst: reg("fp"),
                src: Expr::Deref {
                    addr: Box::new(lea("sp", 0)),
                    size: 4,
                },
            }],
            else_body: None,
        },
        Stmt::Call {
            target: Expr::Addr(0x1000),
            args: vec![lea("fp", -328)],
            dst: None,
            call_spec: None,
        },
        Stmt::Return { value: None },
    ];

    let definitions = collect_stack_address_defs(
        &body,
        StackContext {
            cc: Some(CallConv::ArmHardFloat),
            rbp_repurposed: false,
            frame_pointer_established: false,
            arm_frame_register: Some("fp"),
            parameter_count: Some(3),
        },
        &HashMap::new(),
    );

    assert!(
        !definitions.contains_key(&reg("fp")),
        "fall-through restore retained a stale frame coordinate: {definitions:#?}"
    );
}

#[test]
fn a_reused_temporary_does_not_backdate_the_frame_coordinate() {
    // GCC's pre-value-folding Thumb lowering reuses ONE temporary for both an
    // integer loaded from the frame and, in the epilogue, the frame register
    // itself. The alias map is keyed by register, so recording only the
    // epilogue's address made the earlier `t0 + t1` adds — ordinary integer
    // arithmetic — look like subscripted frame accesses at the frame register's
    // own coordinate, which seeded a byte object over the whole frame.
    //
    // The dual coordinate model has to refuse an alias a register does not hold
    // everywhere. Real shape: `129_struct_by_value:armv7:O0`.
    let body = vec![
        Stmt::Assign {
            dst: reg("sp"),
            src: sub("sp", 48),
        },
        Stmt::Assign {
            dst: reg("r7"),
            src: add("sp", 8),
        },
        // The integer use: `t0` holds a loaded value here, not an address.
        Stmt::Assign {
            dst: reg("t0"),
            src: deref("r7", 4, 4),
        },
        Stmt::Assign {
            dst: reg("t1"),
            src: Expr::Const(1),
        },
        Stmt::Assign {
            dst: reg("r3"),
            src: bin(
                crate::ir::types::BinOp::Add,
                Expr::Reg(reg("t0")),
                Expr::Reg(reg("t1")),
            ),
        },
        // The epilogue reuses the same temporary for the frame address.
        Stmt::Assign {
            dst: reg("t0"),
            src: Expr::Reg(reg("r7")),
        },
        Stmt::Assign {
            dst: reg("t1"),
            src: Expr::Const(40),
        },
        Stmt::Assign {
            dst: reg("r7"),
            src: bin(
                crate::ir::types::BinOp::Add,
                Expr::Reg(reg("t0")),
                Expr::Reg(reg("t1")),
            ),
        },
        Stmt::Assign {
            dst: reg("sp"),
            src: Expr::Reg(reg("r7")),
        },
        Stmt::Return { value: None },
    ];

    let definitions = collect_stack_address_defs(
        &body,
        StackContext {
            cc: Some(CallConv::ArmHardFloat),
            rbp_repurposed: false,
            frame_pointer_established: false,
            arm_frame_register: Some("r7"),
            parameter_count: None,
        },
        &HashMap::new(),
    );

    assert_eq!(
        definitions.get(&reg("r7")),
        Some(&("entry_sp".to_string(), -40)),
        "the established Thumb frame coordinate was lost: {definitions:#?}"
    );
    assert!(
        !definitions.contains_key(&reg("t0")),
        "a reused temporary carried the frame coordinate over its integer uses: \
         {definitions:#?}"
    );
}
