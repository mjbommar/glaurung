//! The normaliser's specification: one test per rule, one per bound, and the
//! two tests that keep the artifact separate from the decompiler.
//!
//! Every case is hand-built LLIR. A peephole pass is a local rewrite over a
//! straight-line block, so a block written out by hand states the rule exactly
//! and a real binary would state it only incidentally.

use std::collections::BTreeMap;

use super::{
    common, constants, cse, normalize_function, normalize_function_with, opcodes, polarity,
    redundancy, strength, Passes, MAX_ROUNDS,
};
use crate::identity::cfr::graph::GraphContext;
use crate::identity::cfr::signature::{CfrSettings, CfrSignature};
use crate::identity::cfr::signature_of;
use crate::identity::cfr::stack::stack_registers_for;
use crate::ir::call_args::CallConv;
use crate::ir::ssa::compute_ssa;
use crate::ir::types::{
    BinOp, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, UnOp, VReg, Value, Width,
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn block(start: u64, ops: Vec<Op>, succs: Vec<u64>) -> LlirBlock {
    LlirBlock {
        start_va: start,
        end_va: start + ops.len() as u64,
        instrs: ops
            .into_iter()
            .enumerate()
            .map(|(index, op)| LlirInstr {
                va: start + index as u64,
                op,
            })
            .collect(),
        succs,
    }
}

fn one_block(ops: Vec<Op>) -> LlirFunction {
    LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(0x1000, ops, vec![])],
    }
}

fn ops_of(function: &LlirFunction) -> Vec<Op> {
    function.blocks[0]
        .instrs
        .iter()
        .map(|instruction| instruction.op.clone())
        .collect()
}

fn only(function: &LlirFunction, passes: Passes) -> Vec<Op> {
    ops_of(&normalize_function_with(function, passes))
}

fn reg(name: &str) -> Value {
    Value::Reg(VReg::phys(name))
}

fn temp(index: u32) -> Value {
    Value::Reg(VReg::Temp(index))
}

// ---------------------------------------------------------------------------
// (a) same-semantics opcode collapse
// ---------------------------------------------------------------------------

#[test]
fn xor_of_a_register_with_itself_becomes_a_zero() {
    let function = one_block(vec![Op::Bin {
        dst: VReg::phys("rax"),
        op: BinOp::Xor,
        lhs: reg("rax"),
        rhs: reg("rax"),
    }]);
    assert_eq!(
        only(&function, Passes::OPCODES),
        vec![Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Const(0),
        }]
    );
}

#[test]
fn subtraction_of_a_constant_becomes_addition_of_its_negation() {
    let function = one_block(vec![Op::Bin {
        dst: VReg::phys("rsp"),
        op: BinOp::Sub,
        lhs: reg("rsp"),
        rhs: Value::Const(8),
    }]);
    assert_eq!(
        only(&function, Passes::OPCODES),
        vec![Op::Bin {
            dst: VReg::phys("rsp"),
            op: BinOp::Add,
            lhs: reg("rsp"),
            rhs: Value::Const(-8),
        }]
    );
}

/// `i64::MIN` has no negation, so the one spelling that cannot be rewritten
/// stays exactly as it was rather than wrapping to itself.
#[test]
fn the_unnegatable_constant_is_left_alone() {
    let function = one_block(vec![Op::Bin {
        dst: VReg::phys("rax"),
        op: BinOp::Sub,
        lhs: reg("rax"),
        rhs: Value::Const(i64::MIN),
    }]);
    assert_eq!(only(&function, Passes::OPCODES), ops_of(&function));
}

#[test]
fn an_identity_operand_collapses_the_operator_to_a_copy() {
    let cases = vec![
        (BinOp::Add, Value::Const(0)),
        (BinOp::Or, Value::Const(0)),
        (BinOp::Xor, Value::Const(0)),
        (BinOp::Shl, Value::Const(0)),
        (BinOp::Mul, Value::Const(1)),
        (BinOp::And, Value::Const(-1)),
    ];
    for (kind, identity) in cases {
        let function = one_block(vec![Op::Bin {
            dst: VReg::Temp(1),
            op: kind,
            lhs: reg("rdi"),
            rhs: identity.clone(),
        }]);
        assert_eq!(
            only(&function, Passes::OPCODES),
            vec![Op::Assign {
                dst: VReg::Temp(1),
                src: reg("rdi"),
            }],
            "{kind:?} with {identity:?} should collapse to a copy"
        );
    }
}

#[test]
fn an_intrinsic_loses_its_width_suffix() {
    let function = one_block(vec![Op::Intrinsic {
        name: "x86.smul_hi.64".into(),
        ins: vec![reg("rax"), reg("rcx")],
        outs: vec![(VReg::phys("rdx"), Width::W64)],
        reads_mem: false,
        writes_mem: false,
    }]);
    let Op::Intrinsic { name, .. } = &only(&function, Passes::OPCODES)[0] else {
        panic!("still an intrinsic");
    };
    assert_eq!(name, "x86.smul_hi");
}

/// A name whose last component is not purely numeric keeps it: `pshufb` is not
/// a width-suffixed `pshu`.
#[test]
fn a_non_numeric_suffix_survives() {
    let function = one_block(vec![Op::Intrinsic {
        name: "x86.rdtsc".into(),
        ins: vec![],
        outs: vec![(VReg::phys("rax"), Width::W64)],
        reads_mem: false,
        writes_mem: false,
    }]);
    assert_eq!(only(&function, Passes::OPCODES), ops_of(&function));
}

#[test]
fn a_width_neutral_cast_becomes_a_copy() {
    let function = one_block(vec![Op::ZExt {
        dst: VReg::phys("rax"),
        src: reg("rdi"),
        from: Width::W64,
        to: Width::W64,
    }]);
    assert_eq!(
        only(&function, Passes::OPCODES),
        vec![Op::Assign {
            dst: VReg::phys("rax"),
            src: reg("rdi"),
        }]
    );
}

#[test]
fn the_wide_division_intrinsic_becomes_the_division_node() {
    let function = one_block(vec![Op::Intrinsic {
        name: "x86.sdiv_quot.32".into(),
        ins: vec![reg("rdx"), reg("rax"), reg("rcx")],
        outs: vec![(VReg::phys("rax"), Width::W32)],
        reads_mem: false,
        writes_mem: false,
    }]);
    assert_eq!(
        only(&function, Passes::OPCODES),
        vec![Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Div,
            lhs: reg("rax"),
            rhs: reg("rcx"),
        }]
    );
}

// ---------------------------------------------------------------------------
// (b) constant folding and copy propagation
// ---------------------------------------------------------------------------

#[test]
fn a_copy_chain_is_forwarded_to_its_source() {
    let function = one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: reg("rdi"),
        },
        Op::Assign {
            dst: VReg::Temp(1),
            src: temp(0),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: temp(1),
            rhs: reg("rsi"),
        },
    ]);
    let out = only(&function, Passes::CONSTANTS);
    assert_eq!(
        out[2],
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: reg("rsi"),
        }
    );
}

#[test]
fn two_constant_operands_are_evaluated() {
    let function = one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: Value::Const(6),
        },
        Op::Bin {
            dst: VReg::Temp(1),
            op: BinOp::Mul,
            lhs: temp(0),
            rhs: Value::Const(7),
        },
    ]);
    assert_eq!(
        only(&function, Passes::CONSTANTS)[1],
        Op::Assign {
            dst: VReg::Temp(1),
            src: Value::Const(42),
        }
    );
}

/// The invariant that keeps a local rewriter honest: `rdi` is read and never
/// written here, so it is a parameter of the peephole and survives.
#[test]
fn a_value_used_but_not_defined_in_the_peephole_survives() {
    let function = one_block(vec![Op::Bin {
        dst: VReg::phys("rax"),
        op: BinOp::Add,
        lhs: reg("rdi"),
        rhs: reg("rsi"),
    }]);
    assert_eq!(ops_of(&normalize_function(&function)), ops_of(&function));
}

#[test]
fn a_redefinition_kills_the_copy_that_named_it() {
    let function = one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: reg("rdi"),
        },
        Op::Assign {
            dst: VReg::phys("rdi"),
            src: Value::Const(1),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: temp(0),
            rhs: reg("rsi"),
        },
    ]);
    // `t0` must NOT be replaced by `rdi`, which now holds something else.
    let out = only(&function, Passes::CONSTANTS);
    assert_eq!(
        out[2],
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: temp(0),
            rhs: reg("rsi"),
        }
    );
}

#[test]
fn a_call_forgets_everything_the_environment_knew() {
    let function = one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: reg("rdi"),
        },
        Op::Call {
            target: crate::ir::types::CallTarget::Direct(0x2000),
            effects: None,
        },
        Op::Assign {
            dst: VReg::phys("rax"),
            src: temp(0),
        },
    ]);
    let out = only(&function, Passes::CONSTANTS);
    assert_eq!(
        out[2],
        Op::Assign {
            dst: VReg::phys("rax"),
            src: temp(0),
        }
    );
}

/// The `lea` expansion's `tmp = 0` seed: a constant base folds into the
/// displacement so the address expression is a bare frame offset.
#[test]
fn a_constant_base_folds_into_the_displacement() {
    let function = one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: Value::Const(0x1000),
        },
        Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::Temp(0)), None, 0, 0x20, 8),
        },
    ]);
    let Op::Load { addr, .. } = &only(&function, Passes::CONSTANTS)[1] else {
        panic!("still a load");
    };
    assert_eq!(addr.base, None);
    assert_eq!(addr.disp, 0x1020);
}

/// Folding is done in `i64` regardless of the destination's real width, which
/// is the documented unsoundness. Pinned so a future change to the arithmetic
/// is a deliberate one.
#[test]
fn folding_ignores_the_destination_width() {
    let function = one_block(vec![
        Op::Assign {
            dst: VReg::phys("eax"),
            src: Value::Const(i64::from(i32::MAX)),
        },
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Add,
            lhs: reg("eax"),
            rhs: Value::Const(1),
        },
    ]);
    assert_eq!(
        only(&function, Passes::CONSTANTS)[1],
        Op::Assign {
            dst: VReg::phys("eax"),
            // A 32-bit machine would wrap to `i32::MIN`; this does not.
            src: Value::Const(i64::from(i32::MAX) + 1),
        }
    );
}

// ---------------------------------------------------------------------------
// (c) local CSE
// ---------------------------------------------------------------------------

#[test]
fn a_repeated_expression_becomes_a_copy_of_the_first_result() {
    let function = one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: Value::Const(8),
        },
        Op::Bin {
            dst: VReg::Temp(1),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: Value::Const(8),
        },
    ]);
    assert_eq!(
        only(&function, Passes::CSE)[1],
        Op::Assign {
            dst: VReg::Temp(1),
            src: temp(0),
        }
    );
}

#[test]
fn cse_stops_at_a_redefinition_of_an_operand() {
    let function = one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: Value::Const(8),
        },
        Op::Assign {
            dst: VReg::phys("rdi"),
            src: Value::Const(3),
        },
        Op::Bin {
            dst: VReg::Temp(1),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: Value::Const(8),
        },
    ]);
    assert_eq!(only(&function, Passes::CSE)[2], ops_of(&function)[2]);
}

#[test]
fn cse_does_not_reuse_a_load() {
    let load = |dst: u32| Op::Load {
        dst: VReg::Temp(dst),
        addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8),
    };
    let function = one_block(vec![load(0), load(1)]);
    assert_eq!(only(&function, Passes::CSE), ops_of(&function));
}

// ---------------------------------------------------------------------------
// (d) dead-store and redundant-write elimination
// ---------------------------------------------------------------------------

#[test]
fn a_load_of_bytes_the_block_just_stored_becomes_a_copy() {
    let slot = || MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8);
    let function = one_block(vec![
        Op::Store {
            addr: slot(),
            src: reg("rdi"),
        },
        Op::Load {
            dst: VReg::phys("rax"),
            addr: slot(),
        },
    ]);
    assert_eq!(
        only(&function, Passes::REDUNDANCY)[1],
        Op::Assign {
            dst: VReg::phys("rax"),
            src: reg("rdi"),
        }
    );
}

#[test]
fn a_store_that_may_alias_stops_the_forward() {
    let function = one_block(vec![
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8),
            src: reg("rdi"),
        },
        Op::Store {
            // A different base: the peephole cannot relate it, so it may alias.
            addr: MemOp::plain(Some(VReg::phys("r12")), None, 0, 0, 8),
            src: reg("rsi"),
        },
        Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8),
        },
    ]);
    assert_eq!(only(&function, Passes::REDUNDANCY)[2], ops_of(&function)[2]);
}

/// ...but a store to a *disjoint* range of the same base does not, which is
/// the one thing [`common::may_alias`] proves apart.
#[test]
fn a_disjoint_slot_of_the_same_frame_does_not_stop_the_forward() {
    let function = one_block(vec![
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8),
            src: reg("rdi"),
        },
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -16, 8),
            src: reg("rsi"),
        },
        Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8),
        },
    ]);
    assert_eq!(
        only(&function, Passes::REDUNDANCY)[2],
        Op::Assign {
            dst: VReg::phys("rax"),
            src: reg("rdi"),
        }
    );
}

#[test]
fn overlapping_ranges_of_one_base_may_alias() {
    let wide = MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8);
    let inner = MemOp::plain(Some(VReg::phys("rbp")), None, 0, -4, 4);
    assert!(common::may_alias(&wide, &inner));
    let apart = MemOp::plain(Some(VReg::phys("rbp")), None, 0, 0, 4);
    assert!(!common::may_alias(&wide, &apart));
}

#[test]
fn a_store_the_block_immediately_overwrites_is_dropped() {
    let slot = || MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8);
    let function = one_block(vec![
        Op::Store {
            addr: slot(),
            src: reg("rdi"),
        },
        Op::Store {
            addr: slot(),
            src: reg("rsi"),
        },
    ]);
    let out = only(&function, Passes::REDUNDANCY);
    assert_eq!(out[0], Op::Nop);
    assert_eq!(out[1], ops_of(&function)[1]);
}

#[test]
fn a_register_write_nobody_reads_before_the_next_write_is_dropped() {
    let function = one_block(vec![
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: reg("rsi"),
        },
        Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Const(0),
        },
    ]);
    assert_eq!(only(&function, Passes::REDUNDANCY)[0], Op::Nop);
}

#[test]
fn a_register_write_something_reads_survives() {
    let function = one_block(vec![
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: reg("rsi"),
        },
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8),
            src: reg("rax"),
        },
        Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Const(0),
        },
    ]);
    assert_eq!(only(&function, Passes::REDUNDANCY), ops_of(&function));
}

/// A call is never dropped, whatever happens to its result.
#[test]
fn an_effectful_operation_is_never_dropped_as_a_redundant_write() {
    let function = one_block(vec![
        Op::Call {
            target: crate::ir::types::CallTarget::Direct(0x2000),
            effects: Some(crate::ir::types::CallEffects {
                result: Some(VReg::phys("rax")),
                ..Default::default()
            }),
        },
        Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Const(0),
        },
    ]);
    assert_eq!(only(&function, Passes::REDUNDANCY), ops_of(&function));
}

// ---------------------------------------------------------------------------
// (e) comparison polarity
// ---------------------------------------------------------------------------

#[test]
fn an_inverted_branch_pushes_its_negation_into_the_comparison() {
    let function = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    lhs: reg("rdi"),
                    rhs: Value::Const(0),
                },
                Op::CondJump {
                    cond: VReg::Flag(Flag::Z),
                    target: 0x1010,
                    inverted: true,
                },
            ],
            vec![0x1010, 0x1008],
        )],
    };
    let out = ops_of(&normalize_function_with(&function, Passes::POLARITY));
    assert_eq!(
        out[0],
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Ne,
            lhs: reg("rdi"),
            rhs: Value::Const(0),
        }
    );
    assert_eq!(
        out[1],
        Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target: 0x1010,
            inverted: false,
        }
    );
}

/// An ordered relation swaps its operands when it is negated, which is the
/// half of the rule that actually moves a feature: `Ult` and `Ule` mix
/// positionally.
#[test]
fn negating_an_ordered_relation_swaps_its_operands() {
    let function = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![
                Op::Cmp {
                    dst: VReg::Flag(Flag::C),
                    op: CmpOp::Ult,
                    lhs: reg("rdi"),
                    rhs: reg("rsi"),
                },
                Op::CondJump {
                    cond: VReg::Flag(Flag::C),
                    target: 0x1010,
                    inverted: true,
                },
            ],
            vec![0x1010, 0x1008],
        )],
    };
    assert_eq!(
        ops_of(&normalize_function_with(&function, Passes::POLARITY))[0],
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ule,
            lhs: reg("rsi"),
            rhs: reg("rdi"),
        }
    );
}

#[test]
fn a_predicate_with_a_second_reader_is_left_alone() {
    let function = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    lhs: reg("rdi"),
                    rhs: Value::Const(0),
                },
                Op::Assign {
                    dst: VReg::phys("al"),
                    src: Value::Reg(VReg::Flag(Flag::Z)),
                },
                Op::CondJump {
                    cond: VReg::Flag(Flag::Z),
                    target: 0x1010,
                    inverted: true,
                },
            ],
            vec![0x1010, 0x1008],
        )],
    };
    assert_eq!(
        ops_of(&normalize_function_with(&function, Passes::POLARITY)),
        ops_of(&function)
    );
}

#[test]
fn a_predicate_defined_in_another_block_is_a_parameter_and_survives() {
    let function = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target: 0x1010,
                inverted: true,
            }],
            vec![0x1010, 0x1004],
        )],
    };
    assert_eq!(
        ops_of(&normalize_function_with(&function, Passes::POLARITY)),
        ops_of(&function)
    );
}

#[test]
fn a_logical_negation_of_a_comparison_folds_into_it() {
    let function = one_block(vec![
        Op::Cmp {
            dst: VReg::Temp(0),
            op: CmpOp::Sle,
            lhs: reg("rdi"),
            rhs: reg("rsi"),
        },
        Op::Un {
            dst: VReg::Temp(1),
            op: UnOp::Not,
            src: temp(0),
        },
    ]);
    let out = ops_of(&normalize_function_with(&function, Passes::POLARITY));
    assert_eq!(
        out[0],
        Op::Cmp {
            dst: VReg::Temp(0),
            op: CmpOp::Slt,
            lhs: reg("rsi"),
            rhs: reg("rdi"),
        }
    );
    assert_eq!(
        out[1],
        Op::Assign {
            dst: VReg::Temp(1),
            src: temp(0),
        }
    );
}

// ---------------------------------------------------------------------------
// (f) strength reduction
// ---------------------------------------------------------------------------

#[test]
fn multiplication_by_a_power_of_two_becomes_a_shift() {
    let function = one_block(vec![Op::Bin {
        dst: VReg::Temp(1),
        op: BinOp::Mul,
        lhs: reg("rax"),
        rhs: Value::Const(8),
    }]);
    assert_eq!(
        only(&function, Passes::STRENGTH),
        vec![Op::Bin {
            dst: VReg::Temp(1),
            op: BinOp::Shl,
            lhs: reg("rax"),
            rhs: Value::Const(3),
        }]
    );
}

#[test]
fn multiplication_by_a_non_power_of_two_is_left_alone() {
    let function = one_block(vec![Op::Bin {
        dst: VReg::Temp(1),
        op: BinOp::Mul,
        lhs: reg("rax"),
        rhs: Value::Const(24),
    }]);
    assert_eq!(only(&function, Passes::STRENGTH), ops_of(&function));
}

/// The 32-bit signed magic sequence for `/ 10`: gcc's `M = 0x66666667`,
/// `s = 2`. The recovered divisor must be exactly 10.
#[test]
fn the_signed_magic_division_idiom_becomes_a_division() {
    let function = one_block(vec![
        Op::Intrinsic {
            name: "x86.smul_hi".into(),
            ins: vec![reg("edi"), Value::Const(0x6666_6667)],
            outs: vec![(VReg::Temp(1), Width::W32)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Bin {
            dst: VReg::Temp(2),
            op: BinOp::Sar,
            lhs: temp(1),
            rhs: Value::Const(2),
        },
        Op::Bin {
            dst: VReg::Temp(3),
            op: BinOp::Sar,
            lhs: reg("edi"),
            rhs: Value::Const(31),
        },
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Sub,
            lhs: temp(2),
            rhs: temp(3),
        },
    ]);
    assert_eq!(
        only(&function, Passes::STRENGTH)[3],
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Div,
            lhs: reg("edi"),
            rhs: Value::Const(10),
        }
    );
}

/// The add-back form, which gcc uses when the magic does not fit: `/ 7` at 32
/// bits is `M = 0x92492493` (negative as an `i64`-carried immediate),
/// `s = 2`, with `h + x` before the shift.
#[test]
fn the_add_back_magic_division_idiom_becomes_a_division() {
    let magic = 0x9249_2493u32 as i32 as i64;
    let function = one_block(vec![
        Op::Intrinsic {
            name: "x86.smul_hi".into(),
            ins: vec![reg("edi"), Value::Const(magic)],
            outs: vec![(VReg::Temp(1), Width::W32)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Bin {
            dst: VReg::Temp(2),
            op: BinOp::Add,
            lhs: temp(1),
            rhs: reg("edi"),
        },
        Op::Bin {
            dst: VReg::Temp(3),
            op: BinOp::Sar,
            lhs: temp(2),
            rhs: Value::Const(2),
        },
        Op::Bin {
            dst: VReg::Temp(4),
            op: BinOp::Sar,
            lhs: reg("edi"),
            rhs: Value::Const(31),
        },
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Sub,
            lhs: temp(3),
            rhs: temp(4),
        },
    ]);
    assert_eq!(
        only(&function, Passes::STRENGTH)[4],
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Div,
            lhs: reg("edi"),
            rhs: Value::Const(7),
        }
    );
}

#[test]
fn the_unsigned_magic_division_idiom_becomes_a_division() {
    // `/ 10` unsigned at 32 bits: M = 0xCCCCCCCD, s = 3.
    let function = one_block(vec![
        Op::Intrinsic {
            name: "x86.umul_hi".into(),
            ins: vec![reg("edi"), Value::Const(0xCCCC_CCCD)],
            outs: vec![(VReg::Temp(1), Width::W32)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Shr,
            lhs: temp(1),
            rhs: Value::Const(3),
        },
    ]);
    assert_eq!(
        only(&function, Passes::STRENGTH)[1],
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Div,
            lhs: reg("edi"),
            rhs: Value::Const(10),
        }
    );
}

/// The sequence is recognised only when the sign shift is the *dividend's*.
/// A subtraction of something else is a subtraction.
#[test]
fn a_subtraction_that_is_not_the_idiom_is_left_alone() {
    let function = one_block(vec![
        Op::Intrinsic {
            name: "x86.smul_hi".into(),
            ins: vec![reg("edi"), Value::Const(0x6666_6667)],
            outs: vec![(VReg::Temp(1), Width::W32)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Bin {
            dst: VReg::Temp(2),
            op: BinOp::Sar,
            lhs: temp(1),
            rhs: Value::Const(2),
        },
        Op::Bin {
            dst: VReg::Temp(3),
            op: BinOp::Sar,
            // NOT the dividend.
            lhs: reg("esi"),
            rhs: Value::Const(31),
        },
        Op::Bin {
            dst: VReg::phys("eax"),
            op: BinOp::Sub,
            lhs: temp(2),
            rhs: temp(3),
        },
    ]);
    assert_eq!(only(&function, Passes::STRENGTH), ops_of(&function));
}

// ---------------------------------------------------------------------------
// The driver: bound, determinism, separation
// ---------------------------------------------------------------------------

/// The pipeline stops. A block built to keep every pass firing is normalised
/// to a fixed point that a second call does not move.
#[test]
fn normalisation_reaches_a_fixed_point_within_the_round_cap() {
    let function = chained_function();
    let once = normalize_function(&function);
    let twice = normalize_function(&once);
    assert_eq!(ops_of(&once), ops_of(&twice));
}

#[test]
fn the_round_cap_is_the_documented_one() {
    assert_eq!(MAX_ROUNDS, 4);
}

/// Determinism, run the way a corpus measurement runs it: the same input gives
/// the same output, twenty times over, with no container whose iteration order
/// could vary between runs.
#[test]
fn normalisation_is_deterministic() {
    let function = chained_function();
    let first = ops_of(&normalize_function(&function));
    for _ in 0..20 {
        assert_eq!(ops_of(&normalize_function(&function)), first);
    }
}

/// The whole pipeline on a block that exercises (a) through (d) in sequence:
/// a `sub` of a constant, a `lea`-shaped zero seed, a duplicated address
/// computation, a stack round-trip and an overwritten temporary.
fn chained_function() -> LlirFunction {
    let slot = || MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8);
    one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: Value::Const(0),
        },
        Op::Bin {
            dst: VReg::Temp(1),
            op: BinOp::Add,
            lhs: temp(0),
            rhs: reg("rdi"),
        },
        Op::Bin {
            dst: VReg::Temp(2),
            op: BinOp::Sub,
            lhs: temp(1),
            rhs: Value::Const(16),
        },
        Op::Bin {
            dst: VReg::Temp(3),
            op: BinOp::Mul,
            lhs: reg("rsi"),
            rhs: Value::Const(4),
        },
        Op::Bin {
            dst: VReg::Temp(4),
            op: BinOp::Mul,
            lhs: reg("rsi"),
            rhs: Value::Const(4),
        },
        Op::Store {
            addr: slot(),
            src: temp(2),
        },
        Op::Load {
            dst: VReg::Temp(5),
            addr: slot(),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: temp(5),
            rhs: temp(4),
        },
        Op::ReturnValue { value: reg("rax") },
    ])
}

/// The pipeline is genuinely a pipeline: no single pass reaches this block's
/// final shape, and each rule below needs an earlier rule's output as its
/// input.
///
/// What the block starts as, and what it ends as:
///
/// ```text
/// t0 = 0                     Assign     t0 = 0            (a dead seed; global
/// t1 = t0 + rdi              Assign     t1 = rdi           DCE, not a peephole,
/// t2 = t1 - 16               Bin  Add   t2 = rdi + -16     removes it)
/// t3 = rsi * 4               Bin  Shl   t3 = rsi << 2
/// t4 = rsi * 4               Assign     t4 = t3
/// [rbp-8] = t2               Store      [rbp-8] = t2
/// t5 = [rbp-8]               Assign     t5 = t2
/// rax = t5 + t4              Bin  Add   rax = t2 + t3
/// return rax                 return rax
/// ```
///
/// The `Add -16` needs (b) to have folded `0 + rdi` into a copy and (a) to have
/// turned `- 16` into `+ -16`; `t4 = t3` needs (c) to have seen two identical
/// `Mul` nodes *before* (f) rewrote them; `rax = t2 + t3` needs (d)'s load
/// forwarding and then (b)'s propagation of the two copies it produced.
///
/// Arithmetic that becomes unreachable rather than rewritten -- `t0 = 0`, and
/// `t4` once its only reader has been re-pointed -- is deliberately *not*
/// removed here. Dropping a definition the peephole cannot see the far end of
/// is the one thing a peephole must not do, and `super::super::prune` already
/// removes everything no root depends on.
#[test]
fn the_passes_compose() {
    let out = ops_of(&normalize_function(&chained_function()));

    assert_eq!(
        out[2],
        Op::Bin {
            dst: VReg::Temp(2),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: Value::Const(-16),
        },
        "the copy chain and the sub-of-constant did not compose: {out:#?}"
    );
    assert_eq!(
        out[3],
        Op::Bin {
            dst: VReg::Temp(3),
            op: BinOp::Shl,
            lhs: reg("rsi"),
            rhs: Value::Const(2),
        },
        "the multiply by four did not become a shift: {out:#?}"
    );
    assert_eq!(
        out[4],
        Op::Assign {
            dst: VReg::Temp(4),
            src: temp(3),
        },
        "the duplicated multiply was not eliminated: {out:#?}"
    );
    assert_eq!(
        out[6],
        Op::Assign {
            dst: VReg::Temp(5),
            src: temp(2),
        },
        "the stack round-trip was not forwarded: {out:#?}"
    );
    assert_eq!(
        out[7],
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: temp(2),
            rhs: temp(3),
        },
        "the forwarded copies were not propagated into the sum: {out:#?}"
    );
}

/// [`Passes::NONE`] is a plain clone, which is what lets the ablation report
/// "no passes" as a row rather than as a special case.
#[test]
fn no_passes_is_a_clone() {
    let function = chained_function();
    assert_eq!(
        ops_of(&normalize_function_with(&function, Passes::NONE)),
        ops_of(&function)
    );
}

#[test]
fn the_pass_set_is_the_six_the_documentation_names() {
    assert_eq!(Passes::ALL.len(), 6);
    let everything = Passes::everything();
    for (pass, name) in Passes::ALL {
        assert!(everything.contains(pass), "{name} is not in the full set");
        assert!(!everything.without(pass).contains(pass));
    }
}

/// The normaliser never mutates its input. The caller's function is the one
/// the decompiler may still be holding.
#[test]
fn the_input_function_is_not_touched() {
    let function = chained_function();
    let before = ops_of(&function);
    let _ = normalize_function(&function);
    assert_eq!(ops_of(&function), before);
}

/// Every pass individually terminates and is idempotent after the driver's
/// rounds, checked one pass at a time so a future pass cannot hide an
/// oscillation behind another pass's fixed point.
#[test]
fn each_pass_alone_reaches_a_fixed_point() {
    let function = chained_function();
    for (pass, name) in Passes::ALL {
        let once = normalize_function_with(&function, pass);
        let twice = normalize_function_with(&once, pass);
        assert_eq!(ops_of(&once), ops_of(&twice), "{name} did not settle");
    }
}

/// The mutable use walker in [`common`] and `ir::use_def`'s immutable one must
/// enumerate the same registers. If a new `Op` variant grows a use and only one
/// walker learns about it, this fails rather than the normaliser silently
/// skipping the operand.
#[test]
fn mutable_and_immutable_use_walks_agree() {
    for op in every_op_shape() {
        let mut mutable: Vec<VReg> = Vec::new();
        let mut clone = op.clone();
        common::for_each_value_use_mut(&mut clone, |value| {
            if let Value::Reg(register) = value {
                mutable.push(register.clone());
            }
        });
        common::for_each_reg_use_mut(&mut clone, |register| mutable.push(register.clone()));

        let mut immutable = common::uses_of(&op);
        // Call arguments are deliberately outside the mutable walk; the doc on
        // `for_each_value_use_mut` says why.
        if let Op::Call { effects, .. } = &op {
            if let Some(effects) = effects {
                for argument in &effects.args {
                    if let Some(position) = immutable.iter().position(|held| held == argument) {
                        immutable.remove(position);
                    }
                }
            }
        }
        mutable.sort();
        immutable.sort();
        assert_eq!(mutable, immutable, "use walks disagree on {op:?}");
    }
}

/// One instance of every `Op` variant that reads anything.
fn every_op_shape() -> Vec<Op> {
    let memop = MemOp::plain(Some(VReg::phys("rbp")), Some(VReg::phys("rax")), 4, -8, 8);
    vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: reg("rdi"),
        },
        Op::Undef {
            dst: VReg::Temp(0),
            reason: "test".into(),
        },
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Add,
            lhs: reg("rdi"),
            rhs: reg("rsi"),
        },
        Op::Un {
            dst: VReg::Temp(0),
            op: UnOp::Neg,
            src: reg("rdi"),
        },
        Op::Cmp {
            dst: VReg::Temp(0),
            op: CmpOp::Eq,
            lhs: reg("rdi"),
            rhs: reg("rsi"),
        },
        Op::Load {
            dst: VReg::Temp(0),
            addr: memop.clone(),
        },
        Op::CondLoad {
            dst: VReg::Temp(0),
            cond: VReg::Flag(Flag::Z),
            inverted: false,
            addr: memop.clone(),
            fallback: reg("rdi"),
        },
        Op::Store {
            addr: memop.clone(),
            src: reg("rdi"),
        },
        Op::CondStore {
            cond: VReg::Flag(Flag::Z),
            inverted: false,
            addr: memop.clone(),
            src: reg("rdi"),
        },
        Op::Jump { target: 0x10 },
        Op::IndirectJump {
            target: reg("rax"),
            index: Some(reg("rcx")),
        },
        Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target: 0x10,
            inverted: false,
        },
        Op::CondReturn {
            cond: VReg::Flag(Flag::Z),
            inverted: false,
        },
        Op::CondReturnValue {
            cond: VReg::Flag(Flag::Z),
            inverted: false,
            value: reg("rax"),
        },
        Op::Call {
            target: crate::ir::types::CallTarget::Indirect(reg("r11")),
            effects: Some(crate::ir::types::CallEffects {
                result: Some(VReg::phys("rax")),
                args: vec![VReg::phys("rdi"), VReg::phys("rsi")],
                ..Default::default()
            }),
        },
        Op::ReturnValue { value: reg("rax") },
        Op::Return,
        Op::Nop,
        Op::ZExt {
            dst: VReg::Temp(0),
            src: reg("edi"),
            from: Width::W32,
            to: Width::W64,
        },
        Op::SExt {
            dst: VReg::Temp(0),
            src: reg("edi"),
            from: Width::W32,
            to: Width::W64,
        },
        Op::Trunc {
            dst: VReg::Temp(0),
            src: reg("rdi"),
            from: Width::W64,
            to: Width::W32,
        },
        Op::Extract {
            dst: VReg::Temp(0),
            src: reg("rdi"),
            hi: 32,
            lo: 0,
        },
        Op::Concat {
            dst: VReg::Temp(0),
            hi: reg("rdx"),
            lo: reg("rax"),
        },
        Op::Ite {
            dst: VReg::Temp(0),
            cond: VReg::Flag(Flag::Z),
            t: reg("rdi"),
            e: reg("rsi"),
            width: Width::W64,
        },
        Op::Intrinsic {
            name: "x86.cpuid".into(),
            ins: vec![reg("rax"), reg("rcx")],
            outs: vec![(VReg::phys("rbx"), Width::W32)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Unknown {
            mnemonic: "vpshufb".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// The off-flag byte-identity guarantee
// ---------------------------------------------------------------------------

fn sign_with(function: &LlirFunction, settings: CfrSettings) -> CfrSignature {
    let ssa = compute_ssa(function);
    let stack = stack_registers_for(CallConv::SysVAmd64);
    let external: BTreeMap<u64, String> = BTreeMap::new();
    let unmapped = |_: u64| false;
    let context = GraphContext {
        settings,
        external_names: &external,
        is_mapped_address: &unmapped,
        stack_registers: &stack,
    };
    signature_of(function, &ssa, &context).0
}

/// The three probe functions whose digests were measured on `a5ba7f7c`, the
/// commit **before** this directory existed, and pasted here.
///
/// This is the guarantee the lane owes the rest of the project: with
/// `normalize` off, every signature byte is what it was. A settings word of
/// zero and an untaken branch make that true by construction; these constants
/// make it true by measurement, and would catch an accidental edit to
/// `labels`, `graph` or `signature` that a "the flag is off" argument could
/// not.
const BASELINE_DIGESTS: [(&str, &str, usize); 3] = [
    (
        "arith",
        "6aa535be9d9ed9c4fe23b2620816af1644c8a0a68bea73885b565260cb2548a6",
        35,
    ),
    (
        "mem",
        "dc6b18afe408c5212094af05a33b5c11750c804488bb3ef63a42a9135cacc330",
        44,
    ),
    (
        "branch",
        "9f292b03a9ebc8fa8821cdecf452de86a1c6259237f47f2d2f676332f3526c84",
        51,
    ),
];

fn probe_functions() -> Vec<(&'static str, LlirFunction)> {
    let arith = one_block(vec![
        Op::Assign {
            dst: VReg::Temp(0),
            src: reg("rdi"),
        },
        Op::Bin {
            dst: VReg::Temp(1),
            op: BinOp::Sub,
            lhs: temp(0),
            rhs: Value::Const(8),
        },
        Op::Bin {
            dst: VReg::Temp(2),
            op: BinOp::Mul,
            lhs: temp(1),
            rhs: Value::Const(4),
        },
        Op::Bin {
            dst: VReg::Temp(3),
            op: BinOp::Xor,
            lhs: temp(2),
            rhs: temp(2),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: temp(2),
            rhs: temp(3),
        },
        Op::ReturnValue { value: reg("rax") },
    ]);
    let slot = || MemOp::plain(Some(VReg::phys("rbp")), None, 0, -8, 8);
    let mem = LlirFunction {
        entry_va: 0x2000,
        blocks: vec![block(
            0x2000,
            vec![
                Op::Store {
                    addr: slot(),
                    src: reg("rdi"),
                },
                Op::Load {
                    dst: VReg::Temp(5),
                    addr: slot(),
                },
                Op::Store {
                    addr: slot(),
                    src: temp(5),
                },
                Op::ZExt {
                    dst: VReg::phys("rax"),
                    src: temp(5),
                    from: Width::W64,
                    to: Width::W64,
                },
                Op::ReturnValue { value: reg("rax") },
            ],
            vec![],
        )],
    };
    let branch = LlirFunction {
        entry_va: 0x3000,
        blocks: vec![
            block(
                0x3000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: reg("rdi"),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x3010,
                        inverted: true,
                    },
                ],
                vec![0x3010, 0x3008],
            ),
            block(
                0x3008,
                vec![
                    Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Const(1),
                    },
                    Op::Jump { target: 0x3010 },
                ],
                vec![0x3010],
            ),
            block(0x3010, vec![Op::ReturnValue { value: reg("rax") }], vec![]),
        ],
    };
    vec![("arith", arith), ("mem", mem), ("branch", branch)]
}

#[test]
fn with_the_flag_off_every_signature_byte_is_what_it_was() {
    let settings = CfrSettings::default();
    assert!(!settings.normalize, "the flag must default to off");
    assert_eq!(settings.bits(), 0, "the default settings word must be zero");

    for ((name, function), (expected_name, digest, features)) in
        probe_functions().into_iter().zip(BASELINE_DIGESTS)
    {
        assert_eq!(name, expected_name);
        let signature = sign_with(&function, settings);
        assert_eq!(
            signature.identity(),
            digest,
            "{name}: the unnormalised digest moved"
        );
        assert_eq!(signature.features.len(), features, "{name}: feature count");
    }
}

/// Turning the flag on is a *different quotient*, not a refinement of the same
/// one: the version triple changes, so the two are never compared.
#[test]
fn a_normalised_signature_is_not_comparable_with_an_unnormalised_one() {
    let plain = CfrSettings::default();
    let normalised = CfrSettings {
        normalize: true,
        ..CfrSettings::default()
    };
    assert_eq!(normalised.bits(), CfrSettings::NORMALIZE_BIT);
    assert_eq!(CfrSettings::from_bits(normalised.bits()), normalised);

    let function = &probe_functions()[0].1;
    let left = sign_with(function, plain);
    let right = sign_with(function, normalised);
    assert!(!left.version.is_comparable_with(right.version));
    assert_eq!(
        crate::identity::cfr::cosine(&left, &right, None),
        0.0,
        "an incomparable pair must answer 0.0, not a low score"
    );
}

/// The normaliser changes the canonical form of a function that has something
/// to normalise -- the point of the lane, on the smallest possible witness.
#[test]
fn the_normaliser_moves_the_canonical_form() {
    let function = chained_function();
    let plain = sign_with(&function, CfrSettings::default());
    let normalised = sign_with(&normalize_function(&function), CfrSettings::default());
    assert_ne!(
        plain.features, normalised.features,
        "normalising a block full of copies and duplicates changed nothing"
    );
}

/// ...and the pass modules are reachable as modules, so a future reader can
/// run one in isolation. (Also keeps the per-pass `run` symbols used, which is
/// what the ablation harness calls.)
#[test]
fn every_pass_module_exposes_its_run_entry() {
    let mut block = block(
        0x1000,
        vec![Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Xor,
            lhs: reg("rax"),
            rhs: reg("rax"),
        }],
        vec![],
    );
    assert!(opcodes::run(&mut block));
    assert!(!constants::run(&mut block));
    assert!(!cse::run(&mut block));
    assert!(!redundancy::run(&mut block));
    assert!(!polarity::run(&mut block));
    assert!(!strength::run(&mut block));
}
