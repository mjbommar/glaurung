//! Invariance tests on hand-built LLIR.
//!
//! These are the specification, not a smoke test. Each one names a compiler
//! choice the canonical form claims to be blind to, or a program difference it
//! claims to see, and asserts exactly that. A representation nobody has
//! falsified in either direction is unfalsifiable, which is the failure mode
//! `tests/similarity_retrieval.rs` was written to end for the byte digests.

use std::collections::{BTreeMap, BTreeSet};

use super::graph::GraphContext;
use super::signature::{CfrSettings, CfrSignature};
use super::stack::stack_registers_for;
use super::{distance, signature_of};
use crate::ir::call_args::CallConv;
use crate::ir::ssa::compute_ssa;
use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};

/// Sign a hand-built function with no image facts: no external callees, no
/// mapped addresses, System V register naming.
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

fn sign(function: &LlirFunction) -> CfrSignature {
    sign_with(function, CfrSettings::default())
}

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

/// `t0 = *(u64 *)(base + 0); t1 = t0 + 1; *(u64 *)(base + 0) = t1; return t1;`
fn increment_through(base: &str, first: u32, second: u32) -> LlirFunction {
    one_block(vec![
        Op::Load {
            dst: VReg::Temp(first),
            addr: MemOp::plain(Some(VReg::phys(base)), None, 0, 0, 8),
        },
        Op::Bin {
            dst: VReg::Temp(second),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::Temp(first)),
            rhs: Value::Const(1),
        },
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys(base)), None, 0, 0, 8),
            src: Value::Reg(VReg::Temp(second)),
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(second)),
        },
    ])
}

/// Register allocation is the compiler's choice, and the first row of the mask
/// table. Two functions that differ only in which registers the allocator
/// picked must be one signature.
#[test]
fn renaming_registers_does_not_change_the_signature() {
    let through_rdi = increment_through("rdi", 0, 1);
    let through_rsi = increment_through("rsi", 40, 41);
    assert_eq!(sign(&through_rdi).digest, sign(&through_rsi).digest);
}

/// Which block the compiler emitted first is layout. Nobody in the survey
/// stores block order; neither do we.
#[test]
fn reordering_blocks_does_not_change_the_signature() {
    let ops_entry = || {
        vec![
            Op::Cmp {
                dst: VReg::Flag(crate::ir::types::Flag::Z),
                op: crate::ir::types::CmpOp::Eq,
                lhs: Value::Reg(VReg::phys("rdi")),
                rhs: Value::Const(0),
            },
            Op::CondJump {
                cond: VReg::Flag(crate::ir::types::Flag::Z),
                target: 0x1200,
                inverted: false,
            },
        ]
    };
    let then_arm = || {
        vec![Op::ReturnValue {
            value: Value::Const(1),
        }]
    };
    let else_arm = || {
        vec![Op::ReturnValue {
            value: Value::Const(2),
        }]
    };

    let forward = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![
            block(0x1000, ops_entry(), vec![0x1200, 0x1100]),
            block(0x1100, else_arm(), vec![]),
            block(0x1200, then_arm(), vec![]),
        ],
    };
    let shuffled = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![
            block(0x1200, then_arm(), vec![]),
            block(0x1100, else_arm(), vec![]),
            block(0x1000, ops_entry(), vec![0x1200, 0x1100]),
        ],
    };
    assert_eq!(sign(&forward).digest, sign(&shuffled).digest);
}

fn binary_with(op: BinOp, swapped: bool) -> LlirFunction {
    let (lhs, rhs) = if swapped {
        (Value::Const(5), Value::Reg(VReg::phys("rdi")))
    } else {
        (Value::Reg(VReg::phys("rdi")), Value::Const(5))
    };
    one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op,
            lhs,
            rhs,
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(0)),
        },
    ])
}

/// `a + b` and `b + a` are the same value, and the commutativity table says so.
#[test]
fn swapping_the_operands_of_an_addition_does_not_change_the_signature() {
    assert_eq!(
        sign(&binary_with(BinOp::Add, false)).digest,
        sign(&binary_with(BinOp::Add, true)).digest
    );
}

/// `a - b` and `b - a` are different values, and the whole reason edges carry a
/// position. If this test ever passes by equality, the positional mixing has
/// been lost and every subtraction in the corpus has collapsed.
#[test]
fn swapping_the_operands_of_a_subtraction_does_change_the_signature() {
    assert_ne!(
        sign(&binary_with(BinOp::Sub, false)).digest,
        sign(&binary_with(BinOp::Sub, true)).digest
    );
}

/// Ordered comparisons reverse under a swap; equality does not.
#[test]
fn comparison_operand_order_matters_for_ordered_but_not_for_equality() {
    let compare = |op: crate::ir::types::CmpOp, swapped: bool| {
        let (lhs, rhs) = if swapped {
            (Value::Const(5), Value::Reg(VReg::phys("rdi")))
        } else {
            (Value::Reg(VReg::phys("rdi")), Value::Const(5))
        };
        sign(&one_block(vec![
            Op::Cmp {
                dst: VReg::Flag(crate::ir::types::Flag::Z),
                op,
                lhs,
                rhs,
            },
            Op::CondJump {
                cond: VReg::Flag(crate::ir::types::Flag::Z),
                target: 0x1000,
                inverted: false,
            },
        ]))
        .digest
    };
    assert_eq!(
        compare(crate::ir::types::CmpOp::Eq, false),
        compare(crate::ir::types::CmpOp::Eq, true)
    );
    assert_ne!(
        compare(crate::ir::types::CmpOp::Slt, false),
        compare(crate::ir::types::CmpOp::Slt, true)
    );
}

/// An extra move is register allocation, not computation.
#[test]
fn a_pure_copy_is_a_shadow_and_changes_nothing() {
    let direct = one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(5),
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(0)),
        },
    ]);
    let through_a_copy = one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(5),
        },
        Op::Assign {
            dst: VReg::Temp(1),
            src: Value::Reg(VReg::Temp(0)),
        },
        Op::Assign {
            dst: VReg::Temp(2),
            src: Value::Reg(VReg::Temp(1)),
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(2)),
        },
    ]);
    assert_eq!(sign(&direct).digest, sign(&through_a_copy).digest);
}

/// A flag nothing branches on is dead, and dead flag computations are masked.
#[test]
fn a_dead_flag_computation_contributes_nothing() {
    let plain = one_block(vec![Op::Return]);
    let with_dead_flag = one_block(vec![
        Op::Cmp {
            dst: VReg::Flag(crate::ir::types::Flag::P),
            op: crate::ir::types::CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(0),
        },
        Op::Return,
    ]);
    assert_eq!(sign(&plain).digest, sign(&with_dead_flag).digest);
}

fn load_of_width(bytes: u8) -> LlirFunction {
    one_block(vec![
        Op::Load {
            dst: VReg::Temp(0),
            addr: MemOp::plain(Some(VReg::phys("rdi")), None, 0, 0, bytes),
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(0)),
        },
    ])
}

/// `nosize` is the switch that buys 32-to-64-bit matching, and it must be a
/// switch: without it the two widths stay apart.
#[test]
fn nosize_collapses_thirty_two_and_sixty_four_bit_widths() {
    let narrow = load_of_width(4);
    let wide = load_of_width(8);
    assert_ne!(sign(&narrow).digest, sign(&wide).digest);

    let settings = CfrSettings { nosize: true };
    assert_eq!(
        sign_with(&narrow, settings).digest,
        sign_with(&wide, settings).digest
    );
}

/// ...but not below four bytes: a byte and a halfword stay apart under `nosize`.
#[test]
fn nosize_keeps_one_and_two_byte_widths_apart() {
    let settings = CfrSettings { nosize: true };
    assert_ne!(
        sign_with(&load_of_width(1), settings).digest,
        sign_with(&load_of_width(2), settings).digest
    );
    assert_ne!(
        sign_with(&load_of_width(2), settings).digest,
        sign_with(&load_of_width(4), settings).digest
    );
}

/// Stack mechanics are masked; that a value addresses the frame is kept.
#[test]
fn a_frame_relative_address_is_a_different_value_class_from_a_pointer_argument() {
    let address_of_local = one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Sub,
            lhs: Value::Reg(VReg::phys("rbp")),
            rhs: Value::Const(8),
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(0)),
        },
    ]);
    let offset_from_argument = one_block(vec![
        Op::Bin {
            dst: VReg::Temp(0),
            op: BinOp::Sub,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(8),
        },
        Op::ReturnValue {
            value: Value::Reg(VReg::Temp(0)),
        },
    ]);
    assert_ne!(
        sign(&address_of_local).digest,
        sign(&offset_from_argument).digest
    );
}

/// Constants reach the label as a magnitude *class*, never as a value.
///
/// This is a deliberate departure from SAFE and PalmTree, which keep small
/// immediates verbatim on the grounds that they identify locals and fields. So
/// they do -- but a stack displacement is exactly the thing that moves between
/// `-O0` and `-O2` as the frame is relaid out, and cross-optimisation matching
/// is what this rung exists for. `0`, `1` and `-1` get their own classes,
/// small is distinguished from large, and beyond that the value is masked; BSim
/// masks constants entirely and is stricter still.
#[test]
fn constant_magnitude_classes_are_kept_and_exact_values_are_masked() {
    let with_const = |value: i64| {
        sign(&one_block(vec![
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rdi")),
                rhs: Value::Const(value),
            },
            Op::ReturnValue {
                value: Value::Reg(VReg::Temp(0)),
            },
        ]))
        .digest
    };
    // The classes are apart from each other...
    assert_ne!(with_const(0), with_const(8));
    assert_ne!(with_const(1), with_const(8));
    assert_ne!(with_const(-1), with_const(8));
    assert_ne!(with_const(8), with_const(0x10000));
    assert_ne!(with_const(0x10000), with_const(0x40_1234));
    // ...and two values in one class are one feature, by construction.
    assert_eq!(with_const(8), with_const(16));
    // Two different magic numbers, neither a power of two nor address-like.
    assert_eq!(
        with_const(0x5851_f42d_4c95_7f2d_u64 as i64),
        with_const(0x2545_f491_4f6c_dd1d_u64 as i64)
    );
}

/// An external callee's name is kept, because it is a stable interface.
#[test]
fn external_callee_names_reach_the_signature() {
    let call_to = |stub: u64| {
        let function = one_block(vec![
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(stub),
                effects: None,
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&function);
        let stack = stack_registers_for(CallConv::SysVAmd64);
        let mut external: BTreeMap<u64, String> = BTreeMap::new();
        external.insert(0x2000, "puts".to_string());
        external.insert(0x2010, "malloc".to_string());
        let unmapped = |_: u64| false;
        let context = GraphContext {
            settings: CfrSettings::default(),
            external_names: &external,
            is_mapped_address: &unmapped,
            stack_registers: &stack,
        };
        signature_of(&function, &ssa, &context).0.digest
    };
    assert_ne!(call_to(0x2000), call_to(0x2010));
    // An unresolved internal callee reduces to an arity class, so two
    // different internal targets are one feature.
    assert_eq!(call_to(0x3000), call_to(0x4000));
}

/// The same input must produce the same bytes, every time, in any process.
#[test]
fn signatures_are_deterministic() {
    let function = increment_through("rdi", 0, 1);
    let first = sign(&function);
    for _ in 0..8 {
        let again = sign(&function);
        assert_eq!(first.digest, again.digest);
        assert_eq!(first.features, again.features);
    }
}

/// Identity on the quotient: two spellings of one function are at distance
/// zero, which is the strongest claim a pseudo-metric is entitled to make.
#[test]
fn the_distance_between_two_spellings_of_one_function_is_zero() {
    let left = sign(&increment_through("rdi", 0, 1));
    let right = sign(&increment_through("rsi", 7, 8));
    assert!(distance(&left, &right, None) < 1e-9);
}

/// A function with no features must not be mistaken for a match with anything.
#[test]
fn an_empty_function_produces_a_signature_that_matches_nothing() {
    let empty = LlirFunction {
        entry_va: 0x1000,
        blocks: Vec::new(),
    };
    let signature = sign(&empty);
    assert!(signature.is_empty());
    let real = sign(&increment_through("rdi", 0, 1));
    assert_eq!(super::cosine(&signature, &real, None), 0.0);
}

/// The width census is the honest report on the pass that cannot always answer.
#[test]
fn the_width_census_counts_what_it_could_not_resolve() {
    let function = increment_through("rdi", 0, 1);
    let ssa = compute_ssa(&function);
    let stack = stack_registers_for(CallConv::SysVAmd64);
    let external: BTreeMap<u64, String> = BTreeMap::new();
    let unmapped = |_: u64| false;
    let context = GraphContext {
        settings: CfrSettings::default(),
        external_names: &external,
        is_mapped_address: &unmapped,
        stack_registers: &stack,
    };
    let (_, census) = signature_of(&function, &ssa, &context);
    assert!(census.total > 0);
    // Every value here is either a 64-bit load, a 64-bit add, or a physical
    // register, so nothing should be left unresolved.
    assert_eq!(census.unknown, 0, "census: {census:?}");
}

/// Sanity on the plumbing: the sets used by the graph builder are the ones the
/// calling convention names, not a global union that would mis-taint `r11`.
#[test]
fn stack_register_sets_are_calling_convention_specific() {
    let sysv: BTreeSet<&str> = stack_registers_for(CallConv::SysVAmd64);
    assert!(sysv.contains("rbp"));
    assert!(!sysv.contains("r11"));
    let arm: BTreeSet<&str> = stack_registers_for(CallConv::Arm);
    assert!(arm.contains("r11"));
    assert!(!arm.contains("rbp"));
}
