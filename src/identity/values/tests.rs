//! Value harvesting on hand-built LLIR, where the answer is known by hand.
//!
//! These are the specification, not a smoke test. Each one names a value the
//! function demonstrably computes and asserts that the fingerprint contains
//! exactly it, or names a compiler choice the representation claims to be
//! blind to and asserts two spellings land on one multiset.

use std::collections::BTreeMap;

use super::fingerprint::{branch_element, normalize, BranchKind};
use super::harvest::{bare_context, run_seed, RunOutcome, ValueContext};
use super::seeds::{fresh_value, ADDRESS_FLOOR, STACK_BASE};
use super::settings::ValueSettings;
use super::{fingerprint_of, weighted_jaccard, ValueFingerprint};
use crate::ir::types::{
    BinOp, CallTarget, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value,
    Width,
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Blocks are laid out 0x10 apart, so a block's `end_va` is the start of its
/// fall-through successor -- the contiguity `crate::exec` relies on to resolve
/// a not-taken branch, and which a hand-built function has to honour or every
/// conditional falls off the CFG.
fn block(start: u64, ops: Vec<Op>, succs: Vec<u64>) -> LlirBlock {
    assert!(
        ops.len() <= 0x10,
        "a test block holds at most 16 instructions"
    );
    LlirBlock {
        start_va: start,
        end_va: start + 0x10,
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

/// A fingerprint with no image facts behind it: nothing mapped, nothing
/// initialised, no callee named.
fn fingerprint_with(function: &LlirFunction, settings: ValueSettings) -> ValueFingerprint {
    fingerprint_of(function, &bare_context(settings)).0
}

fn fingerprint(function: &LlirFunction) -> ValueFingerprint {
    fingerprint_with(function, ValueSettings::default())
}

/// One seed, no branch conditions, no site cap in the way: the smallest
/// configuration in which "what did this function compute" has one answer.
fn single_run(function: &LlirFunction) -> Vec<u64> {
    let settings = ValueSettings {
        seeds: 1,
        branch_conditions: false,
        ..ValueSettings::default()
    };
    fingerprint_with(function, settings)
        .values
        .into_iter()
        .map(|(element, _)| element)
        .collect()
}

fn contains(fingerprint: &ValueFingerprint, element: u64) -> bool {
    fingerprint.values.iter().any(|(v, _)| *v == element)
}

// ---------------------------------------------------------------------------
// Extraction: arithmetic on inputs
// ---------------------------------------------------------------------------

/// `return 3 * rdi;` -- and the same computation spelled `rdi + rdi + rdi`.
///
/// vSim's headline example (Figure 1: `3 * x` in one build, `x' + 2 * x'` in
/// the other). Two spellings, one number, one fingerprint element.
#[test]
fn two_spellings_of_the_same_arithmetic_produce_the_same_value() {
    let by_multiply = one_block(vec![
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Mul,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(3),
        },
        Op::Return,
    ]);
    let by_addition = one_block(vec![
        Op::Bin {
            dst: VReg::phys("rcx"),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Reg(VReg::phys("rdi")),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rcx")),
            rhs: Value::Reg(VReg::phys("rdi")),
        },
        Op::Return,
    ]);

    let seed = fresh_value(0, None);
    let expected = 3 * seed;
    assert!(single_run(&by_multiply).contains(&expected));
    assert!(single_run(&by_addition).contains(&expected));

    // Different register names, different instruction counts, same values.
    assert!(
        weighted_jaccard(&fingerprint(&by_multiply), &fingerprint(&by_addition), None) > 0.0,
        "two spellings of 3*x share no value"
    );
}

/// The multiple seeds are the whole point of running more than once: a value
/// that depends on the input takes a different number under each.
#[test]
fn a_value_that_depends_on_the_input_appears_once_per_seed() {
    let function = one_block(vec![
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Mul,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(3),
        },
        Op::Return,
    ]);
    let settings = ValueSettings {
        seeds: 3,
        branch_conditions: false,
        ..ValueSettings::default()
    };
    let fingerprint = fingerprint_with(&function, settings);
    for seed in 0..3u8 {
        let expected = 3 * fresh_value(seed, None);
        assert!(
            contains(&fingerprint, expected),
            "seed {seed} should contribute {expected}; got {:?}",
            fingerprint.values
        );
    }
}

/// A constant stored at every width is the same integer afterwards. This is
/// the property that lets a 32-bit build match its 64-bit sibling.
#[test]
fn a_negative_constant_normalises_to_one_integer_at_every_width() {
    let at = |width: Width, constant: i64| {
        one_block(vec![
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Const(constant),
            },
            Op::Store {
                addr: MemOp::plain(
                    Some(VReg::phys("rsp")),
                    None,
                    0,
                    -64,
                    width.bytes().max(1) as u8,
                ),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Return,
        ])
    };
    let thirty_two = single_run(&at(Width::W32, -1));
    let sixty_four = single_run(&at(Width::W64, -1));
    let minus_one = normalize(u64::MAX, Width::W64);
    assert!(thirty_two.contains(&minus_one), "{thirty_two:?}");
    assert!(sixty_four.contains(&minus_one), "{sixty_four:?}");
}

// ---------------------------------------------------------------------------
// Extraction: a store
// ---------------------------------------------------------------------------

/// `*(u64 *)(rsp - 8) = 0xdeadbeef;` -- vSim's other worked example.
///
/// The value is recorded (a memory store is half of Table II) and the address
/// it was stored at is not (it is a stack address, rule F3).
#[test]
fn a_store_records_its_value_and_not_its_address() {
    let function = one_block(vec![
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 8),
            src: Value::Const(0xdead_beef),
        },
        Op::Return,
    ]);
    let values = single_run(&function);
    assert!(values.contains(&0xdead_beef), "{values:?}");
    assert!(
        !values.iter().any(|v| v.abs_diff(STACK_BASE) < 4096),
        "a stack address reached the fingerprint: {values:?}"
    );
}

/// A load of memory nothing wrote reads as the seed's trial value, not zero.
///
/// The interpreter's own `Memory` reads unwritten bytes as zero; without the
/// pre-fault every uninitialised read would collapse to the same 0 and the
/// scheme would be measuring the constant folding of a bug.
#[test]
fn an_uninitialised_load_reads_a_fresh_value_rather_than_zero() {
    let function = one_block(vec![
        Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -16, 8),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(1000),
        },
        Op::Return,
    ]);
    let values = single_run(&function);
    let seed = fresh_value(0, None);
    assert!(
        values.contains(&(seed + 1000)),
        "expected {} in {values:?}",
        seed + 1000
    );
}

/// A round trip through memory is not a new value: the store's value and the
/// load's result are the same number, so the multiset counts them together.
#[test]
fn a_value_written_then_read_back_comes_back_unchanged() {
    let function = one_block(vec![
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 8),
            src: Value::Const(4242),
        },
        Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 8),
        },
        Op::Return,
    ]);
    let settings = ValueSettings {
        seeds: 1,
        branch_conditions: false,
        ..ValueSettings::default()
    };
    let fingerprint = fingerprint_with(&function, settings);
    let count = fingerprint
        .values
        .iter()
        .find(|(value, _)| *value == 4242)
        .map(|(_, count)| *count);
    assert_eq!(count, Some(2), "{:?}", fingerprint.values);
}

// ---------------------------------------------------------------------------
// Extraction: a loop
// ---------------------------------------------------------------------------

/// `for (i = 0; i < 8; i++) sum += i;` -- four blocks, a back edge, a bounded
/// trip count.
fn counted_loop(limit: i64) -> LlirFunction {
    // 0x1000: i = 0; sum = 0
    // 0x1010: flag = i < limit ; if !flag goto 0x1030
    // 0x1020: sum = sum + i ; i = i + 1 ; goto 0x1010
    // 0x1030: return
    LlirFunction {
        entry_va: 0x1000,
        blocks: vec![
            block(
                0x1000,
                vec![
                    Op::Assign {
                        dst: VReg::phys("rcx"),
                        src: Value::Const(0),
                    },
                    Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Const(0),
                    },
                    Op::Jump { target: 0x1010 },
                ],
                vec![0x1010],
            ),
            block(
                0x1010,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Slt),
                        op: CmpOp::Slt,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Const(limit),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Slt),
                        target: 0x1030,
                        inverted: true,
                    },
                    Op::Jump { target: 0x1020 },
                ],
                vec![0x1020, 0x1030],
            ),
            block(
                0x1020,
                vec![
                    Op::Bin {
                        dst: VReg::phys("rax"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Reg(VReg::phys("rcx")),
                    },
                    Op::Bin {
                        dst: VReg::phys("rcx"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("rcx")),
                        rhs: Value::Const(1),
                    },
                    Op::Jump { target: 0x1010 },
                ],
                vec![0x1010],
            ),
            block(0x1030, vec![Op::Return], vec![]),
        ],
    }
}

/// The loop runs to completion and the values it produces are the ones a
/// reader can compute by hand.
#[test]
fn a_counted_loop_runs_and_yields_its_running_sum() {
    let function = counted_loop(8);
    let context = bare_context(ValueSettings {
        seeds: 1,
        site_cap: 15,
        ..ValueSettings::default()
    });
    let harvest = run_seed(&function, &context, 0);
    assert_eq!(harvest.outcome, RunOutcome::Returned);

    let settings = ValueSettings {
        seeds: 1,
        site_cap: 15,
        branch_conditions: false,
        ..ValueSettings::default()
    };
    let values = fingerprint_with(&function, settings);
    // sum after k iterations: 0, 0, 1, 3, 6, 10, 15, 21, 28.
    for partial in [1u64, 3, 6, 10, 15, 21, 28] {
        assert!(
            contains(&values, partial),
            "partial sum {partial} missing from {:?}",
            values.values
        );
    }
}

/// The per-site cap is what keeps a long loop from drowning the fingerprint.
#[test]
fn the_site_cap_bounds_what_a_loop_contributes() {
    let capped = fingerprint_with(
        &counted_loop(64),
        ValueSettings {
            seeds: 1,
            site_cap: 3,
            branch_conditions: false,
            ..ValueSettings::default()
        },
    );
    let uncapped = fingerprint_with(
        &counted_loop(64),
        ValueSettings {
            seeds: 1,
            site_cap: 15,
            branch_conditions: false,
            ..ValueSettings::default()
        },
    );
    assert!(
        capped.len() < uncapped.len(),
        "cap 3 kept {} elements, cap 15 kept {}",
        capped.len(),
        uncapped.len()
    );
    assert!(capped.len() <= 3 * 5, "{} elements survived", capped.len());
}

/// An unbounded loop stops at the budget instead of hanging, and says so.
#[test]
fn an_unbounded_loop_stops_at_the_budget_and_reports_it() {
    let function = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![
                Op::Bin {
                    dst: VReg::phys("rax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(1),
                },
                Op::Jump { target: 0x1000 },
            ],
            vec![0x1000],
        )],
    };
    let settings = ValueSettings {
        seeds: 1,
        max_steps: 500,
        ..ValueSettings::default()
    };
    let harvest = run_seed(&function, &bare_context(settings), 0);
    assert_eq!(harvest.outcome, RunOutcome::BudgetExhausted);
    assert_eq!(harvest.steps, 501, "the budget must be the step count");

    let (_, stats) = fingerprint_of(&function, &bare_context(settings));
    assert_eq!(stats.budget_exhausted, 1);
    assert!(
        !stats.budget_exhausted_before_any_value,
        "this loop does produce values before the budget trips"
    );
}

/// The other half of the coverage question: a run that hits the budget having
/// learned nothing. A self-jump computes nothing at all, so however long it
/// spins there is no value to record.
#[test]
fn a_budget_too_small_to_learn_anything_is_reported_separately() {
    let function = LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![Op::Jump { target: 0x1000 }],
            vec![0x1000],
        )],
    };
    let settings = ValueSettings {
        seeds: 1,
        max_steps: 50,
        ..ValueSettings::default()
    };
    let (_, stats) = fingerprint_of(&function, &bare_context(settings));
    assert_eq!(stats.budget_exhausted, 1);
    assert!(stats.budget_exhausted_before_any_value);
}

// ---------------------------------------------------------------------------
// Calls, undefined values, and the things that would otherwise stop a run
// ---------------------------------------------------------------------------

/// A call to an unmodelled callee does not stop the run, and two builds
/// calling the same external see the same return value.
#[test]
fn a_call_continues_with_a_sentinel_keyed_on_the_callee() {
    let call_to = |target: u64| LlirFunction {
        entry_va: 0x1000,
        blocks: vec![block(
            0x1000,
            vec![
                Op::Call {
                    target: CallTarget::Direct(target),
                    effects: None,
                },
                Op::Bin {
                    dst: VReg::phys("rbx"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rax")),
                    rhs: Value::Const(0),
                },
                Op::Return,
            ],
            vec![],
        )],
    };
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    names.insert(0x4000, "memcpy".to_string());
    names.insert(0x5000, "memcpy".to_string());
    names.insert(0x6000, "strlen".to_string());

    let settings = ValueSettings {
        seeds: 1,
        branch_conditions: false,
        ..ValueSettings::default()
    };
    let with_names = |target: u64| {
        let mut context: ValueContext<'_> = bare_context(settings);
        context.external_names = &names;
        let harvest = run_seed(&call_to(target), &context, 0);
        assert_eq!(harvest.outcome, RunOutcome::Returned, "the call stopped it");
        fingerprint_of(&call_to(target), &context).0
    };

    // Two different PLT slots for the same external are the same value.
    assert_eq!(with_names(0x4000).values, with_names(0x5000).values);
    // A different external is a different value.
    assert_ne!(with_names(0x4000).values, with_names(0x6000).values);
}

/// `Op::Undef` poisons a register and the interpreter halts on the first read.
/// Under-constrained execution wants a fresh value there, not a stop.
#[test]
fn an_undefined_value_becomes_fresh_rather_than_halting_the_run() {
    let function = one_block(vec![
        Op::Undef {
            dst: VReg::phys("rdx"),
            reason: "unmodelled".to_string(),
        },
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys("rdx")),
            rhs: Value::Const(11),
        },
        Op::Return,
    ]);
    let settings = ValueSettings {
        seeds: 1,
        ..ValueSettings::default()
    };
    let harvest = run_seed(&function, &bare_context(settings), 0);
    assert_eq!(harvest.outcome, RunOutcome::Returned);
    assert!(single_run(&function).contains(&(fresh_value(0, None) + 11)));
}

// ---------------------------------------------------------------------------
// Branch conditions
// ---------------------------------------------------------------------------

/// The E2 elements reach the fingerprint, and they are the canonical
/// (non-strict) form.
#[test]
fn branch_conditions_reach_the_fingerprint_in_canonical_form() {
    let with_branches = fingerprint_with(
        &counted_loop(8),
        ValueSettings {
            seeds: 1,
            ..ValueSettings::default()
        },
    );
    // `i < 8`, tested inverted, is `i >= 8`.
    assert!(contains(&with_branches, branch_element(BranchKind::Sge, 8)));

    let without = fingerprint_with(
        &counted_loop(8),
        ValueSettings {
            seeds: 1,
            branch_conditions: false,
            ..ValueSettings::default()
        },
    );
    assert!(!contains(&without, branch_element(BranchKind::Sge, 8)));
}

// ---------------------------------------------------------------------------
// The contract the harness relies on
// ---------------------------------------------------------------------------

/// Extraction is a pure function of the function and its settings. An identity
/// that moved between two calls would not be an identity.
#[test]
fn extraction_is_deterministic() {
    let functions = [
        counted_loop(8),
        counted_loop(64),
        one_block(vec![
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 8),
                src: Value::Const(0xdead_beef),
            },
            Op::Return,
        ]),
    ];
    for function in &functions {
        let first = fingerprint(function);
        let second = fingerprint(function);
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.values, second.values);
    }
}

/// A fingerprint is its own nearest neighbour, and two unrelated functions are
/// not each other's.
#[test]
fn the_similarity_axioms_hold_on_hand_built_functions() {
    let loop_eight = fingerprint(&counted_loop(8));
    let store = fingerprint(&one_block(vec![
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 8),
            src: Value::Const(0xdead_beef),
        },
        Op::Return,
    ]));
    assert!((weighted_jaccard(&loop_eight, &loop_eight, None) - 1.0).abs() < 1e-12);
    let cross = weighted_jaccard(&loop_eight, &store, None);
    assert!(cross < weighted_jaccard(&loop_eight, &loop_eight, None));
    assert!((0.0..=1.0).contains(&cross));
    assert!(
        (cross - weighted_jaccard(&store, &loop_eight, None)).abs() < 1e-12,
        "asymmetric"
    );
}

/// Two loops with different bounds are not the same function, and the
/// fingerprint has to be able to say so.
#[test]
fn two_loops_with_different_bounds_are_distinguishable() {
    let eight = fingerprint(&counted_loop(8));
    let sixty_four = fingerprint(&counted_loop(64));
    assert_ne!(eight.digest, sixty_four.digest);
    assert!(weighted_jaccard(&eight, &sixty_four, None) < 1.0);
}

/// Turning the filter off changes the answer -- which is the only thing that
/// makes the ablation in the harness a measurement rather than a rerun.
#[test]
fn the_filter_setting_changes_what_survives() {
    // A function that computes a stack address into a register: `rax = rsp - 32`.
    let function = one_block(vec![
        Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Sub,
            lhs: Value::Reg(VReg::phys("rsp")),
            rhs: Value::Const(32),
        },
        Op::Return,
    ]);
    let filtered = fingerprint_with(
        &function,
        ValueSettings {
            seeds: 1,
            ..ValueSettings::default()
        },
    );
    let unfiltered = fingerprint_with(
        &function,
        ValueSettings {
            seeds: 1,
            filter: false,
            ..ValueSettings::default()
        },
    );
    assert!(
        filtered.len() < unfiltered.len(),
        "the stack address survived the filter"
    );
    assert!(contains(&unfiltered, STACK_BASE - 32));
    // ...and the two are not comparable, because they are different quotients.
    assert_eq!(weighted_jaccard(&filtered, &unfiltered, None), 0.0);
}

/// The low-address guard is what stops a shared object from having its
/// constants deleted. Asserted here over a whole function rather than over the
/// filter in isolation.
#[test]
fn a_small_constant_survives_an_image_that_maps_low() {
    let function = one_block(vec![
        Op::Store {
            addr: MemOp::plain(Some(VReg::phys("rsp")), None, 0, -8, 4),
            src: Value::Const(0x1234),
        },
        Op::Return,
    ]);
    let low_mapped = |address: u64| address < 0x5000;
    let mut context = bare_context(ValueSettings {
        seeds: 1,
        branch_conditions: false,
        ..ValueSettings::default()
    });
    context.is_mapped_address = &low_mapped;
    let (fingerprint, _) = fingerprint_of(&function, &context);
    assert!(0x1234 < ADDRESS_FLOOR);
    assert!(contains(&fingerprint, 0x1234), "{:?}", fingerprint.values);
}
