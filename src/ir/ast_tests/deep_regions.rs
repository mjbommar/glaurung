//! Lowering a deeply nested region tree must not exhaust the stack.
//!
//! `wide154_dense_switch` is 256 contiguous cases. Built for aarch64 at `-O0`
//! by `aarch64-linux-gnu-gcc 15.2.0`, the switch does not become a jump table;
//! the structurer recovers a comparison ladder 442 regions deep. `lower_region`
//! and `lower_region_inner` recurse in lockstep over that tree with no depth
//! budget, and each pair consumed roughly 18 KB of stack, so the default 8 MB
//! ran out:
//!
//!     glaurung decompile w154.so --vas 0x5c8   ->   SIGSEGV (core dumped)
//!
//! with no stdout and, because the process died in a prologue rather than
//! panicking, no stderr either. `tools/arch_roundtrip.py` reported it only as
//! `gate-crashed: ` with an empty message, and it took five whole lanes of
//! `--write-baseline` with it.
//!
//! Raising `ulimit -s` to 64 MB made the same invocation succeed and emit
//! 958 KB of correct C, which is what identified the depth rather than the
//! decompilation as the fault.
//!
//! These tests build the nesting directly so the contract holds without a
//! cross-compiler, and at a depth well past anything a real switch produces.

use crate::ir::ast::lower;
use crate::ir::structure::Region;
use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

/// Well beyond the 442 that crashed, so the guard is not merely "one more than
/// the case that failed".
const DEEP: usize = 5_000;

/// One real assignment per block, so each level lowers to a statement and an
/// empty result cannot be mistaken for success.
fn block_with_work(index: usize, va: u64) -> LlirBlock {
    LlirBlock {
        start_va: va,
        end_va: va + 4,
        instrs: vec![LlirInstr {
            va,
            op: Op::Assign {
                dst: VReg::phys(format!("v{index}")),
                src: Value::Const(index as i64),
            },
        }],
        succs: Vec::new(),
    }
}

/// One block per region level plus a shared tail, so every nested region
/// references a real index.
fn function_with(blocks: usize) -> LlirFunction {
    LlirFunction {
        entry_va: 0x1000,
        blocks: (0..blocks)
            .map(|index| block_with_work(index, 0x1000 + (index as u64) * 4))
            .collect(),
    }
}

#[test]
fn a_deeply_nested_conditional_ladder_lowers_without_exhausting_the_stack() {
    let function = function_with(DEEP + 2);
    // The shape a wide switch degrades into: else-if all the way down.
    let mut region = Region::Block(DEEP + 1);
    for level in (0..DEEP).rev() {
        region = Region::IfThenElse {
            cond: level,
            then_r: Box::new(Region::Block(DEEP)),
            else_r: Box::new(region),
            join: None,
            invert: false,
        };
    }

    let lowered = lower(&function, &region, "deep_ladder");
    assert!(
        !lowered.body.is_empty(),
        "a {DEEP}-deep conditional ladder must lower to statements"
    );
}

#[test]
fn a_deeply_nested_sequence_lowers_without_exhausting_the_stack() {
    // `Seq` recurses through a different arm than `IfThenElse`, and the tail
    // passes over the lowered statements (`collect_goto_targets`,
    // `deduplicate_labels`) walk the resulting statement tree just as deeply.
    let function = function_with(DEEP + 1);
    let mut region = Region::Block(DEEP);
    for level in (0..DEEP).rev() {
        region = Region::Seq(vec![Region::Block(level), region]);
    }

    let lowered = lower(&function, &region, "deep_sequence");
    assert!(
        !lowered.body.is_empty(),
        "a {DEEP}-deep sequence must lower to statements"
    );
}
