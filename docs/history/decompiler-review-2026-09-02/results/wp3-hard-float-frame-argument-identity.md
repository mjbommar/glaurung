# WP3 hard-float frame-argument identity

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `67b6a8a0` prevents recovered-layout call folding from discarding the
exact value placed in an ARM hard-float argument slot when that value came
from an impure expression such as a frame load. The setup statement remains
where it was evaluated, and the call reads that setup statement's exact SSA
destination. It no longer falls back to a raw architectural spelling such as
`s2` after value numbering has renamed the current value.

The compiled Cortex-M regression now renders the source-ordered call as:

```c
return arm_hf_three(value, (float)((-limit)), limit);
```

The former output used an undefined `var5` for the third argument. The test
now checks the semantic contract independently of whether later cleanup emits
the call as an assignment or a direct return: three arguments, the incoming
value, the negated lower limit, the positive upper limit, and no invented
temporary.

## Safety boundary

The existing movement proof remains conservative. Before changing the call,
the pass proves that none of the recovered setup values is reassigned between
its setup and the call. Pure expressions continue through the existing inline
and statement-removal path. If any expression is impure, every setup statement
stays rooted at its original program point; only its exact SSA destination is
put in the call argument list.

## Focused evidence

Against a fresh debug extension:

```text
cargo test --features python-ext ir::call_args::tests:: -- --test-threads=1
132 passed; 0 failed

pytest python/tests/test_cli_decompile.py::test_real_arm_hard_float_compare_does_not_erase_three_call_args -q
1 passed
```

The Rust slice includes the new frame-load contract plus the existing
intervening-reassignment, memory-alias, origin, mixed-layout, and hard-float
controls.

The one required whole-Python fail-fast gate passed the former 11% Thumb and
hard-float blockers and reached 17%. It then stopped at
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: four
x86-64 control verdicts in committed `arch_baseline.json` disagree with
committed `baseline.json`. This commit touches neither ledger, and neither was
regenerated from the concurrently dirty checkout.

This closes one bounded recovered-call identity defect, not WP3. The remaining
semantic-reader and invalidation work stays open.
