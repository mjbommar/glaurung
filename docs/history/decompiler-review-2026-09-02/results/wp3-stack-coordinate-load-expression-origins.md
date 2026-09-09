# WP3 stack-coordinate load expression origins

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `0d29922b` makes call-argument folding's stack-coordinate phase guard
transparent to expression ownership on a dereference. An attributed load from
`[rsp + offset]` now remains statement-rooted when moving it to a later call
would cross an `rsp` adjustment and change which memory it reads.

The guard remains narrow. It applies only to a semantic dereference through the
active architecture stack register with an intervening write to that register;
ordinary arguments retain the established folding behavior.

## Focused TDD

The existing x86 tail-epilogue contract now attributes the load expression.
Before repair, reconstruction deleted the load and moved its dereference after
the `rsp` restore. After repair, it and two adjacent architecture controls pass:

```text
rsp_relative_argument_load_stays_before_tail_epilogue:       pass
arm_call_argument_keeps_its_current_stack_coordinate:        pass
fixed_arm_library_contract_crosses_shadowed_argument_setup:  pass
```

An exact detached release build of `0d29922b` was fresh. The original stripped
real-binary regression passes:

```text
test_real_stripped_format_wrapper_recovers_forwarded_string_parameter: pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The cross-
architecture Hello checkpoint was not repeated because it passed recently and
this increment has a direct real-binary witness.

This closes one residual call-folding semantic reader, not general MemorySSA or
WP3. Authoritative identity, explicit invalidation, and the remaining consumer
audit stay open.
