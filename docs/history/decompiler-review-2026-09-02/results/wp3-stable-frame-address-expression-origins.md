# WP3 stable-frame address expression origins

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `02d0ab6c` makes captured call-argument frame-address classification
transparent to expression ownership. A dereference through an attributed,
constant `rbp`/`ebp` address now remains eligible for exact reaching-definition
substitution instead of being left as an unresolved scratch register.

The existing safety proof is unchanged: the frame base requires exact value
identity; an intervening overlapping store, frame-base write, call, or control
boundary rejects substitution; and ambiguous or merely suggestive register
spellings fail closed.

## Focused TDD

The existing exact-identity contract now owns both its dereference and address.
Before repair, its valid opaque-frame case failed. After repair:

```text
stable_frame_load_uses_exact_identity_not_display_spelling:           pass
sysv_resolves_distinct_stable_frame_loads_from_one_scratch_register:  pass
rsp_relative_argument_load_stays_before_tail_epilogue:                pass
```

An exact detached release build of `02d0ab6c` was fresh. The established direct
fixture witness passes:

```text
11_call_shapes:clang:O0:call_into_spill  pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The recent Hello
checkpoint was not repeated because this increment has a direct real-binary
call/frame witness.

This closes one residual captured-frame semantic reader, not general MemorySSA
or WP3. Authoritative identity, explicit invalidation, and the remaining
consumer audit stay open.
