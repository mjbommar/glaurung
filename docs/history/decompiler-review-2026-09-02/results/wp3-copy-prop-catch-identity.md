# WP3 copy-propagation catch identity preservation

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `f33427d4` fixes a concrete identity-authority loss in dead-copy
elimination. When the pass recounted and cleaned a recovered `catch` body, it
explicitly replaced the production `ValueIdentities` sidecar with `None`. An
opaque promoted stack object could therefore be reclassified from source
storage to disposable scratch solely because it crossed an exception-region
boundary, and its assignment could be deleted.

The recursive cleanup now retains the caller's identity authority. Synthetic
handler temporaries absent from the sidecar remain scratch, while retained
values keep their authoritative promoted-storage ownership.

## Red/green evidence

Before the fix:

```text
cargo test --features python-ext \
  ir::copy_prop::tests::exception_dead_copy_cleanup_preserves_owned_opaque_stack_objects \
  --lib -- --exact --test-threads=1
FAILED: the owned frame-object assignment disappeared from the catch body
```

After the fix:

```text
same command
1 passed; 0 failed; 4843 filtered out

cargo test --features python-ext ir::copy_prop::tests:: --lib -- --test-threads=1
39 passed; 0 failed; 4805 filtered out

cargo check --features python-ext --lib
pass
```

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

This fixes one demonstrated mutation defect and advances WP3 identity
preservation. It does not yet close the copy-propagation family's remaining
optional internal authority paths.
