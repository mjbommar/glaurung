# WP3 copy-propagation internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `25055e14` closes the copy-propagation family's optional production
identity engine. One closed authority now reaches the core linear walkers,
read counting, scratch classification, store-address substitution, dead-copy
elimination, scratch liveness, adjacent value movers, and switch-entry
propagation. Spelling-based entry points and the legacy authority variant are
compiled only for hand-written unit tests.

AST preparation now uses the identity-aware untyped promoted-value mover rather
than always invoking its spelling-only form. This lets an opaque but
authoritatively owned promoted temporary fold into its sole adjacent consumer.
The late single-use call-result fold in both AST preparation and the Python
render pipeline also uses identity-aware read counting.

## Focused evidence

```text
cargo test --features python-ext ir::copy_prop:: --lib -- --test-threads=1
83 passed; 0 failed; 4762 filtered out

cargo test --features python-ext ir::lazy_call_select::tests:: --lib -- --test-threads=1
19 passed; 0 failed; 4826 filtered out

cargo check --features python-ext --lib
pass

rg 'Option<&crate::ir::value_number::ValueIdentities>' \
  src/ir/copy_prop.rs src/ir/copy_prop/*.rs
no matches
```

The owning coverage includes exact and misleading storage spellings, read/write
classification, store lvalue boundaries, alias barriers, loop-carried values,
dead-copy and scratch-liveness cleanup, adjacent guards and calls, switches,
exceptions, and origin preservation. A new exact-path test proves that an
opaque owned promoted `Select` temporary now folds into its return.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes every earlier test and again stops at 17% on
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane`: committed
`arch_baseline.json` and `baseline.json` disagree for the existing fixture 157,
172, and 81 control rows. This source commit changes neither ledger, and the
baseline was not regenerated from the shared dirty checkout.

This closes the copy-propagation internal authority seam. It does not complete
WP3's remaining semantic-reader audit, mutation invalidation, or origin
coverage.
