# WP3 final-cleanup and dead-store origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commits `7d531781` and `4b35aeab` close five related statement-origin
omissions near the final preparation and rendering boundary.

`src/ir/ast/prepare.rs` now removes attributed machine-frame markers without
discarding their owners: the semantic comment becomes an inert `Nop` inside
the existing origin carrier. `src/ir/widen.rs`, `src/ir/cmp_fusion.rs`, and
`src/ir/dwarf_fields.rs` inspect and mutate the semantic statement beneath a
carrier, so provenance no longer disables widening, comparison fusion, or
definition invalidation.

`src/ir/dead_stores.rs` now treats attributed assignments, calls, promoted
stores, nested exits, and inert separators identically to their unwrapped
semantic statements. This is both a readability and a correctness repair:
unused call destinations and self-copies disappear again, while a value that
reaches an attributed `break`, `continue`, `goto`, indirect transfer, or return
is no longer deleted as if that exit did not exist. Calls retain their carrier
when only the unused destination is cleared.

## Focused TDD

The first four cases were observed red before `7d531781`:

```text
attributed_machine_frame_markers_become_owned_inert_nodes
attributed_assignment_is_widened_without_losing_its_owner
attributed_guard_is_fused_without_losing_its_owner
attributed_writes_are_visible_to_definition_invalidation
```

After the repair, the cross-module attribution filter and all four touched
module suites pass:

```text
cargo test --features python-ext attributed_ --lib -- --nocapture
52 passed; 0 failed; 4,259 filtered out; 0.23 s test execution

prepare fixpoint tests: 3 passed
widen tests: 20 passed
comparison-fusion tests: 20 passed
DWARF-field tests: 10 passed
```

Three dead-store cases were then observed red before `4b35aeab`: an attributed
unused call kept its fake result, an attributed self-copy survived, and an
attributed nested `break` allowed the value reaching that exit to be deleted.
All three now pass, the complete dead-store module is 40/40 green, and the
origin-focused library slice is 58/58 green.

## Release real-binary evidence

A release parent/tip check of the signed-loop, linked-list, and ILP32-wide-
return tests found the same five pre-existing copy-propagation expectations on
both sides of `7d531781`; the attributable delta is zero. The intended visible
change is removal of machine-frame comments only.

An isolated release wheel containing `4b35aeab` passes every function in
fixture 11 across GCC and Clang at O0 and O2:

```text
tools/dectest.py 11_call_shapes --full --jobs 4
52 passed across four lanes; no regression in scope
```

The output improvement is direct. GCC O0 `call_result_unused` changes from:

```c
int var1;
var1 = signed_step(local_4);
```

to:

```c
signed_step(local_4);
```

The startup helper likewise changes a fake
`long var2 = __cxa_finalize(...)` into a void declaration and effect-only call.

## Broad gates

The complete Rust gate after `7d531781` passed the 4,311-test library and all
ordinary integration targets. Two identity-retrieval ratchets failed because
one weighted row scored 176 Clang queries while its control scored 178. The
contended result did not reproduce when the complete target was rerun alone:

```text
cargo test --features python-ext --test identity_retrieval
44 passed; 0 failed; 10 ignored; 525.26 s
```

A serial whole-Python run was intentionally stopped at 27% after the newer
`4b35aeab` source commit made it obsolete. A replacement `pytest -n 8` run
reached at least 96%, including its internally serialized Docker fixture, but
its terminal summary was not retained. It is therefore inconclusive and is
not reported as a pass. The cumulative post-`4b35aeab` whole-Python checkpoint
remains due at the next coherent source integration boundary; the focused
tests and release fixture above are the evidence for this increment.

## Next ordered increment

Finish the enabled wildcard-consumer audit. Then define non-contiguous
fold/hoist/duplication behavior and introduce expression ownership before
migrating copy propagation, constant folding, dead-store elimination, and DCE
onto authoritative SSA identities. Do not replace the stable-value work with
display-name rules.
