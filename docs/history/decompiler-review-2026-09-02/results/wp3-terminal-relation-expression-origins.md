# WP3 terminal-relation expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `65162531` makes the width-proved terminal mixed-view relation fold
transparent to expression-origin carriers. The x86 flag shape
`((unsigned(x) == K) | (signed(x) < K)) == 0` still recovers the readable
`K < signed(x)` relation when its terminal test, inner relation, and both
comparison leaves are independently attributed.

The replacement owns the deterministic union of all four consumed semantic
contributors. Constant range, shared-value, width, extension-provenance, and
signedness refusal rules are unchanged. Folding inside an existing attributed
node also flattens any synthesized nested carrier into the canonical union.

Follow-on commit `2fccded5` closes the comparison-to-zero entry boundary. An
attributed zero no longer blocks terminal mixed-view, eager-boolean, or exact-
boolean recovery, and its owner joins the replacement's canonical set.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The focused test produced two useful RED states. Initially the attributed flag
tree remained unreduced. After transparent recognition was added, the readable
relation returned but its public origin set exposed only the outer owner,
proving that folding had created a nested carrier. The final repair recognizes
the attributed children and canonicalizes that nested ownership:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_terminal_mixed_view_relation_unions_consumed_origins \
  -- --exact
1 passed; 0 failed; 4,375 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
74 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed.
The touched-module run includes its existing checked-in real-binary
end-to-end test. No full Rust, Python, fixture, architecture, DecBench, or
Joern suite was run.

## Next boundary

Continue the constructor audit with the next independently proved
constant-fold family. Keep every recognition/refusal proof unchanged and
compose only the origins of semantics actually consumed by its replacement.
