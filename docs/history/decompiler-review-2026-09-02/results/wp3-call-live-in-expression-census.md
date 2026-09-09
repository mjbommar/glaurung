# WP3 call live-in expression census

Commit `0678d3fb` closes a provenance-transparency hole in call live-in
discovery. The register census used to inspect statement owners but silently
skip an `Expr::Origin`, so attributing a live-in register could make that
register disappear from argument reconstruction.

The census is now exhaustive over the current AST: it descends through
expression owners, conversions, expression calls, table indexes, wide
arithmetic, throws, indirect transfers, exception regions, and push/pop forms.
Leaf forms are explicit, so adding a new AST variant produces a compiler error
instead of another silent omission.

The strengthened contract was observed red before the repair (`[]` instead of
`["rdi"]`). Afterward, exactly three Rust tests ran:

```text
origin_wrappers_do_not_hide_register_names_from_call_recovery       pass
value_numbered_tail_call_backfills_a_proven_bare_live_in_prefix     pass
no_bare_register_is_injected_into_a_value_numbered_body             pass
```

Each invocation filtered out 4,726 unrelated tests. An exact detached release
build of the pushed commit then passed only the directly related real fixture:

```text
06_calling_conventions:gcc:O2:forward_sum6  pass
SCOPED: 1 lane of 838; no regressions in scope
```

The periodic Hello World sample also remained canonical at GCC O0 and O2 for
x86-64, AArch64, and ARMv7: **6/6 passed**. This was the symbol-bearing PIE
sample, not the full 72-cell Hello grid.

No broad Rust, Python, fixture, DecBench, or Joern suite ran. This closes one
bounded semantic-reader gap, not WP3's authoritative SSA, invalidation, or
universal production-attribution work.
