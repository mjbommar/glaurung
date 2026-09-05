# WP4 ARMv7 multi-latch dispatch-loop ownership — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `6f0ba701` closes the production-v1 ownership failure exposed by the
ARMv7 A32 compact-byte switch slice. The real GCC O2
`206_aarch64_wide_dispatch::dispatch_in_loop` CFG contains a natural loop with
six case-specific latches, an explicit seven-way switch, and multiple exits.
The switch was already recovered, but production structuring stopped at an
unresolved outer guard and left all six latch-to-header edges unowned.

## Implementation boundary

- `src/ir/structure/loop_shape.rs` recognises an explicit-switch natural loop
  with multiple dominated latches. The broader two-exit allowance requires
  multiple latches, preserving the ordinary single-latch loop path.
- `src/ir/structure.rs` follows only an exact single-successor path when one
  side of an otherwise unresolved binary guard reaches that loop. It emits the
  other arm as an explicit bypass transfer and continues at the loop header.
- Recursive structure recovery retains the graph-sized depth/work budget from
  `5ef0bcb9`; failure still degrades to the complete labelled CFG rather than a
  partial tree or native stack overflow.

This is not a general licence to invent loop ownership. The path must remain
linear, the loop must satisfy the natural-loop dominance checks, and ambiguous
or single-latch two-exit shapes continue through the existing conservative
path.

## Behavioral evidence

At exact commit `56503e53`, after a clean-worktree release extension build:

- all seven focused ARMv7 A32 architecture tests pass;
- production v1 recompiles and executes `dispatch_in_loop` correctly;
- the strict expected-failure marker is removed;
- structural accounting has no hard unowned block or edge finding;
- the result contains a real `switch` inside `while (1)` and retains explicit
  case-latch transfers;
- one `EdgeViaGoto` on the outer guard remained an honest readability finding
  at this revision. It is closed by the bounded private-prefix/shared-terminal
  repair at `0e29ffc4`; see `wp4-a32-guard-quality.md`.

The complete ARMv7 A32 O0/O2 matrix covers 410 compiler/optimisation lanes and
1,604 function verdicts. Relative to the exact pre-repair map, the only
attributable change is:

```text
206_aarch64_wide_dispatch:armv7_a32:O2:dispatch_in_loop fail -> pass
```

`03_loop_shapes::loop_break` and `15_binary_search_tree::bst_search` changed
from pass to fail in that particular comparison, but retained same-revision
runs show both alternate independently. `bst_search` changes fail/pass/pass on
three retries of the unchanged parent, while `loop_break` alternates across
pre-WP4 matrices. Neither contains the explicit switch-dispatch shape touched
by this change, so neither is attributed to `6f0ba701`.

## Gates

- `cargo test --features python-ext`: green, including 4,112 library tests and
  all integration and documentation tests.
- focused structure suite: 62 passed.
- focused ARMv7 A32 architecture suite: seven passed.
- generated census at `56503e53`: 4,629 declared tests and zero never-executed
  entries.

The whole Python repository gate remains required before release closure. Its
known broad-red baseline is not replaced by these focused and architecture
matrix results.

## Next boundary

Commits `28b3bc5b` and `0e29ffc4` close the outer-guard `goto` and
undefined-looking temporary as separate, measured increments. WP4 promotion still
requires corpus-wide accounting, GED/structure movement, execution, runtime,
and output-size evidence; this vertical slice does not claim promotion.
