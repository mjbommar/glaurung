# WP3 GOT expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `befd81e5` makes resolved GOT-pointer folding transparent to expression
provenance. An attributed dereference and attributed slot address now retain
the same exact relocation proof as their plain forms. The resolved target
receives the flattened, deterministic union of both owners.

The existing safety boundary is unchanged: the read must be pointer-sized, the
semantic address must be a direct or named slot, and the image-derived target
map must contain that slot.

## Focused TDD

The existing ownership contract was strengthened to attribute both the load
and its address. It was observed red before the repair and green afterward:

```text
an_attributed_pointer_load_keeps_its_instruction_owner: pass
ir::got_fold: 6 passed, 4,692 filtered out
```

No broad Rust or Python suite was run.

## Release real-binary evidence

A clean detached release build at `befd81e5` ran exactly one owning
execution-differential lane:

```text
157_symbol_visibility:gcc:O0:vis_read_bias  fail
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

The emitted C still reads through `glaurung_global_3fe8`, so production did not
provide a usable resolved target for this load. This is a recorded pre-existing
failure, not evidence that the origin repair closes GOT-backed public globals.
The next boundary is the image target-map/pipeline input to this pass.

## Scope

This closes the GOT folder's expression-origin consumer. Production GOT target
availability, the `157_symbol_visibility` semantic failure, and universal
expression attribution remain open.
