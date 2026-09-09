# WP3 global scalar initializers

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `49a2f7eb` preserves exact file-backed initial values when DecBench-style
output materializes a named scalar global. Analysis already retained the bytes;
the renderer now emits them when the symbol start, object width, access width,
and representable scalar value agree.

Unknown objects, arrays, width conflicts, interior addresses, and high-bit
values without a portable signed interpretation retain the prior conservative
zero-initialized fallback.

## Focused TDD

The file-scope scalar contract was observed red before the renderer change and
green afterward. Two neighboring global/function-static contracts remained
green:

```text
decbench_file_backed_global_scalar_keeps_its_initializer: pass
decbench_exact_sized_global_renders_as_a_scalar_object: pass
dwarf_owned_static_object_renders_in_its_function_scope: pass
```

Each invocation selected one test and filtered out 4,699 unrelated tests. No
broad Rust or Python suite was run.

## Execution-differential closure

A clean detached release build at `49a2f7eb` ran only fixture 157: four host
lanes and five functions per lane. All 20 verdicts pass. Twelve recorded
failures became passes with no regression:

```text
clang O0/O2: vis_fold_with_biases, vis_read_bias, vis_set_biases
gcc   O0/O2: vis_fold_with_biases, vis_read_bias, vis_set_biases
```

Commit `e942e71f` ratchets exactly those 12 baseline cells. Repeating the same
20-verdict slice against the updated baseline reports no improvements and no
regressions in scope.

## Scope

This closes the symbol-visibility fixture and its measured initialized scalar
global class. Aggregate/global-array initialization, high-bit scalar spelling,
other fixture families, and universal WP3 attribution remain open.
