# WP8 type and terminal-guard regression closure

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `db0c7321` closes every TypeMatch loss in the 11-function regression
set between `d8665dd` and `15d8b51c`, and restores the genuine `user_name`
structural regression.

Three bounded defects were responsible:

- authoritative DWARF pointers to nominal typedefs were erased to `void *`
  before the renderer could validate and emit their declarations;
- authoritative source locals declared inside `for (...)` were invisible to
  the benchmark's declaration inventory; and
- instruction-origin wrappers made an otherwise safe exact eager-boolean
  guard fail the terminal-guard recognizer's safety check.

The fixes preserve nominal pointers until the existing fail-closed DWARF
render validation, keep authoritative source declarations as separate
function-scope facts, and make the eager-boolean safety check transparent to
origin metadata. Anonymous promoted machine locals retain compact inline
declarations, and memory-reading eager expressions remain ineligible for
short-circuit recovery.

## Targeted evidence

After a release `maturin develop`, the current local DecBench evaluator was run
only over the 11 known TypeMatch losses and the two known GED losses. The
machine-readable result is outside the repository at
`$HOME/.cache/glaurung/type-ged-targeted-final.json`.

```text
TypeMatch regression set: 11/11 perfect

libacl:O0:getfacl:user_name
  source CFG:     10 nodes, 11 edges
  decompiled CFG: 10 nodes, 11 edges
  GED: 0.0 (exact isomorphism)

gnutls:O2-noinline:ocsptool:socket_open2
  source CFG:     66 nodes, 102 edges
  decompiled CFG: 64 nodes, 99 edges
  GED: 20.0
```

The focused Rust contracts pass:

```text
cargo test --features python-ext --lib \
  dwarf_named_scalars_keep_separate_source_declarations
cargo test --features python-ext --lib \
  loop_local_used_only_by_loop_is_declared_in_for_initializer
cargo test --features python-ext --lib \
  matching_commented_returns_keep_one_shared_terminal
cargo test --features python-ext --lib \
  authoritative_nominal_pointer_reaches_dwarf_render_validation
cargo test --features python-ext --lib \
  eager_boolean_with_memory_read_is_not_short_circuited
cargo test --features python-ext --lib \
  opaque_dwarf_parameter_does_not_discard_renderable_sibling_types
cargo test --features python-ext --lib \
  recovered_opaque_typedef_parameter_is_self_contained

all seven focused tests passed
```

No broad DecBench run, Joern sweep, whole Rust gate, or whole Python gate was
run for this increment.

## `socket_open2` classification

The remaining `socket_open2` score is not repaired by restoring its earlier
text. The old GED-perfect output contained a fabricated stack-canary condition,
branch, label, and failure path. Removing that incorrect control flow reduced
the decompiled graph by exactly two nodes and three edges, exposing missing
source structure elsewhere. The earlier graph isomorphism was therefore a
metric coincidence, not faithful recovery.

Reintroducing the canary branch would optimize the score by making the output
less correct. The honest action is to retain the current canary recovery and
treat the function's two missing source nodes as future structuring work.
