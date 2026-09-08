# WP3 function-table origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `217796be` makes relocation-proven function-table recovery fully
transparent to statement origins. Attributed assignments now participate in
the pass's reaching-definition map; attributed calls and indirect transfers
invalidate unversioned proofs at the same boundaries as raw statements; and
write/clobber collection sees through carriers.

The pass also resolves expressions inside throws and every `try`/`catch` body.
Definitions written on any exception path are conservatively removed before
subsequent statements, preserving the existing fail-closed proof boundary.
Outer statement owners are retained unchanged.

This is a bounded WP3 consumer migration. It does not infer a table without
complete relocation evidence, add expression origins, or complete the
remaining tail-call and argument-recovery audit.

## Evidence

Both new tests were observed red before the production change: an attributed
table base disappeared from the proof map, and table expressions inside
`throw` and catch-side indirect transfer nodes were skipped. The complete
focused module is green:

```text
cargo test --features python-ext function_tables::tests -- --nocapture
10 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

The complete JSON map is byte-for-byte identical to the GOT-fold boundary. The
complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,274 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite improved by one normalized node with no
addition:

```text
217 failed; 4,588 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 1 removed failure node
```

The removed node is
`test_dispatch_recovers_portable_local_function_table`. A controlled release
A/B reversed only `217796be`: the parent emitted an indirect call through raw
input-image address `0x4040` and failed, while the restored tip emitted the
portable `ops[5]` table and passed. The source hash was checked after restoring
the patch and the release extension was rebuilt again.

## Next ordered increment

Continue in production pass order through `call_args::tail_calls`. Its direct,
resolved-indirect, and vtable tail-call rewrites still traverse and replace raw
statements, so attributed transfers can be skipped and synthesized call/return
nodes can lose the contributing transfer owner.
