# WP3 indirect-result origin transparency

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `c51a116d` makes the enabled indirect aggregate-result consumer
transparent to statement origins before and after stack promotion. AAPCS64
`x8` setup, SysV hidden first-argument setup, nested control statements, stack
adjustments, calls, and promoted-object bindings are now recognised through
their metadata carrier. Mutating a call destination preserves that call's
existing origin set.

This closes one confirmed omission from the WP3 wildcard audit. It does not
change the AAPCS64 or SysV ABI proofs, invent a result buffer when evidence is
missing, complete expression ownership, or establish structured line mappings.

## TDD and correctness boundary

Three attributed tests were observed red before the production migration:

- AAPCS64 frame-address copies reaching `x8` produced no buffer hint;
- a SysV memory-result call's attributed hidden first argument produced no
  aggregate hint;
- an attributed post-promotion `x8 = &local` setup did not bind the call
  destination.

The existing unprovable-evidence and non-AAPCS64 controls remained green. The
production change replaces raw statement matching with `semantic()` or
`semantic_mut()` at the five affected traversal boundaries. It does not relax
frame-base, call-clobber, result-size, convention, or promoted-object checks.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext aapcs64_indirect_result::tests -- --nocapture
5 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

That result is exactly neutral against the preceding latch-predicate boundary.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,264 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory post-commit whole Python gate completed red with 221 failures.
Its failure-node set is byte-for-byte identical to the 221-node pre-commit
run: zero new and zero removed nodes. The pytest cache contains 222 entries
because it retains one node not executed by either run. No AAPCS64,
aggregate-return, indirect-result, undeclared-local, or latch-predicate node is
present. The shared worktree's concurrent dataflow, metrics, syntax, binding,
and census changes remain outside this attribution.

## Next ordered increment

Continue the enabled-pass audit at the front of `run_ast_passes`.
`src/ir/vector_copy.rs` is the next confirmed omission: raw matches can hide
attributed lane batches and nested bodies, while its destructive rewrites
remove four loads, four stores, and sometimes a scalar-view bridge. Make its
recognition origin-transparent and transfer the exact consumed load, store,
and bridge origins into the two synthesized 128-bit statements before moving
to expression ownership.
