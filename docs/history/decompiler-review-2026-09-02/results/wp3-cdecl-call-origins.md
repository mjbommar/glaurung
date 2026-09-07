# WP3 cdecl32 call-argument origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `c291328a` makes cdecl32 outgoing-stack argument recovery transparent to
statement origins. Attributed contiguous stores, lowered push pairs,
post-call-cleanup evidence, pure intervening values, and stack-relative
rebasing now participate in the same proofs as raw statements. Every consumed
setup owner is unioned into the surviving call, while owners of removed stack
decrements are also preserved on the synthesized net `esp` adjustment.

This is not metadata-only in current production. Before the migration, origin
wrappers hid real i386 push setup from `fold_one_cdecl32_call`, leaving
`helper3()` with explicit stack stores. The migrated release output recovers
`helper3(a, b, c)`, and its rebuilt C executes identically to the source.

The safety boundaries are unchanged: non-contiguous outgoing areas, excessive
traffic relative to caller cleanup, stack-pointer-valued arguments, frame
prologues, unproved intervening statements, and control boundaries still
decline.

## Evidence

Two ownership tests were observed red before the production change. The first
uses attributed contiguous `[esp+offset]` stores; the second uses attributed
lowered push pairs and checks both the call owner and synthesized adjustment
owner. All cdecl-focused tests and the complete call-argument module pass:

```text
cargo test --features python-ext cdecl32_ -- --nocapture
23 passed; 0 failed

cargo test --features python-ext ir::call_args:: -- --nocapture
117 passed; 0 failed
```

The release-built focused Python check has one known readability failure and
ten passes; the current undeclared-local invariant remains eight-for-eight:

```text
uv run maturin develop --release
uv run pytest -q python/tests/test_pe32_cdecl_roundtrip.py \
  python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared
10 passed; 1 failed
```

The remaining failure is the pre-existing `_print_sum(sum)` expectation; the
output still names that value `stack_1`. It is not introduced by this slice.

The complete stripped/debug differential is byte-for-byte identical to the
preceding accepted boundary:

```text
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,284 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite improves the preceding accepted boundary by
two exact normalized nodes with no addition:

```text
213 failed; 4,592 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 2 removed failure nodes
```

The removed nodes are the i386 cdecl decompile/recompile/execute round trip and
the single-function/full-architecture-lane equivalence check. A controlled
release A/B reversed only `c291328a`: both nodes failed at the parent, the
exact source hashes were restored, and both passed after rebuilding the tip.

## Next ordered increment

Continue the argument-recovery origin audit in
`src/ir/call_args/aapcs.rs`. Preserve owners across proven stack-area
consumption and cleanup while retaining its alias, register-overlap,
phase-sensitive stack, and control-boundary refusals.
