# WP3: typed input facts require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `d7e6411d` tightens three connected identity-aware contracts:

- DWARF field annotation now requires `&ValueIdentities`, and its raw AST
  adapter is test-only;
- the identity-aware proven-call-input predicate requires an actual snapshot;
- identity-aware LLIR parameter-slot discovery requires an actual snapshot.

Raw proven-input and parameter-slot analysis remains available because
pre-numbering production consumers legitimately operate before an identity
sidecar exists. The implementation dispatches explicitly between raw and typed
semantics at that boundary; a caller can no longer invoke a function named
`with_identities` while passing `None`.

This preserves the intended phase order: exact identities govern numbered
DWARF, call-input, phi-plumbing, and parameter facts, while unnumbered type and
format analysis retains its separate conservative raw route.

## Focused evidence

```text
cargo test --features python-ext ir::dwarf_fields::tests:: --lib
13 passed; 0 failed; 4829 filtered out

cargo test --features python-ext ir::use_def::tests:: --lib
16 passed; 0 failed; 4826 filtered out

cargo test --features python-ext ir::value_number::tests:: --lib
65 passed; 0 failed; 4777 filtered out

cargo check --features python-ext --lib
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-source-commit Python gate was run once, fail-fast:

```text
uv run pytest python/tests/ -q -x
stopped at 11%: 1 failed
```

Its first ordinary failure remains the established ARM Thumb leaf-frame
regression and retains the same spurious
`*(int *)((&local_18[0] + 20)) = var0;` store. No ordinary failure appeared
earlier. No fixture matrix, DecBench, Joern, or corpus sweep was run. This is
an authority/API change, not an output or timing claim.

## Remaining boundary

Commit `082b00d2` closes the parameter-slot classifier's internal optional
state. Its shared CFG walk now receives a closed `ParameterIdentityAuthority`:
value-numbered callers select `Exact(&ValueIdentities)`, while legitimate
pre-numbering consumers select `PlainLlir`. Exact slot lookup and proven-input
classification dispatch on that authority directly, so a missing snapshot can
no longer silently select spelling semantics inside signature recovery.

Follow-on focused evidence:

```text
cargo test --features python-ext ir::value_number::tests:: --lib -- --test-threads=1
65 passed; 0 failed; 4781 filtered out

cargo check --features python-ext
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-source-commit Python gate was run once, fail-fast. It reached
17% without an earlier failure, then stopped at the established disagreement
between `arch_baseline.json` and `baseline.json` for fixture 157 at x86-64
O0/O2, fixture 172 at x86-64 O0, and fixture 81 at x86-64 O2. The dirty shared
tree was not used to regenerate either ledger. No fixture matrix, DecBench,
Joern, or corpus sweep ran.

The downstream architectural-read and ARM-padding compatibility engines still
accept optional identity state and are the next bounded closures. WP3 also
remains open for the remaining production semantic-reader audit, conservative
invalidation, and universal origin preservation.
