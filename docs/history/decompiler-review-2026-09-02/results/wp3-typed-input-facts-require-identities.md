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

Commit `b18a9cd1` closes those downstream compatibility engines. Architectural
read collection and phi-copy recognition now expose separate plain-LLIR and
exact-identity entry points backed by a closed internal authority. Both
parameter inference and phi coalescing choose one explicitly. ARM alignment
padding classification and use exclusion likewise expose separate plain and
exact APIs; no optional identity state remains in any of these three modules.

Focused evidence for the full chain remains:

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

The required Python fail-fast gate again reached 17% without an earlier
failure, then stopped at the same committed baseline-ledger disagreement. No
fixture matrix, DecBench, Joern, or corpus sweep ran. This is an authority/API
closure, not an output-quality or timing claim.

The typed input and parameter-evidence compatibility chain is now closed. WP3
remains open for the remaining production semantic-reader audit, conservative
invalidation, and universal origin preservation.

Commit `796c2acb` closes the final proven-input predicate underneath that chain.
Its shared implementation now accepts a closed `ProvenInputAuthority`, with
raw type recovery selecting `PlainLlir` and identity-aware parameter and
architectural-read analysis selecting `Exact`. Register equivalence cannot
fall through from an absent snapshot to display spelling.

Focused evidence:

```text
cargo test --features python-ext ir::use_def::tests:: --lib -- --test-threads=1
16 passed; 0 failed; 4830 filtered out

cargo test --features python-ext ir::value_number::tests:: --lib -- --test-threads=1
65 passed; 0 failed; 4781 filtered out

cargo check --features python-ext
exit 0

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required Python fail-fast gate reached 17% without an earlier failure and
again stopped at the established baseline-ledger disagreement. No fixture
matrix, DecBench, Joern, or corpus sweep ran. This completes the typed
input/signature evidence authority family; it is not an output or timing claim.
