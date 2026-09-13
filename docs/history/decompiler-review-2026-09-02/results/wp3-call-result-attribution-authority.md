# WP3: explicit call-result attribution authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `4631b33d` replaces the optional identity state inside call-result
attribution with a closed `ResultIdentityAuthority`. Value-numbered production
input must select `Exact(&ValueIdentities)`; deliberately unnumbered plain LLIR
must select `PlainLlir`. The adjacent call-folding reader now branches to those
two named APIs explicitly instead of forwarding an `Option` whose absence could
mean either a valid pipeline mode or missing evidence.

The change preserves the existing conservative attribution policy: a call gets
a destination only when the ABI result storage is read before it is overwritten,
and unresolved lexical fallthrough remains treated as consumed. Exact mode
continues to refuse rendered-name matches when the identity sidecar assigns a
different or ambiguous physical base.

## Focused evidence

```text
cargo test --features python-ext ir::call_args::return_attribution::tests:: --lib -- --test-threads=1
3 passed; 0 failed; 4843 filtered out

cargo test --features python-ext ir::call_args::tests:: --lib -- --test-threads=1
132 passed; 0 failed; 4714 filtered out

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
O0/O2, fixture 172 at x86-64 O0, and fixture 81 at x86-64 O2. The shared dirty
tree was not used to regenerate either ledger.

No fixture matrix, DecBench, Joern, or corpus sweep ran. This is an authority
and API-safety increment, not an output-quality or timing claim. WP3 remains
open for the residual semantic-reader audit, conservative invalidation, and
universal origin preservation.
