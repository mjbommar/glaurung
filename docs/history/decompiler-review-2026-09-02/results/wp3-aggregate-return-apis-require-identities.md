# WP3: aggregate-return APIs require identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `df29aeed` makes the complete aggregate-return reconstruction family
identity-required in non-test builds. Integer-pair composition, promoted-object
bank composition, INTEGER+SSE materialisation, and SSE-pair materialisation now
accept `&ValueIdentities`; none of their typed APIs can be called with `None`.

The production preparation and scored-render paths already own the authoritative
snapshot and now pass it directly. Identity-free adapters remain available only
to legacy unit tests over hand-written ASTs. This keeps all four ABI return
shapes on one authority policy instead of allowing one path to fall back to
register, promoted-object, or SSA display spellings.

## Red/green evidence

The first focused compile caught two adjacent call-site argument mismatches
introduced during the signature migration. They were corrected before commit.
The final focused evidence is:

```text
cargo test --features python-ext ir::callee_return_pair::tests:: --lib
10 passed; 0 failed; 4832 filtered out

cargo test --features python-ext ir::callee_return_bank::tests:: --lib
23 passed; 0 failed; 4819 filtered out

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

The modules retain optional-identity internals only for test compatibility.
WP3 still requires isolation or deletion of those adapters, the remaining
production identity/parser audit, conservative invalidation, and universal
origin preservation.
