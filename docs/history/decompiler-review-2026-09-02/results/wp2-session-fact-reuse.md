# WP2 reusable-session fact ownership

Revision under test: `357579c4`

## Result

`DecompilerSession.program_fact_cache_stats` now exposes ownership of call
graphs, program environments, type artifacts, and symbol artifacts separately
from discovery and rendered-artifact caches.

A real compiled fixture is decompiled under two explicit discovery budgets.
The test proves:

- output remains byte-identical;
- discovery retains two exact budget identities;
- call graphs retain two exact discovery identities;
- the compatible program environment is reused once;
- immutable symbol and type facts initialize once;
- clearing caches removes discovery, call-graph, environment, and render facts;
- immutable image-derived symbol and type facts remain initialized.

## Validation

```text
cargo check --features python-ext
  passed

uv run maturin develop --release
  release wheel built and installed

uv run pytest -q python/tests/test_decompiler_session.py
  4 passed
```

This closes WP2's reusable-session facts and explicit-budget test checkbox.
Fingerprint/function-order determinism and deliberately reduced range-budget
completeness remain open.
