# WP3 stack-canary origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `9942f948` completes the next bounded WP3 statement-consumer migration
in `src/ir/canary.rs`. Stack-canary save and exit-check recognition now sees
through statement-origin carriers, and every synthesized canary comment owns
the deterministic union of the instructions removed by the rewrite. Nested
structured traversal remains transparent, while the existing relocation,
TLS-slot, stack-slot, comparison, and `__stack_chk_fail` proofs remain intact.

The migration is output-neutral on the complete stripped/debug differential
and on the exact whole-Python failing-node set. It strengthens attribution; it
does not broaden which patterns are accepted as canaries.

The release-built declaration invariant is also green in all eight
architecture/optimization cells. That current evidence supersedes the earlier
report of undeclared `stack_3` / `local_c` failures, but it does not attribute
the repair to this output-neutral canary commit or to uncommitted concurrent
stack-promotion work.

## Evidence

The two focused ownership tests were observed red before the production
change. The focused and complete canary modules pass:

```text
cargo test --features python-ext attributed_canary_ -- --nocapture
2 passed; 0 failed

cargo test --features python-ext ir::canary::tests -- --nocapture
22 passed; 0 failed
```

The required release extension and real Python checks pass:

```text
uv run maturin develop --release
uv run pytest -q \
  python/tests/test_decompiler_canary.py \
  python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared \
  python/tests/test_decompiler_arch_roundtrip.py::test_aarch64_o2_stack_protected_functions_return_through_their_canary
30 passed
```

The complete stripped/debug differential is unchanged from the accepted AAPCS
boundary:

```text
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 18 improvements; 0 infrastructure problems
```

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,289 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite has the exact same normalized failed-node set
as the preceding accepted boundary:

```text
uv run pytest python/tests/
211 failed; 4,594 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 0 removed failure nodes
```

## Next ordered increment

Re-run the enabled semantic-consumer audit and migrate the next bounded raw
statement consumer. Do not infer WP3 completion: expression ownership,
non-contiguous transformation policy, structured Python line mappings,
multi-output SSA identity, and remaining identity consumers are still open.
