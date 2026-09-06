# WP3 statement instruction-origin carrier

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `59840017` gives every AST statement an optional compositional
`OriginSet` without changing rendered pseudocode. `Stmt::Origin` is a
transparent carrier: re-attribution unions canonical sets instead of nesting
wrappers, semantic readers and mutators can reach the carried statement, and
the three renderers ignore provenance textually. This closes statement-level
ownership only. LLIR lowering does not yet attach instruction VAs, expressions
do not yet carry origins, and structured line mappings are not yet exposed.

The migration converted all 64 exhaustive statement consumers exposed by the
new enum variant. It also explicitly fixed wildcard consumers at the rendering
boundary, including `for` clauses, switch suffix labels, terminal case
transfers, frame sizing, stack fallthrough, and exact return guards. A broader
audit of pattern-based production consumers remains required before lowering
may emit wrappers universally.

## Changes

- `src/ir/ast.rs` owns `Stmt::Origin`, `with_origins`, `origins`, `semantic`,
  and `semantic_mut`.
- Enabled AST analyses and rewrites recurse through or mutate inside the
  carrier rather than dropping it.
- C-like, typed-context, and scored C rendering preserve identical text for
  attributed statements, including attributed `for` initializers and steps.
- `src/ir/ast/origin.rs` adds union-without-nesting and renderer-neutrality
  tests.
- `tests/test_census_baseline.json` records two new IR tests: 4,736 to 4,738
  total declarations and 2,143 to 2,145 under `ir`.

## Verification

The focused five-test origin suite passed:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
cargo test --features python-ext --lib origin::tests -- --nocapture
```

The required full Rust gate passed from the unchanged source subsequently
committed as `59840017`:

```bash
cargo test --features python-ext
```

The library target reported 4,221 passed, zero failed, and five ignored. Every
integration and documentation target passed. The CFR target reported 44
passed, zero failed, and ten ignored in 524.56 seconds.

The release extension rebuilt successfully:

```bash
uv run maturin develop --release
```

The required identity-only sweep used:

```bash
uv run python tools/stripped_differential.py --jobs 8 --json \
  > "$HOME/.cache/glaurung/tmp/wp3-statement-origin-carrier-stripped.json"
```

All 419 pairs remain byte-identical to the preceding WP3 map. The JSON SHA-256
is `d86d3399127f93a292e895acc84375d2622065b9acf17d38228bb20973ca0c21`,
with the same 116 existing divergences and zero infrastructure problems. Exit
1 is the existing two-sided ratchet drift, not a changed output.

The post-commit census passed all six tests. The mandatory whole Python suite
completed red against the shared dirty checkout. Pytest's current cache holds
86 failed node IDs, one of which is the stale
`test_shadow_batch_locally_declines_an_unavailable_function` entry absent from
this run's terminal failure list. The failures are in the existing fixture,
ratchet, generated-document, dialect, fitness, and repository-wide lanes; the
origin and census tests are absent. Because unrelated `csource`, `syntax`,
source-metrics, and `src/lib.rs` edits remained in the worktree, this is not a
clean-checkout release claim. The focused origin evidence, full Rust gate, and
419-map identity establish the bounded carrier result.

No DecBench run or upstream interaction was performed.

## Next boundary

Finish the wildcard/pattern consumer audit, then attribute every statement
produced from one `LlirInstr` with that instruction's VA at the LLIR-to-AST
boundary. Folding must union contributing origins, while duplication must copy
the exact set. Only after wrappers survive the enabled production pipeline may
the Python result expose deterministic structured line-to-address mappings.
