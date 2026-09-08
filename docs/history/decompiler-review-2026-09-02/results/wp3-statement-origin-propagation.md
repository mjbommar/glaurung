# WP3 statement-origin propagation

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `8cb7d171` carries the deterministic instruction-origin statement
wrapper through the enabled AST pipeline instead of letting existing passes
silently stop matching wrapped statements. It also keeps the wrapper
transparent to structured return-definition and ABI-width analysis.

This is a bounded WP3 increment. It does not complete pipeline-owned versioned
SSA, invalidation migration, expression-level origins, structured line
mappings, or migration of all semantic consumers onto authoritative SSA.

## Correctness repairs exposed by the carrier

Origin propagation exposed passes that matched directly on `Stmt` and stopped
recognizing assignments, returns, switch dispatches, loop exits, calls,
stack-local flow, and dead definitions. Those consumers now inspect the
semantic statement while retaining the wrapper on output.

Fixture 45 exposed three concrete consequences:

- GCC `format_decimal` declared the exact 32-bit divisor `0xcccccccd` as signed
  and respelled it as a negative 64-bit multiplier. A definition-and-use proof
  now selects unsigned spelling only when all exact high-bit definitions and
  every use preserve the positive narrow value.
- GCC `parse_decimal` used `0x80000000` as a positive 32-bit bound in a signed
  64-bit comparison domain. The same proof admits that wider domain while a
  negative control retains signed interpretation for a narrow signed use.
- Clang `format_decimal` rendered `unsigned long` and positive 64-bit error
  sentinels because wrappers hid the existing structured return-width proof.
  Origin-transparent ABI-width and reaching-definition walks restore the
  signed 32-bit return without a function-specific rule.

## Evidence

Source revision and release build:

```text
8cb7d171 decompiler: preserve statement origins through AST passes
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv run maturin develop --release
```

Focused origin tests after the final return-analysis repair:

```text
cargo test --features python-ext origin --lib --quiet
33 passed; 0 failed
```

The real regression cell is green:

```text
uv run python tools/dectest.py \
  '45_string_algorithms:clang:O2strip:format_decimal' --show
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

The release-built complete stripped/debug differential:

```text
uv run python tools/stripped_differential.py --jobs 8 --json
103 regressions; 17 improvements; 0 changed; 0 infrastructure problems
```

The propagation sweep began at 112 regressions and 17 improvements, so it
removes nine regressions without losing an improvement or introducing an
infrastructure failure. These are matched stripped/debug fixture comparisons,
not a DecBench score or a claim about another corpus.

The complete Rust gate on the final source is green:

```text
cargo test --features python-ext --quiet
library: 4,244 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The whole Python gate required after a `src/` commit completed red:

```text
uv run pytest python/tests/ -q
231 failed test nodes in the terminal pytest cache; gate exit 1
```

The output transport truncated pytest's 361,655-token failure report, so this
record does not invent unavailable pass/skip/xfail subtotals. The cache was
updated by this completed run at 2026-09-06 15:57:10 EDT and contains 5,759
known node IDs. Failures span pre-existing/shared lanes including generated
references and baselines, parser dialects, canonical hello matrices, fixture
ratchets, and unrelated `csource`/source-metrics work present in the worktree.
This is an honest broad red gate, not evidence that those failures belong to
this increment and not a release-green claim. The focused origin tests, full
Rust gate, real target, and stripped differential above are the increment's
acceptance evidence.

## Remaining WP3 boundary

Next in dependency order is the remaining WP3 core: ratchet legacy unknown
invalidations downward, migrate consumers incrementally, add expression origins
and structured line mappings, and prove byte neutrality
except for explicitly measured corrections. The statement carrier is
substrate for that work, not a substitute for it.
