# WP3 exception-origin propagation

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `cda7ab73` makes the post-pipeline C++ exception recovery consumer
transparent to statement-origin wrappers. It preserves the contributing
instruction addresses when raw landing-pad flow becomes a structured
`try`/`catch`, compiler-runtime allocation and throw calls become `throw`, or a
restored catch value becomes a direct return.

This is a bounded WP3 consumer migration. It does not complete expression
origins, structured line mappings, non-contiguous transformation policy,
authoritative SSA migration, or the remaining wildcard consumer audit.

## Correctness repair

The statement carrier exposed a late consumer that still matched raw `Stmt`
variants. Wrapped labels, calls, gotos, returns, and stores therefore became
invisible to exception recovery. On the real Clang O2 stripped C++ fixture this
left the catch path after an ordinary return instead of recovering the typed
handler. The consumer now inspects the semantic statement while retaining the
wrapper, and every synthesized exception node receives the deterministic union
of the statements it replaces.

## Evidence

Focused unit coverage and release build:

```text
cargo test --features python-ext exception_recover --lib --quiet
8 passed; 0 failed

export TMPDIR="$HOME/.cache/glaurung/tmp"
uv run maturin develop --release
```

The real regression cell is green:

```text
uv run python tools/dectest.py \
  '10_cpp_runtime_shapes:clang:O2strip:cpp_exception' --show
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

The complete release-built stripped/debug differential:

```text
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 changed; 0 infrastructure problems
```

The carrier work began at 112 regressions and 17 improvements. The preceding
statement-pass migration reached 103; this exception migration removes one
more without losing an improvement or introducing an infrastructure failure.
These are matched fixture comparisons, not a DecBench result.

The complete Rust gate on the committed source is green:

```text
cargo test --features python-ext --quiet
library: 4,245 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The whole Python gate required after a `src/` commit completed red. Its pytest
cache records 230 failing node IDs across the shared checkout. The failures
span stale generated inventories and documentation manifests, canonical-output
ratchets, cross-architecture toolchain lanes, and decompiler defects already
tracked by the plan; they are not evidence that this bounded exception repair
is globally green. The focused exception test, real target, complete stripped
differential, and complete Rust gate above are the attributable evidence for
this increment.

## Remaining WP3 boundary

The four isolated origin-era regressions now belong to floating-point and x87
families: fixture 175 Clang O2 stripped `dot_product_f64`, fixture 181 Clang and
GCC O2 stripped `kahan_sum_f64`, and fixture 205 GCC O2 stripped
`x87_compare_classify`. Continue from those measured cells, then finish the
wildcard consumer audit, expression origins, non-contiguous composition rules,
structured Python line mappings, and stable-identity consumer migrations.
