# WP3 pair-return expression origins

Date: 2026-09-08

Commit: `8acf4d08`

## Defect and repair

The callee integer-pair pass composes two machine result registers into the
double-word C value required by the declared ABI class. Its statement owner was
preserved, but the synthesized root did not retain the original low-result
expression owner. Its explicit-SSE refusal and final signature validator also
matched raw expression shapes, so an origin carrier could hide a conflicting
float result or make an attributed composition appear uncomposed.

`src/ir/callee_return_pair.rs` now classifies those expressions through
`Expr::semantic()`. The synthesized `Or` root inherits the low-result
expression's origin set, while the original attributed subtree remains intact.
The declared `IntegerPair` class, exact low/high carrier identity, reaching-high
proof, all-return-path rule, and explicit-SSE refusal remain mandatory.

## Focused validation

The existing attributed pair-return contract now gives its low result an
independent expression owner and asserts that the synthesized root retains it.
That ownership assertion was observed red before the repair. The explicit-SSE
refusal now wraps its float conversion in an origin carrier as well. The
complete owning module passes:

```text
running 10 tests
..........
test result: ok. 10 passed; 0 failed; 0 ignored; 4686 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and a cache-backed build directory:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run python tools/dectest.py \
  195_by_value_aggregates:gcc:O0:bv195_make_quad --show
```

Result:

```text
native extension: fresh
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

This is one exact SysV GCC O0 aggregate-return lane, not the full aggregate or
repository suite. It closes the known expression-owner gaps in integer-pair
return composition; universal WP3 attribution and explicit invalidation remain
open.
