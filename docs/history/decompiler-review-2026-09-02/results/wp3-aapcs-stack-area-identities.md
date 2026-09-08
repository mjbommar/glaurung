# WP3 AAPCS stack-area identities

Status: landed in `06b6f429` on `agent/wp5-next-switch`.

## Result

Preallocated AAPCS outgoing stack arguments now require the address base and
intervening stack-pointer writes to carry authoritative `sp` identity. The
reader no longer accepts a display spelling such as `sp#2` as proof of stack
storage.

An opaque value whose complete identity candidate set is `sp` is accepted. A
displayed `sp#2` mapped to `r4`, a missing sidecar identity, or identities that
do not all agree on `sp` are rejected. The explicit no-sidecar compatibility
entry point retains the old name parser.

## Focused evidence

- Exact regression: `aapcs_stack_area_uses_exact_identity_not_display_spelling`
  passed (`1 passed`, `4477 filtered out`).
- Owning AAPCS module: `cargo test --features python-ext --lib
  ir::call_args::aapcs -- --nocapture` passed (`6 passed`, `0 failed`, `4472
  filtered out`).
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  11_call_shapes:armv7:O2:call_into_spill --show` selected exactly one of 3,304
  lanes and reported no regression.

The adjacent ARMv7 O0 cell reported `pass -> fail`, but an isolated patch-off
rebuild reproduced the same output and failure at the exact parent. That stale
baseline row is therefore recorded as pre-existing debt, not evidence for or
against this increment.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. The cdecl stack reader is the next call-recovery surface that
still derives stack identity from display names.
