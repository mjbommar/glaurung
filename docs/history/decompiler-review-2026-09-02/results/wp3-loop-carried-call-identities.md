# WP3 loop-carried call identities

Status: landed in `10325870` on `agent/wp5-next-switch`.

## Result

Loop-carried ABI argument discovery now joins the pre-loop initializer and the
back-edge definition by their exact SSA identity. The argument slot comes from
that identity's physical storage rather than from a display spelling such as
`rdi#1` or `x0#1`.

An opaque initializer and loop value representing the same exact SSA value are
accepted even when their display names differ. Conversely, a value displayed
as `rdi#1` but authoritatively mapped to `rax` cannot be mistaken for argument
slot zero. Missing, ambiguous, unversioned, or differently initialized
identities still decline. Entry points without an identity sidecar retain the
existing compatibility parser.

## Focused evidence

- RED/GREEN regression:
  `loop_carried_input_uses_exact_identity_not_display_spelling` failed before
  the implementation and then passed (`1 passed`, `4475 filtered out`).
- Owning module: `cargo test --features python-ext --lib ir::call_args --
  --nocapture` passed (`135 passed`, `0 failed`, `4341 filtered out`) in 0.22
  seconds after compilation.
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  11_call_shapes:aarch64:O2:call_chain_in_loop --show` selected exactly one of
  3,304 lanes and reported no regression.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. The next call-recovery identity surfaces are the AAPCS and
cdecl readers that still derive storage facts from display names.
