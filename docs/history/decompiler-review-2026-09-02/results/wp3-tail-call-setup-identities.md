# WP3 tail-call setup identities

Status: landed in `6ab43e01` on `agent/wp5-next-switch`.

## Result

Resolved direct and symbol-backed indirect tail-call recovery now receives the
pipeline's identity sidecar. Its decision whether a local statement sets up an
ABI argument is made from complete SSA identity candidates rather than a
register display spelling.

The classification recurses through every structured statement body. An opaque
value proved to occupy `rdi` prevents speculative forwarding of all entry
arguments. A displayed `rdi#1` proved to occupy `rax` is not mistaken for local
argument setup. Ambiguous cross-slot identities remain conservative. Existing
public no-sidecar entry points retain their compatibility behavior; the new
sidecar-aware entry points remain crate-internal.

## Focused evidence

- Exact regression: `tail_setup_uses_exact_identity_not_display_spelling`
  passed (`1 passed`, `4479 filtered out`).
- Owning module: `cargo test --features python-ext --lib
  ir::call_args::tail_calls -- --nocapture` passed (`14 passed`, `0 failed`,
  `4466 filtered out`).
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  06_calling_conventions:gcc:O2:forward_sum6 --show` selected exactly one of
  838 host lanes and reported no regression.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. Proven Rust vtable-tail recovery still recognizes the high
result word and intervening writes from display names and is the next tail-call
identity slice.
