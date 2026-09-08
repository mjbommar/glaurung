# WP3 vtable-tail identities

Status: landed in `c576b207` on `agent/wp5-next-switch`.

## Result

Proven Rust vtable-tail recovery now receives the pipeline identity sidecar.
The computed jump target is joined to its defining assignment by exact SSA
identity, and the vtable base plus intervening high-result writes are classified
from complete wide-return identity candidates rather than `rdx`-style display
names.

An opaque value proved to be the high half of the ABI's wide integer result is
accepted. A value displayed as `rdx#result` but proved to occupy `rax`, missing
identity evidence, or candidates that disagree on the wide-result part cannot
authorize vtable recovery. The public no-sidecar entry point retains its
compatibility behavior; the sidecar-aware entry point is crate-internal.

## Focused evidence

- Exact regression:
  `vtable_tail_uses_exact_high_result_identity_not_display_spelling` passed
  (`1 passed`, `4480 filtered out`).
- Owning module: `cargo test --features python-ext --lib
  ir::call_args::tail_calls -- --nocapture` passed (`15 passed`, `0 failed`,
  `4466 filtered out`).
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  167_rust_trait_objects:rustc:O2:rust_dyn_apply --show` selected exactly one of
  838 host lanes and reported no regression. Its terminal vtable call remains
  recovered; broader source-type/readability debt remains outside this slice.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. The next step is the remaining production parser audit in
the ordinary recovered-layout and call-fold paths, followed by removal of the
last typed dependency on `tag_phys`.
