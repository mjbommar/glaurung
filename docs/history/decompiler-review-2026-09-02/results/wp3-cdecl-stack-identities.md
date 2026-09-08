# WP3 cdecl stack identities

Status: landed in `75c95f4b` on `agent/wp5-next-switch`.

## Result

The cdecl argument reader now carries the identity sidecar through its complete
stack proof: outgoing stores, push lowering, frame-prologue refusal, caller
cleanup, stack-mention safety, surviving-displacement rebasing, and bounded PIC
setup traversal all classify `esp`/`rsp`/`ebp`/`rbp` by authoritative SSA
identity.

An opaque value proved to occupy `esp` is accepted. A displayed `esp#2` proved
to occupy `eax`, missing identity evidence, or mixed identity candidates are
not treated as stack storage. The explicit no-sidecar path retains its existing
name-based compatibility behavior.

## Focused evidence

- Exact regression: `cdecl_stack_reader_uses_exact_identity_not_display_spelling`
  passed (`1 passed`, `4478 filtered out`).
- Narrow cdecl filter: `cargo test --features python-ext --lib cdecl32 --
  --nocapture` passed (`27 passed`, `0 failed`, `4452 filtered out`) in 0.19
  seconds. This includes the call-argument cdecl tests and the adjacent cdecl
  ABI/prologue/stack-local tests selected by that exact filter, not the full
  Rust suite.
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  11_call_shapes:i386:O0:call_into_spill --show` selected exactly one of 3,304
  lanes and reported no regression.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. The next step is to audit the remaining production
call-recovery name readers, separating ABI layout declarations and explicit
no-sidecar compatibility parsers from value-identity consumers that still need
migration.
