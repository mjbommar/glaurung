# WP3 cdecl32 frame expression origins

Date: 2026-09-08

Commit: `e26e43f2`

## Defect and repair

GCC's 32-bit aligned entry frame is a complete transaction: align `esp`, save
the incoming frame/stack bases, allocate the callee frame, and restore the same
bases before return. Glaurung collapses it only when those facts balance and no
removed storage identity remains live.

Statement-level origins were already retained on the resulting prologue and
epilogue annotations, but the transaction inspected its child expressions
directly. Provenance on an alignment operand, frame-base source, saved push,
promoted parameter address, allocation width, or restore operand prevented the
same balanced frame from matching and left machine setup in source output.

`src/ir/x86_prologue.rs` now classifies each expression in this transaction
through its semantic view. Exact stack/frame registers, promoted-slot identity,
push/pop counts, allocation/restore widths, and the post-removal liveness check
remain required.

## Focused validation

The existing transaction contract
`attributed_cdecl32_entry_frame_keeps_prologue_and_epilogue_owners_separate`
was strengthened so every relevant child expression carries an independent
owner. It was observed red with all eight input statements surviving and passes
after the repair with separate attributed prologue and epilogue annotations.
The complete owning module passes:

```text
running 45 tests
test result: ok. 45 passed; 0 failed; 0 ignored; 4651 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and cache-backed build directories:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run pytest \
  python/tests/test_pe32_cdecl_roundtrip.py::test_i386_cdecl_decompile_recompile_execute_round_trip \
  -q
```

Results:

```text
native extension: fresh
1 passed
```

This is one exact PE32 execution round trip, not the entire Python suite. The
increment closes the aligned-entry-frame transaction but not every remaining
x86 epilogue expression reader or universal WP3 attribution.
