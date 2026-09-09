# WP3 stack-idiom expression origins

Date: 2026-09-08

Commit: `08bfcbf8`

## Defect and repair

The x86 lifter represents a push as a stack-pointer subtraction followed by a
store, and a function epilogue can contain a final stack-pointer addition.
`stack_idiom` removes that machine bookkeeping from source-level output by
rematerializing push/pop operations and dropping the trailing epilogue adjust.

Those recognizers used the raw operands. Attaching an expression-origin carrier
to the stack register, adjustment width, stack-top slot, or restored value made
an otherwise identical idiom fail to match. The output then retained artificial
`rsp` arithmetic and stack-slot stores.

`src/ir/stack_idiom.rs` now classifies each of those operands through its
semantic view. Existing positive-width, physical-register, adjacency, and
return-position requirements are unchanged.

## Focused validation

The combined contract
`attributed_stack_operands_still_rematerialize_push_and_drop_epilogue_adjustment`
was observed red with all four bookkeeping statements surviving. It passes
after the repair with only the rematerialized push and return remaining. The
complete owning module passes:

```text
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored; 4683 filtered out
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
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-gcc]' \
  -q
```

Results:

```text
native extension: fresh
1 passed
```

This is one exact release-built Hello World cell, not the full Hello collection
or repository suite. The recent eight-cell O0/O2 cross-architecture checkpoint
remains the broader periodic measurement. This increment does not close the
remaining WP3 semantic consumers or universal production attribution.
