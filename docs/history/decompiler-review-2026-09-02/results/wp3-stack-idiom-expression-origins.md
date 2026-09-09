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

## Earlier value-owner increment

Commit `4c19cb2e` preserves exact value provenance when the stack-idiom pass
rematerializes a lifted decrement/store pair as `Stmt::Push`.

The pushed expression retains any owner it already carried and additionally
owns the store that supplied the pushed value. The synthesized push statement
continues to own the union of the stack decrement and store. This keeps the
value-producing instruction distinct from stack-motion bookkeeping while
preserving the existing semantic collapse.

Pop targets are storage identities rather than expressions and need no
analogous expression carrier. Recognition and refusal rules were unchanged by
that increment. The existing attributed-push test was strengthened with three
distinct facts: an existing source-expression owner, a stack-decrement owner,
and a value-store owner. It was observed red because the pushed expression
retained only its existing owner and lost the store owner.

Focused verification at that commit was:

```text
cargo test --features python-ext \
  attributed_push_pair_unions_instruction_origins --lib
1 passed; 0 failed

cargo test --features python-ext 'ir::stack_idiom::tests::' --lib
11 passed; 0 failed; 4,349 filtered out
```

Its focused real-binary canary was
`208_flag_register_roundtrip::single_argument_survives`, which executes an x86
`pushfq`/`popfq` sequence. Parent and isolated-tip release builds both reported:

```text
clang O0 pass; clang O2 pass; gcc O0 pass; gcc O2 pass
4 lanes; no scoped regressions
```

The build guard was fresh at `4c19cb2e`, with native SHA-256
`2e4a5a7959beccb71d82f78308dc890de7d29edcd4a61dcdea99c10feeb81686`.
No full Rust, Python, fixture, architecture, or DecBench suite ran for that
increment.
