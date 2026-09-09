# WP3 stack-load address expression origins

Date: 2026-09-08

Commit: `9e3a75e9`

## Defect and repair

Once an address-taken frame slot has a bounded stack-object identity, a later
dereference must retarget its frame-relative address to that `StackAddr`.
`rewrite_expr` correctly resolved through an expression-origin carrier, but
then replaced the complete address node. The load reached the right storage
while silently losing the instruction ownership attached to its address.

`src/ir/stack_locals/rewrite.rs` now replaces only the semantic payload of the
dereference address. The original carrier remains around the recovered
`StackAddr`; storage recovery and attribution no longer compete.

## Focused validation

The end-to-end contract
`attributed_load_address_keeps_its_owner_when_retargeted_to_stack_object`
initializes a real frame slot, lets its address escape to a call, and then loads
through an independently attributed frame-relative address. It was observed
red before the repair and passes afterward. The complete owning module also
passes:

```text
running 120 tests
test result: ok. 120 passed; 0 failed; 0 ignored; 4574 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit, a separate virtual environment,
and cache-backed build directories:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run python tools/dectest.py \
  218_cpp_lambdas_and_callables:gcc:O0:mixed_capture --show
```

Results:

```text
native extension: fresh
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

This is focused evidence for bounded stack-object load retargeting. It does not
close the remaining WP3 semantic-expression consumers or universal production
attribution.
