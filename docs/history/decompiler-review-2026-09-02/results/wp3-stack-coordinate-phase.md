# WP3 stack-coordinate phase preservation

Date: 2026-09-06

Behavioral commits: `4fa0b12f`, hardened by `dcdc99cc`

## Defect

A stripped SysV x86-64 wrapper loaded an outgoing variadic argument from
`[rsp + 8]`, restored `rsp`, and then made its tail call. Call-argument folding
moved the dereference to the call site, after the stack adjustment. The same
textual address then named a different slot, and stack promotion misclassified
it as an incoming seventh parameter. A real two-parameter function rendered
with seven parameters and forwarded `arg6` instead of `arg1`.

## Change

The first repair kept every non-substitutable call setup statement rooted.
That solved the fixture but widened behavior far beyond the memory-coordinate
defect. The hardened rule keeps only a dereference through the active stack
pointer rooted when moving it would cross an assignment to that stack pointer.
Ordinary expressions and other impure expressions retain the established
folding behavior until WP3 has a general memory/reaching-definition model.

This is a bounded value-origin/phase repair. It does not claim general memory
SSA or complete WP3.

## Real output

The stripped wrapper moves from a seven-parameter signature and
`error(..., arg6)` to a two-parameter signature and `error(..., arg1)`.

## Validation

- `cargo test --features python-ext ir::call_args::tests::`: 94 passed.
- `python/tests/test_cli_decompile.py::test_real_stripped_format_wrapper_recovers_forwarded_string_parameter`:
  passed against the rebuilt release extension.
- `cargo test --features python-ext`: complete green Rust gate; 4,200 library
  tests passed, zero failed, five ignored, and all integration/doc targets
  passed.
- The complete def-use census is 4/6 green. Its two red ratchets reproduce
  before this repair at `ce3fd28a`; no baseline was changed.
