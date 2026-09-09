# WP3 escaping stack-address expression origins

Date: 2026-09-08

Commit: `00b1e612`

## Defect and repair

The address-taken stack-object promotion has a conservative ARM rule: a bare
frame anchor such as Thumb `r7` proves one saved machine word, not an array that
spans from the bottom of the frame to the CFA. That rule inspected the raw
expression. An origin carrier around `r7` therefore bypassed it and could turn
the saved frame pointer into a frame-sized byte array that swallowed adjacent
locals or argument homes.

The same routine replaced successful stack addresses by assigning the whole
expression. That discarded an existing origin carrier even when address
recovery itself correctly read through it.

`src/ir/stack_locals/rewrite.rs` now classifies the semantic frame-anchor node
and mutates only the semantic payload on every successful replacement path in
`promote_address_taken_stack_object`. The machine-word bound and original
expression owner therefore both survive.

## Focused validation

The contract
`attributed_arm_frame_anchor_stays_one_word_and_keeps_its_owner` was observed
red before the repair because its recovered object was wider than four bytes.
It passes afterward. The complete owning module also passes:

```text
running 119 tests
test result: ok. 119 passed; 0 failed; 0 ignored; 4574 filtered out
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
  25_kmp_search:armv7_a32:O0:kmp_search --show
```

Results:

```text
native extension: fresh
SCOPED: 1 lane of 3304 (0%) - no regressions in scope
```

This is focused evidence for the ARM escaping-address path. It does not close
the remaining WP3 semantic-expression consumers or universal production
attribution.
