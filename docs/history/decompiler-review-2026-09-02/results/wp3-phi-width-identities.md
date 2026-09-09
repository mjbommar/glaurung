# WP3 phi-width identities

Date: 2026-09-09

Source commit: `d68b005f`

## Change

Scalarized XMM-lane phi recovery now decides whether every incoming value has
the same machine width directly from `(base, SSA version)` facts. It no longer
reconstructs a numbered `reg#version` spelling and queries the compatibility
name-keyed width map.

This removes one more typed dependency on value-numbering presentation text.
Phi-copy names are still rendered by the value-numbering tagger, so the broader
WP3 item to remove `tag_phys` is not complete.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

The new contract was observed red first because the identity-keyed query did
not exist. After the production change:

```text
cargo test --features python-ext --lib \
  ir::value_number::tests::phi_width_agreement_uses_ssa_values_not_numbered_spellings \
  -- --exact
1 passed; 0 failed; 4,727 filtered out

cargo test --features python-ext --lib \
  ir::value_number::tests::loop_phi_copies_retain_scalarized_lane_widths \
  -- --exact
1 passed; 0 failed; 4,727 filtered out

cargo test --features python-ext --lib ir::value_number::tests::
64 passed; 0 failed; 4,664 filtered out
```

A detached clean worktree at `d68b005f` built the release extension. Four
selected end-to-end checks passed:

```text
python/tests/test_decompiler_control_flow_semantics.py::test_clang_o2_vectorized_max_round_trips
python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-gcc]
python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-aarch64]
python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-armv7]
4 passed
```

No broad Rust suite, Python suite, fixture corpus, DecBench run, or Joern run
was performed.
