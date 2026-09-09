# WP3 renderer valued types

Date: 2026-09-09

Source commit: `d4fe3568`

## Change

The DecBench-style typed renderer now recovers types for value-numbered LLIR
with the pipeline-owned `ValueIdentities` and `TypeMapV` sidecars. It no longer
routes that numbered function through the identity-free compatibility API.

This matters when value numbering canonicalizes a raw subregister occurrence.
For example, an incoming `edi` use becomes the opaque numbered `rdi` value. The
old renderer-local recovery inferred eight bytes from that presentation name;
the production path now recovers the original four-byte fact through the exact
SSA value.

Raw LLIR recovery remains identity-free intentionally. WP3 and removal of the
value-numbering tagger are not complete.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

The new contract was observed red first because the renderer had no
identity-aware numbered-type boundary. It then demonstrated both sides of the
defect: the compatibility path inferred eight bytes and the repaired path
inferred four.

```text
cargo test --features python-ext --lib \
  python_bindings::ir::type_maps::tests::numbered_renderer_types_retain_raw_use_width_by_identity \
  -- --exact
1 passed; 0 failed; 4,728 filtered out

cargo test --features python-ext --lib python_bindings::ir::type_maps::tests::
26 passed; 0 failed; 4,703 filtered out
```

A detached clean worktree at `d4fe3568` built the release extension. Its build
guard reported `fresh` with native SHA-256
`96eee8b6337717b91eb4f46c111b6ff6fa5e88ea9c6256aa1667ff627518028b`.
The directly adjacent width canary remained green:

```text
uv run python tools/dectest.py \
  174_float_compare_classify:gcc:O2:sign_bit_of_binary32 --show
SCOPED: 1 lane of 838; no regressions in scope
```

The three O2 symbols/PIE Hello cells on x86-64, AArch64, and ARMv7 passed on
the immediately preceding exact release commit `d68b005f`. They were not
redundantly rerun for this renderer-only increment.

No broad Rust suite, Python suite, fixture corpus, DecBench run, or Joern run
was performed.
