# WP3 captured scratch identities

Date: 2026-09-08

Source commit: `45c12f56`

## Change

Call reconstruction treats captured register arguments and removable stack
arguments differently. A numbered scratch can remain statement-rooted for a
register argument, whereas a stack argument must substitute the scratch
definition before its setup store disappears. Production previously selected
that policy by testing whether the destination spelling contained `#`.

The production path now asks the identity sidecar whether the destination owns
any non-entry SSA value. Opaque numbered scratch names therefore retain the
correct policy, and a misleading `#` spelling attached to a version-zero value
does not gain semantic authority. The parser remains only for callers that
explicitly provide no identity sidecar.

This advances the WP3 call-recovery audit. It does not complete the audit or
remove `tag_phys`.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::captured_scratch_numbering_comes_from_identity_not_spelling \
  -- --exact
1 passed; 0 failed; 4,502 filtered out

uv run maturin develop
passed; debug extension rebuilt

uv run python tools/build_guard.py
fresh; native SHA-256 dbc684c000bc46a0e26a24c246bf71d0d94fbdbe4336ec1ef485ee29c96965b5

uv run python tools/dectest.py 11_call_shapes:clang:O0:call_into_spill --show
1 of 838 lanes selected; no regression in scope
```

No broad Rust or Python suite, fixture sweep, DecBench run, or Joern run was
performed for this bounded increment.
