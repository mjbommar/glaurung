# WP3 call frame-coordinate identities

Status: bounded production consumer migration landed at `42f9c5e0` on
`agent/wp5-next-switch`.

## Result

Call-argument substitution now decides whether a captured value is stack/frame
coordinate state through exact `ValueIdentities`. An opaque value with semantic
`rsp`, `rbp`, `sp`, or target-equivalent identity remains statement-rooted so
frame rebasing is not applied twice. A scratch merely spelled `rsp#version`
cannot block an otherwise valid substitution when its exact identity is `rax`.

Missing or ambiguous production identity declines frame-coordinate
classification. No-sidecar compatibility callers retain spelling recognition.

## Focused evidence

```text
/usr/bin/time -v cargo test --lib --features python-ext \
  ir::call_args -- --nocapture
131 passed; 0 failed; 4,341 filtered out
elapsed 11.55 s; maximum RSS 2,811,448 KiB

uv run maturin develop
completed

/usr/bin/time -v uv run pytest \
  python/tests/test_cli_decompile.py::test_real_arm_hard_float_compare_does_not_erase_three_call_args -q
1 passed
elapsed 0.57 s; maximum RSS 134,716 KiB
```

Build fingerprint: commit `42f9c5e0`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

The initially selected `11_call_shapes:gcc:O2` lane was not evidence: it hit a
`const_fold::fold_constants reported no change but edited the body` invariant.
An exact patch-off/patch-on rebuild reproduced the same failure without this
migration, so it is recorded as pre-existing rather than called a regression or
a pass.

## Measurement boundary

One directly related ARM C end-to-end behavior passed and no Rust fixture was
evaluated. No GED, byte, Union, goto, switch, break, or corpus-wide execution
measurement ran. No broad suite, fixture matrix, DecBench, or Joern ran.

## Remaining scope

This removes one production stack/frame semantic-name decision from call
argument substitution. Stack-area recovery, slot marking, captured-definition
aliasing, and AAPCS/cdecl readers remain separate migrations. WP3 remains open.
