# WP3 prototype returns preserve the reaching SSA value

Status: bounded WP3 semantic-reader migration landed at `6993a984` on
`master`.

## Result

Early prototype-output materialization now uses the pipeline's authoritative
`ValueIdentities`. A direct floating-point helper result may legally travel
from `xmm0` through an integer carrier such as `rax`; the return selector now
recognizes that coalesced cross-bank identity and chooses the latest reaching
result rather than an earlier incoming argument value in the same carrier.

The concrete GCC O0 failure was:

```c
ret = x;
x = fp172_horner_f64(x, a, b);
return ret;
```

It now round-trips as the helper result, and the corresponding known-failure
entry is closed in `tests/decompiler_fixtures/baseline.json`. Selection remains
fail-closed: every identity candidate must occupy modeled ABI result storage,
and at least one must be in the preferred integer result tier. Display names
are not semantic evidence.

## Focused evidence

The focused regression reproduces the real `xmm0 -> rax#2 -> xmm0` transport:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext ir::direct_output::tests --lib
23 passed; 0 failed; 4,747 filtered out; finished in 0.00s
```

An exact detached release build of `6993a984` produced native SHA-256
`d346a3d9a09aac5c6f0510a6466d35ab09b76592a25c922c1214f68f8f947840`.
The build guard reported the detached native extension fresh. The complete
host fixture slice passed:

```text
tools/dectest.py '172_float_double_widths:*:*:double_precision_horner' \
  --show --full
4 passed; 0 failed
172_float_double_widths:gcc:O0:double_precision_horner: fail -> pass
```

The periodic symbols/PIE Hello checkpoint also passed all six selected cells:
x86-64, AArch64, and ARMv7 at O0 and O2.

## Measurement boundary

Only the 23 direct-output tests, the four host Horner fixture cells, and six
Hello cells ran. No broad Rust or Python suite, complete fixture matrix,
cross-corpus sweep, DecBench, Joern, GED, or performance run was used. This
closes one premature-return-materialization consumer; WP3 remains open.
