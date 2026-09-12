# WP3 path-sensitive live-in result projection

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `c39f41d2` closes the AArch64 O2 `call_chain_in_loop` execution
regression at the direct-output identity boundary. The function returns its
live-in `x0` value when the loop count is zero and a later loop-carried `x0#1`
value after the loop. Direct-output projection previously selected the later
value globally and inserted it into every bare machine return. The early path
therefore read a definition that existed only in the nonzero branch.

When an authoritative prototype proves that live-in argument zero is also the
result and the production identity sidecar is present, bare returns now consume
the result definition reaching their lexical path. Conditional and loop-local
definitions remain inside their region and cannot escape a region that may not
execute. The compatibility path remains fail closed: a versioned result write
without identities still blocks live-in inference rather than guessing which
version reaches a return.

The resulting source shape is execution-correct and exposes the real early
return:

```c
if (n == 0) {
    return seed;
}
int v = seed;
/* loop */
return v;
```

## Evidence

- The exact AArch64 O2 fixture was observed red before the repair: zero rounds
  returned `0` instead of `22176384` for input `[0, 0]`.
- The focused reaching-result regression and all 24 `direct_output` tests pass.
- A release extension rebuild is fresh.
- `11_call_shapes:aarch64:O2:call_chain_in_loop` passes its execution
  differential.
- The enclosing AArch64 O2 `call_chain_in_loop` and `call_into_spill` pytest
  test passes.
- All four host GCC/Clang O0/O2 `call_chain_in_loop` fixture lanes pass.
- The required post-source whole-Python fail-fast gate passes the former 17%
  AArch64 stopping point and next stops at the adjacent i386 O2 GOT-relative
  switch test: both `dense_dispatch` and `dispatch_in_loop` fail execution.
  This path-sensitive change cannot run on cdecl32, whose stack parameter zero
  does not alias the `eax` result register, so that next failure is outside the
  changed route rather than evidence for this increment.

This is one bounded WP3 result-identity consumer migration. It does not replace
the general structured reaching-definition work, finish expression ownership,
or complete WP3.
