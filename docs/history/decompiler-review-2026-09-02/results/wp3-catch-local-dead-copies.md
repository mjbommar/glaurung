# WP3 catch-local dead-copy cleanup

Final commit `0d8b92c8` completes one bounded cleanup omission exposed after
typed-handler recovery. Dead-copy counting previously used one whole-function
read map, so a register spelling used on the normal path could falsely keep an
unread assignment with the same spelling in a mutually exclusive catch body.
Catch bodies now receive their own conservative spelling-based read census.

The scope is intentionally smaller than the first implementation in
`842dd5fc`: the four-cell runtime fixture immediately found that recursively
cleaning the normal try body could delete a value required by GCC O2. Follow-on
`b04e0b78` preserved post-recovery spelling identity, and `0d8b92c8` removed
the remaining unsafe surface by limiting the new recount to catches. This is
the WP3 rule in miniature: identities created or rearranged after value
numbering are not treated as authoritative.

## Focused evidence

The catch-local contract was observed red first. At the final commit:

```text
cargo test --features python-ext --lib \
  exception_regions_have_independent_dead_copy_counts
1 passed; 4,742 filtered out

cargo test --features python-ext --lib ir::copy_prop::tests::
36 passed; 4,707 filtered out
```

An exact detached release build of `0d8b92c8` produced native SHA-256
`1198a1665afc991f129bd2c82e37bf66d8e119c7d62e3644369c3cac47858436`.
The directly owning execution differential is fully green:

```text
10_cpp_runtime_shapes:clang:O0:cpp_exception  pass
10_cpp_runtime_shapes:clang:O2:cpp_exception  pass
10_cpp_runtime_shapes:gcc:O0:cpp_exception    pass
10_cpp_runtime_shapes:gcc:O2:cpp_exception    pass
```

The GCC O0 catch no longer emits the unused `rbx_1 = ...` assignment; it now
computes `rax_9` and returns that value directly. The periodic canonical Hello
checkpoint also passes exactly six GCC symbols/PIE cells: O0 and O2 on x86-64,
AArch64, and ARMv7.

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite ran.
Advanced aggregate and nested C++ unwinding remains a separate exception-type
and region-model capability, not a cleanup failure addressed here.
