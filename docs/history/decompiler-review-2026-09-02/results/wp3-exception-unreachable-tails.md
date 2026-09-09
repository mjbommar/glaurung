# WP3 recovered exception unreachable tails

Commit `84771886` closes the late exception-region omission in the existing
origin-transparent unreachable-tail pass. The pass already removed sequential
text after an unconditional transfer, but it neither entered `TryCatch` bodies
nor treated `Throw` as a terminator. Typed handlers and throws are recovered
after the ordinary preparation cleanup, so production now reruns the same pass
at an explicit named boundary immediately after throw recovery.

The rule is structural and conservative. It removes only sequential statements
after `return`, `throw`, `goto`, indirect goto, or `break`, while a surviving
label still reopens a possible entry. Surviving attributed statements keep
their exact origin sets; removed unreachable statements do not donate ownership
to another node.

## Focused evidence

The attributed try/catch contract was observed red first. At the committed
implementation:

```text
cargo test --features python-ext --lib \
  attributed_exception_terminators_prune_only_their_unreachable_tails
1 passed; 4,743 filtered out

cargo test --features python-ext --lib ir::label_prune::tests::
21 passed; 4,723 filtered out
```

An exact release build of `84771886` produced native SHA-256
`1a76d041523821b80fba806cabe6a10d1944d676ea800f4ace1bf3a01f811b71`.
The directly owning execution slice is green:

```text
10_cpp_runtime_shapes:clang:O0:cpp_exception  pass
10_cpp_runtime_shapes:clang:O2:cpp_exception  pass
10_cpp_runtime_shapes:gcc:O0:cpp_exception    pass
10_cpp_runtime_shapes:gcc:O2:cpp_exception    pass
```

Direct inspection of a symbol-bearing GCC-O2 build confirms that the catch now
ends at its first return instead of rendering a second unreachable normal-path
return. The pre-render verifier count on that specimen drops from five
undefined reads to three. Those remaining `local_c`, `rax_5`, and `stack_0`
findings are retained for a separate exception-region identity/dataflow audit;
this increment does not relabel them as harmless.

The one real pipeline-profile output-transparency test passes, as does the
periodic six-cell GCC symbols/PIE Hello checkpoint at O0/O2 across x86-64,
AArch64, and ARMv7. No broad Rust, Python, fixture, architecture, DecBench, or
Joern suite ran.
