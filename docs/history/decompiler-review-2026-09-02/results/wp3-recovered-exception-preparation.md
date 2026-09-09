# WP3 recovered exception preparation

Commit `15c9734c` connects three origin-transparent cleanup capabilities to the
production point where typed exception bodies actually exist. Typed handlers
are recovered late, after the ordinary expression pipeline. Although copy
propagation, temporary reconstruction, and constant folding can now traverse
exception statements, they previously ran before `TryCatch` was created and
therefore could not improve newly recovered handlers.

Copy propagation now treats every try and catch body as an independent region,
substitutes a reaching copy into a throw value, and clears its environment at
the exceptional boundary. No copy is carried between the outer body, try body,
or any catch. Immediately after typed-handler recovery, the renderer runs that
copy propagation followed by the existing temporary reconstruction and
constant fold once, under one named and health-traced pipeline stage.

This is a bounded WP3 consumer/scheduling migration. It does not permit copies
across exceptional edges, infer exception types, or complete the remaining SSA
identity and invalidation work.

## Focused evidence

The new independent-region contract was observed red first: the pass reported
no change and both try-return and catch-throw copies remained. After repair:

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::exception_bodies_are_independent_copy_propagation_surfaces
1 passed; 4,741 filtered out

cargo test --features python-ext --lib ir::copy_prop::tests::
35 passed; 4,707 filtered out
```

An exact detached release build of `15c9734c` produced native SHA-256
`91da0f4818fa7bff419aa7e67385c62c03e6a3305f688fc7ca74df8e41410ba5`.
The directly owning fixture remains fully green:

```text
10_cpp_runtime_shapes:clang:O0:cpp_exception  pass
10_cpp_runtime_shapes:clang:O2:cpp_exception  pass
10_cpp_runtime_shapes:gcc:O0:cpp_exception    pass
10_cpp_runtime_shapes:gcc:O2:cpp_exception    pass
```

The complete narrow exception sample covered those four cells plus all twelve
GCC/Clang O0/O2 cells in `136_cpp_exception_unwinding`. It reported no baseline
regressions: the first four pass and the twelve advanced unwinding cells retain
their existing failing verdicts.

On GCC O0, the recovered `cpp_exception` function improves from 12 local
declarations to 6 and from 16 executable/label statements to 9. In particular,
the call argument loses two redundant machine-width casts, the normal return
loses an intermediate register assignment, and the catch arithmetic loses five
copy/cast temporaries. The behavioral differential remains green.

The one real pipeline-profile output-transparency test also passes when run
from the main checkout against the exact installed extension. Its first run
from the detached worktree failed before execution because that worktree has no
`.venv`; this was an environment-path failure, not a product result. The prior
six-cell x86-64/AArch64/ARMv7 O0/O2 Hello checkpoint was not repeated. No broad
Rust, Python, fixture, architecture, DecBench, or Joern suite ran.
