# WP3 exception landing-pad inputs

> **Kind:** record · **Date:** 2026-09-12

Commit `b0319768` closes the GCC O0 C++ cleanup-path definedness regression.
The real `main` at `0x2549` ended its normal path with `return`, after which
the generic unreachable-tail pass deleted the first LSDA landing-pad entry.
Later cleanup code still read that entry's saved exception object. A second
landing pad survived structurally, but its exception-object register was an
implicit unwinder input and therefore had no ordinary predecessor definition.

Two deliberately separate rules repair those defects:

- a producer-owned `__glaurung_eh_landing_<va>` marker reopens reachability
  after a normal terminator because LSDA metadata proves an external
  exceptional entry;
- the first landing-pad copy becomes an explicit external unknown only when
  `ValueIdentities` proves one unambiguous ABI integer-result register. A
  suggestive rendered name, a mixed physical-base set, or another first
  operation does not authorize the rewrite.

The latter rule models Itanium's unwinder-supplied exception object honestly.
It does not invent a predecessor definition or treat an arbitrary undefined
local as a parameter. Scored C renders the established opaque expression as
`__unknown(0)` and remains parseable.

## Focused evidence

The reachability contract was observed red before the fix: only the leading
`return` survived. After the fix, all 22 label-pruning tests pass. The two new
identity contracts pass individually: an opaque value proven to be `rax`
materializes, while mixed `rax`/`rbx` identity declines.

An isolated release extension carrying the exact source overlay has SHA-256
`de6e45554988f2cc8497f6db9ea285d0bd85357aeff520be4f29615463436a20`.
The fixture-backed regression is green:

```text
uv run pytest \
  python/tests/test_decompiler_output_canaries.py::test_real_cpp_cleanup_landing_inputs_are_defined \
  -q
1 passed
```

With `GLAURUNG_VERIFY_DEFS=1`, the GCC O0 Hello C++ `main` now has zero
`glaurung-verify` findings. Its LSDA cleanup regions survive after the normal
return, every `_Unwind_Resume` argument has a definition, and unwinder inputs
render explicitly as `__unknown(0)`.

The four directly owning executable exception cells remain green:

```text
10_cpp_runtime_shapes:clang:O0:cpp_exception  pass
10_cpp_runtime_shapes:clang:O2:cpp_exception  pass
10_cpp_runtime_shapes:gcc:O0:cpp_exception    pass
10_cpp_runtime_shapes:gcc:O2:cpp_exception    pass
```

The twelve functions in fixture `136_cpp_exception_unwinding` remain at their
existing failed baseline across GCC/Clang O0/O2; this increment introduces no
change in that slice and does not claim broader exception recovery complete.
Follow-on test-only commit `3bc525f5` resolves the module's stale AArch64 GOT
throw assertion. The machine sequence zero-extends a 32-bit reload to 64 bits
but stores only four bytes into an `int` exception object; preparation
correctly reduces this to one signed 32-bit cast. The assertion now checks that
semantic contract instead of requiring obsolete nested-cast scaffolding, and
all 13 exception-recovery tests pass.

The required post-source-commit `pytest python/tests/ -x` gate stopped at the
unrelated CFR retrieval corpus-size invariant after 569 passes, 15 skips,
three xfails, and two subtests in 131.34 seconds on the confirming run: only
eight eligible queries
were present where the test requires twenty. This is a partial gate, not a
whole-suite-green claim. No DecBench or Joern run was performed.
