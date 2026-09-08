# WP3 adjacent overwritten-store identities

Commit `592ea81b` moves adjacent overwritten promoted-store cleanup from
display-name inference to producer-owned stack-object identity. The production
dead-store path now optimizes a slot only when `ValueIdentities` proves it is
promoted stack storage. The explicit no-sidecar compatibility path retains its
historical `local_` / `stack_` convention.

The fail-closed regression was observed red before the fix: an unowned object
spelled `local_8` lost its first store. It is now preserved, while an opaque
owned `frame_object` still removes the immediately overwritten value. Both
exact tests and all 47 `ir::dead_stores::tests` pass with 4,566 unrelated Rust
tests filtered out.

After a fresh serial debug extension build, `tools/build_guard.py` reports the
native module fresh and the exact committed Win64/PDB
`test_overwritten_win64_push_value_does_not_become_an_undefined_local` fixture
passes. The census records 5,150 declared Rust tests and zero outside every
gate; all six census checks pass after the source commit. The four-cell Hello
World checkpoint then passes four-for-four across x86-64 Clang and AArch64,
each at O0 and O2 with symbol-bearing PIE input. Every cell independently
compiles its binary and requires exact canonical recovered source. No broad
Rust suite, Python suite, fixture matrix, DecBench, or Joern lane ran.
