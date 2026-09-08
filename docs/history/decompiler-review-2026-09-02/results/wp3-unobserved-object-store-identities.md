# WP3 unobserved object-store identities

Commit `ca6a4df7` moves unobserved promoted-object field-store cleanup from
display-name inference to producer-owned stack-object identity. Production now
deletes those stores only when `ValueIdentities` says the base is promoted
stack storage. The explicit no-sidecar compatibility entry point retains its
historical `local_` / `stack_` rule.

Two exact adversarial tests prove both sides of the boundary: an opaque owned
`frame_object` is cleaned up, while an unowned object spelled `local_10` is
preserved. All 45 `ir::dead_stores::tests` pass with 4,566 unrelated Rust tests
filtered out.

After a fresh serial debug extension build, `tools/build_guard.py` reports the
native module fresh and only `09_memory_effects:clang:O0:tick_n` was exercised;
it reports no scoped regression. The census records 5,148 declared Rust tests
and zero outside every gate, and all six census checks pass after the source
commit. The four-cell Hello World canary was not repeated because this bounded
identity migration does not change rendering; its immediately preceding
amd64/AArch64 Clang O0/O2 run remains four-for-four. No broad Rust suite,
Python suite, fixture matrix, DecBench, or Joern lane ran.
