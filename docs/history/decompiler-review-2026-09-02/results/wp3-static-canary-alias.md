# WP3 static glibc canary alias closure

> **Kind:** record · **Date:** 2026-09-12

Commit `73b8fbba` closes the undefined-local regression in statically linked
glibc binaries whose stack-protector failure edge calls the hidden
`__stack_chk_fail_local` alias. The canary pass already recognised the ordinary
`__stack_chk_fail` and PLT spellings, but its structured failure-arm predicate
required that exact base name. It therefore collapsed the proved prologue save
to a comment while leaving the failure comparison alive, producing an
observable read of an unassigned `local_10`.

The failure-call predicate now accepts exactly `__stack_chk_fail` and
`__stack_chk_fail_local` after removing an optional symbol-version suffix. It
does not use a broad prefix match. An observed-red Rust contract reproduces the
structured static-glibc shape, and all 26 canary tests pass after the repair:

```text
cargo test --features python-ext ir::canary::tests:: --lib
26 passed; 0 failed
```

The Python-visible check used a fresh detached worktree at exact commit
`73b8fbba`, CPython 3.14.3, a release extension with SHA-256
`56c008de38f10cc90250aceba47dd8ff7ff3b98a81492340cfc6c47f11786f92`, and:

```text
uv run pytest \
  python/tests/test_build_configuration_invariants.py::test_the_stack_guard_is_never_part_of_the_recovered_interface \
  python/tests/test_build_configuration_invariants.py::test_no_recovered_local_is_read_without_ever_being_assigned \
  -q -vv
```

The static-executable `local_10` interface and undefined-read findings are gone.
Nine non-skipped/xfail configuration nodes pass. The independent frame-pointer
defect remains red: `bc_many_parameters` and `bc_pointer_walk` render a source
local initialised from an undefined `rbp`. The LTO frame-recovery case remains
the declared strict xfail.

The required post-source-commit gate was started with
`uv run pytest python/tests/ -x` in that same verifier. It stopped at the first
remaining `rbp` failure after 532 passes, 15 skips, 128 deselections, two
xfails, and two passing subtests in 125.50 seconds. This is a decisively red
partial gate, not a full-suite-green claim. The next correctness slice is the
frame-pointer source-identity defect, not another canary exception.
