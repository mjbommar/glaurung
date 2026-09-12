# WP3 coalesced frame-save identity closure

Commit `02c2fd19` closes the remaining non-LTO undefined-local failures in the
build-configuration invariant. GCC's x86-64 frame-pointer code can save `rbp`
before a delayed frame setup, and can place that save inside one structured
branch. AST coalescing retained several SSA candidates for the rendered source
value, so the old cleanup required an exact identity that production could not
provide. The machine save survived as a read from an undefined `rbp`, exposed
through a fabricated `stack_0` or `local_c` source variable.

The cleanup now accepts a coalesced entry value only when every candidate has
the same physical-register base and at least one candidate is version zero.
Mixed physical bases and candidate sets containing no entry value still fail
closed. Storage must independently carry producer-owned `machine_saved_slot`
evidence. The same proof now applies recursively to structured bodies in the
one production `recognise_machine_frame` pass; the former shadow-only duplicate
invocation and its boolean plumbing were removed.

Two observed-red Rust contracts cover the straight-line and nested forms. The
complete owning module passes:

```text
cargo test --features python-ext ir::dead_stores::tests:: --lib -q
51 passed; 0 failed; 4,760 filtered out
```

Python-visible validation used a release extension in the isolated verifier
`/home/mjbommar/.cache/glaurung/verify-canary-73b8fbba`, with exactly the
`02c2fd19` source delta applied to the clean `73b8fbba` source base. The focused
real-binary invariant passes every supported configuration:

```text
uv run pytest \
  python/tests/test_build_configuration_invariants.py::test_no_recovered_local_is_read_without_ever_being_assigned \
  -q -vv
10 passed; 1 xfailed in 1.99s
```

The sole xfail is the separately declared LTO cross-CU DWARF/frame defect.
Direct batch decompilation of the two formerly failing frame-pointer functions
shows the user-visible closure. `bc_many_parameters` is now a direct arithmetic
return with no local declarations; `bc_pointer_walk` contains the source-level
early return followed by `return strlen(s) + 1;`. Neither output contains
`rbp`, `stack_0`, or an unassigned frame-save local. `bc_pointer_walk` still
declares an unused `len`; that is declaration cleanup, not an undefined read.

A periodic GCC x86-64 Hello check ran only `main` at O0 and O2. Neither output
contains the repaired frame-save artifacts. O2 remains structurally valid. O0
still reports two pre-existing definition-before-use findings in exception
paths, so this is not a broad Hello-green claim.

The required post-source-commit gate advanced beyond the former 8 percent
frame-pointer stop:

```text
uv run pytest python/tests/ -x
1 failed; 632 passed; 16 skipped; 128 deselected; 3 xfailed;
2 subtests passed in 166.36s
```

It stopped at 11 percent on
`test_cli_decompile.py::test_decompile_entry_prints_pseudocode`, whose `_start`
output names `__libc_start_main` but loses its reconstructed `main` argument.
A release parent-source A/B rerun fails the exact test identically, proving that
failure is pre-existing and not caused by recursive machine-frame cleanup. The
full Python suite remains red and no broader fixture corpus was run.
