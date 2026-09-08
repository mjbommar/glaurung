# WP3 enclosing call-argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `f2e69784` preserves instruction origins when
`EnclosingSlots::advance_reaching` records a versioned ABI-register definition.
Calls nested inside a guarded function-table dispatch therefore receive the
exact owners of the enclosing definitions used as their argument expressions.

This closes the table-call reaching-value fallback and benefits every consumer
of the same authoritative enclosing-value record. Existing origin-bearing
overrides remain unchanged, locally captured table setup continues through the
already-migrated recovered-layout producer, and unversioned, clobbered,
partial-lane, or control-ambiguous definitions still clear or decline.

Together with the generic register, SysV/AAPCS stack, recovered-layout,
cdecl32, and hard-float increments, this completes the currently identified
call-argument expression producers. It does not complete universal expression
attribution, SSA consumer migration, invalidation ratchets, or WP3.

## Focused verification

The guarded table-dispatch test was given two distinctly attributed enclosing
definitions and observed red: both recovered argument expressions had the
correct versioned register but no origin. After recording provenance with the
reaching value, both arguments retain their exact owners.

One older assertion expected origin-transparent reaching analysis to discard
the carrier. The touched-module run exposed it; the assertion now checks the
same semantic register plus its preserved exact owner.

```text
cargo test --features python-ext \
  a_proven_table_call_reads_the_enclosing_reaching_definitions --lib
1 passed; 0 failed

cargo test --features python-ext \
  origin_wrappers_do_not_hide_enclosing_reaching_definitions --lib
1 passed; 0 failed

cargo test --features python-ext 'ir::call_args::tests::' --lib
111 passed; 0 failed; 4,249 filtered out; 0.19 seconds
```

The exact real-binary comparison covers only the guarded and loop-carried
dispatch functions from fixture 95 across GCC/Clang O0/O2. Parent and isolated
tip have the identical eight-function map: three pass and five fail. Four of
the failures are reported as baseline regressions and all predate this change;
none is added or removed by the provenance migration.

The tip build guard reports fresh at exact commit `f2e69784`, with native
SHA-256 `fe5bc9843180575933bcafa5f51955c1f2bf3aa99d2cb4c8a5a1f3bb32a6a38e`.
No full Rust, Python, fixture, architecture, or DecBench suite was run.

## Next boundary

Re-audit remaining non-exhaustive expression consumers now that the complete
call-argument producer family is migrated. Select the next production
expression constructor that consumes attributed inputs, add exact composition
tests, and keep SSA/invalidation work ahead of dependent WP6/WP7B architecture.
