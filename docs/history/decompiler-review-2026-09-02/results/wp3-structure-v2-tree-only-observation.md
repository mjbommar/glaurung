# WP3 structure-v2 production observation is tree-only

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `67a0de6f` separates verified structure-v2 tree recovery from its legacy
diagnostic rendering. Both production consumers now request a tree-only
observation:

- the optional `structure-v2-shadow` logger operating on production v1's CFG;
  and
- the pipeline path that adapts a verified v2 tree for possible selection.

Those paths retain the same block, edge, loop, candidate, tree, refusal,
honest-goto, duplication, and verification evidence, but leave
`raw_pseudocode` and `prepared_pseudocode` empty. The selected region is still
lowered from value-numbered LLIR by the common production pipeline, where the
authoritative `ValueIdentities` sidecar is available.

The public shadow diagnostic observer continues to render both text views for
the existing review and fixture evidence. That compatibility surface is now
explicitly documented as non-production: `LlirFunction` plus `SsaInfo` carries
neither the calling convention nor enough information to construct the
pipeline's complete identity sidecar.

## Focused evidence

The new contract was first compiled before `observe_tree` existed and failed
with `E0425`, establishing that production had no tree-only API. After the
implementation:

```text
ir::structure_v2::tests:                                      30 passed, 0 failed
tree-only contract with structure-v2-shadow enabled:           1 passed, 0 failed
production_preparation_exposes_the_verified_clang_wide_switch: 1 passed, 0 failed
```

`uv run maturin develop` completed and `tools/build_guard.py` reported
`fresh`, with native SHA-256
`8b2b16c8b4b92fbb5a32a47a11c91fe3467e3c17c47fb9d898c43e9b5886ce51`.
The native build includes concurrent, unstaged shared-worktree changes outside
this increment, so it proves buildability of the live tree rather than an
exact-clean-checkout artifact for `67a0de6f`.

No fixture output is intended to change: this removes unused diagnostic work
from production selection rather than changing the selected tree or common
lowering. No test-census update is required because the new contract is a Rust
unit test. No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

Production structure-v2 selection no longer invokes identity-free AST
preparation as an observation side effect. The compatibility diagnostic
renderer and the general early no-sidecar copy/constant preparation entry
points remain to be classified separately. WP3 and `tag_phys` removal remain
incomplete.
