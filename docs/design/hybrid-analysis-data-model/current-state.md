# Hybrid analysis current state

> **Kind:** design · **Status:** maintained · checkpoint of 2026-09-17

This checkpoint records what the first accumulated hybrid/runtime tranche
actually proves. The objective ladder remains authoritative: representative
vertical slices are progress, not programme completion.

## What now works

- The 60-program, 120-scenario corpus has typed semantic oracles and a
  deterministic build/run/capture ledger.
- Owned-child live capture and Linux x86-64 ELF-core import produce the same
  provider-neutral process-capsule model with explicit missing evidence.
- Runtime modules, mappings, PCs, instructions, LLIR blocks, operations,
  expressions, and semantic values use explicit static/runtime relations rather
  than address comments or mutation of decompiler state.
- Crash, object-change, descriptor/file/process/mapping behavior, bounded
  instruction traces, input provenance, replay, and counterfactual validation
  have real representative fixture lanes.
- SAT/SMT decisions use the in-process native Axeyum backend. Process/pipe and
  SMT-LIB solver transport is confined to an explicit comparison feature.
- Static operation identity is generation-scoped and occurrence identity is
  capture/process/thread/event-scoped. Concrete values remain on occurrences.
- DWARF variable/type nodes use exact-image debug-info offsets. Recovered ABI
  parameters and unambiguous frame locals use storage-derived variable
  identities rather than rendered names.
- Structurally recovered parameter hints now produce immutable recovered type
  nodes. Their identities use the exact image, semantic shape, target width,
  and recovery profile; C spelling is presentation only.

## What remains deliberately incomplete

- Recovered stack-local type text does not mint a type identity. The current
  facts lack a structural type provenance equivalent to parameter `TypeHint` or
  a DWARF DIE.
- High variables are not yet live-range/cover aware, and bindings do not yet
  connect all recovered variables to all relevant semantic values.
- AST-origin identity and token-to-expression-to-operation navigation are not
  complete, so Objective 4's end-to-end semantic crash explanation remains
  open.
- Live/core equivalence, silent-corruption classification, OS behavior, and
  persistence have strong representative slices but not complete corpus-wide
  coverage.
- Multi-process/thread causality, a second architecture/provider, hostile-input
  hardening, numeric performance budgets, and blinded real-world closure remain
  later objectives.

## Architectural boundary retained

The decompiler owns immutable static meaning. Runtime analysis owns captured
state, event order, object lifetimes, completeness, and concrete values. The
shared semantic kernel owns stable target, storage, type, value, expression,
operation, identity, and provenance vocabulary. Evidence-bearing relations
join the worlds; neither world is copied into the other.

Missing or ambiguous evidence fails closed. In particular, the implementation
does not derive identity from rendered names, C-like type strings, PIDs, raw
runtime addresses, or fixture labels.

## Validation boundary

The pre-commit shared worktree was checked as follows:

- `cargo test --features python-ext` passed the 5,122-test library inventory and
  every ordinary integration group. Its two final doctests hit `E0460` because
  the shared `target/` contained two concurrent PyO3 builds. Re-running
  `cargo test --features python-ext --doc` with an isolated
  `CARGO_TARGET_DIR` passed both doctests (one declared ignore).
- The focused Rust variable/identity tests passed: seven recovered-variable
  tests and the canonical function/block/operation identity test.
- The compact Python hybrid gate covering `test_ir.py`, runtime Axeyum profile
  reporting, solver-authority documentation, tool routing, corrected core/file/
  process evidence cases, and the real under-allocation/stale-pointer matrices
  passed with seven declared missing-PE/PDB fixture skips.
- `ruff check python/` passed.
- `ty check python/` remains repository-red with 410 diagnostics spanning
  existing CLI, LLM, optional-dependency, and test typing. This is not a clean
  type-gate claim.
- A full `pytest python/tests/` run was stopped after 16 minutes once it was
  conclusively red: 1,397 tests had passed and 35 had failed, all in decompiler
  architecture/curriculum/dialect/def-use/fixture tests in the concurrently
  edited worktree. The focused hybrid/runtime gate above is green; the full
  Python gate is not.

These results distinguish the validated runtime/hybrid increment from the
state of unrelated concurrent decompiler work. A focused pass is not a full-
suite claim.
