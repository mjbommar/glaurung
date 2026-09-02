# Mini-project 3: CFG and discovery decomposition

> **Kind:** record · **Date:** 2026-08-13

## Problem

`src/analysis/cfg.rs` is a large concentration point for graph representation,
function discovery, traversal algorithms, mutation, and validation. Those
responsibilities evolve at different rates and have different soundness
requirements. A graph algorithm should not decide whether missing bytes or an
unresolved indirect branch means analysis is complete.

## Target design

- `cfg/model.rs`: nodes, edges, terminators, stable identities, completeness.
- `cfg/builder.rs`: checked construction and mutation.
- `cfg/discovery.rs`: worklist and budget policy over `ProgramSession` images.
- `cfg/indirect.rs`: switch/table and unresolved-target evidence.
- `cfg/algorithms/`: dominance, SCCs, loops, reachability, post-dominance.
- `cfg/verify.rs`: structural invariants and source-edge accounting.
- `cfg/render.rs`: DOT/serialization views only.

Function-boundary discovery should be a sibling service that produces
provenance-bearing candidates; it must not silently mutate graph truth.

## Required contracts

- Every terminator has an explicit representation, including unknown and
  indirect transfers.
- Completeness distinguishes exhausted discovery, resource limits, unsupported
  semantics, unreadable bytes, and unresolved targets.
- Edge provenance identifies direct decode, relocation/debug evidence,
  recovered table, or heuristic candidate.
- Algorithms operate on immutable graph views and state their requirements.
- Structuring consumes a verified CFG and must account for every reachable
  edge, using explicit goto/unknown fallback when necessary.

## Phases

1. Characterize current construction and mutation call sites.
2. Introduce model and verification facades without behavior changes.
3. Extract pure graph algorithms and property-test them on real-derived graph
   fixtures plus small exhaustive graphs.
4. Extract discovery policy and make budgets/completeness part of its result.
5. Separate indirect-target evidence and function-candidate reconciliation.
6. Migrate structuring, xrefs, Python bindings, and execution consumers.

## Exit evidence

- No graph algorithm reads binary bytes or format parsers.
- No renderer or binding mutates a graph.
- Exact-edge fixture gates report zero invented or missing edges on their
  supported corpus; incomplete cases remain explicitly incomplete.
- Budget changes participate in session cache identity.
- `cfg.rs` is removed or reduced to a documented compatibility facade, then
  deleted after downstream migration.

## Stop conditions

Stop if an unknown edge becomes fallthrough, an indirect branch disappears,
function candidates are accepted without provenance, or graph validity is
inferred only from successful rendering.

