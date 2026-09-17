# Cindergraph migration, 2026-09-17

> **Kind:** record · **Date:** 2026-09-17 · **Status:** in progress (sizing
> committed first; the switch follows on the same branch)

Cindergraph's Milestone H ("Glaurung migration", its `docs/ROADMAP.md` §12)
and item 10 of [`improvement-list-2026-09-16.md`](improvement-list-2026-09-16.md):
Glaurung stops compiling its own copy of the C source-analysis stack and
depends on the crate at
`https://github.com/mjbommar/cindergraph.git`. The instruction, verbatim:
"glaurung needs to use the github dependency, not a copied / vendored version
of cinder".

This note is the sizing: what each side changed since the extraction, what
the switch touches, and what cannot be kept without a change in cindergraph.
The decision record is
[`source-001`](../decisions/source-001-depend-on-cindergraph-by-git-rev.md).

## The two trees

| | revision | date |
|---|---|---|
| extraction base (Glaurung) | `0892552157be6bd9267007231419ff6606a2dd38` | 2026-09-13 |
| extraction commit (cindergraph) | `ec47556c7c8e6bdbf465432cdd0a4e5ea71add96` "extract Cindergraph as standalone Rust and Python package"; its parent `1bd10ee` is the filtered image of `0892552` | 2026-09-14 |
| Glaurung `master` before this lane | `af9f826d` | 2026-09-17 |
| cindergraph on GitHub (`origin/main`), the pin | `ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825` "Document design and evaluation references" | 2026-09-15 |
| cindergraph local `main`, **not on GitHub** | `de1865c`, 19 commits past `ed5e55e` (`repr="ops"`, loop metadata, the external-facts contract, the export schema attributes, `__version__`) | 2026-09-16/17 |

Glaurung depends on what is on GitHub, so the pin is `ed5e55e`. Nothing in
this migration needs the unpushed 19; they are additions (new exports, new
attributes), not changes to the surface Glaurung consumes.

## What is being replaced

Glaurung's embedded copy, measured at `af9f826d`:

| set | files | lines | `#[test]`s | fate |
|---|---|---|---|---|
| `src/syntax/` | 23 | 12,549 | 222 | deleted; `cindergraph::syntax` |
| `src/csource/` minus `lower/`, `equiv/`, `feasibility.rs` | 32 | 20,323 | 361 | deleted; `cindergraph::csource` (`joern` is `parity` there) |
| `src/csource/lower/` (C → LLIR) | 13 | 6,429 | 87 | stays; imports the crate's parse/AST types |
| `src/csource/equiv/` + `feasibility.rs` (solver-backed, `symbolic` feature) | 8 | 3,649 | 41 | stays; EXTRACTION.md excludes them deliberately |

55 files and 32,872 lines go; 583 embedded unit tests go with them. Of those
583 test names, 571 exist under the same name in cindergraph at `ed5e55e`
(which has 816 unit tests in the crate), two exist under a changed name
(`a_struct_body_is_one_opaque_node_and_declares_no_locals` was rewritten when
struct bodies started parsing members; `the_corpus_recovers_a_type_for_almost_every_binding`
is `..._declared_binding`, and it reads Glaurung's own
`tests/decompiler_fixtures/src`, so it is kept here as an integration test over
the crate), and **ten do not exist in cindergraph at all** — the four
Glaurung-side parity corrections below.

## List 1: what Glaurung changed since the extraction base

`git log 0892552..af9f826d -- src/csource src/syntax`: five commits.

| commit | date | change | in cindergraph `ed5e55e`? | in the unpushed 19? |
|---|---|---|---|---|
| `828a41a9` | 09-13 | `joern/chains.rs`: deduplicate parallel edges (an empty `if` arm's true and false edges to one continuation) **before** reading degree in `parity_chains`, as pyjoern's `nx.DiGraph` does; test `parallel_empty_branch_edges_are_deduplicated_before_coalescing` | **no** | **no** |
| `0266715f` | 09-13 | `joern/nodes.rs`: remove the impossible false exit of a syntactically constant-true loop (`while (1)`, `do … while (1)`, `for (;;)`), keeping the header and its cycle; `GranularityStats::constant_loop_exits_elided`; 3 tests | **no** — and it **conflicts**: cindergraph's `elide_empty_for_headers` (in `47f9e35`) deletes the `for (;;)` header outright, as Joern does; Glaurung keeps it ("Joern incorrectly erases a truly infinite loop") | no |
| `68b39f18` | 09-13 | `joern/nodes.rs`: a bare literal `if` test (`if (0)`, `if (1)`) is elided while its fork is kept; `literal_if_tests_elided`; 2 tests | **no** | no |
| `f9a5cbaa` | 09-13 | `joern/nodes.rs`: collapse the duplicate loop header around a ternary in a loop test (`while (i < (x ? 14 : 8))`), inside `elide` before operand elision; `ternary_loop_branches_collapsed`; 4 tests | **no** — cindergraph's `elide_redundant_loop_headers` handles the *short-circuit* loop-test case, not the ternary one | no |
| `761f48a8` | 09-14 | formatting only (`rustfmt`), plus one `use` removed from `src/lib.rs` | n/a (cindergraph rustfmt'd at extraction) | n/a |

The four corrections are DecBench parity work: the campaign record at
[`docs/history/campaigns/decbench-joern-replacement-2026-09-13/`](../history/campaigns/decbench-joern-replacement-2026-09-13/README.md)
pins them as four extension builds ("parallel-edge", "constant-loop",
"literal-`if`", "ternary-loop" corrections) measured over the 85,645-cell
oracle. They all live inside `expression_granular`'s private `Work` state and
`parity_chains`, which the crate does not expose. **A faithful local shim is
not possible**: two of the four run interleaved with region elision (the
ternary collapse must precede operand elision; the constant-loop rule reads
edge kinds `Work` still has), and the third conflicts with a decision
cindergraph took for the same shape. Reproducing them over the crate's output
would mean copying `Work`, `parity_chains` and `parity_of` (~700 lines) under
another name, which is the re-vendoring this migration exists to end.

**Finding:** the four corrections need porting to cindergraph (its
`csource/parity/{chains,nodes}.rs`), with the `for (;;)` rule reconciled
against `elide_empty_for_headers` by a human. Until that lands and Glaurung
re-pins, Glaurung's parity projection at the crate differs from `af9f826d`'s
on exactly those four shapes. The ten tests that pin them are listed in the
decision record so the port can carry them across.

## List 2: what cindergraph changed that Glaurung's consumers see

`git log ec47556..ed5e55e -- crates/cindergraph/src`: nine commits. Against the
consumer surface Glaurung imports (`grep -rln 'crate::csource\|crate::syntax' src`
minus the embedded files themselves), a `pub` signature diff of the two trees
shows **nine removals and ninety-seven additions**; the removals are:

| removed / changed | consumer effect |
|---|---|
| `csource::joern` is `csource::parity` (extraction commit) | `source_cfg.rs`, `metrics/tree_distance.rs`, doc links in `python_bindings/metrics.rs`: rename the path |
| `csource::metrics::size::parameters(&Tokens, Option<(u32,u32)>)` removed (`47f9e35`) | no Glaurung consumer calls it |
| `GranularityStats::{constant_loop_exits_elided, literal_if_tests_elided, ternary_loop_branches_collapsed}` absent (never ported) | only the deleted parity tests read them |
| `dataflow` and `syntax::cfg` re-export lists reformatted to multi-line | none (same names) |
| `csource::{equiv, feasibility, lower}` absent | stay in Glaurung's `src/csource/` |

Everything else is additive: `csource::semantic` (`AnalysisUnit`,
`FunctionId`, `AnalysisOptions`, `ANALYSIS_REVISION = 5`),
`csource::eval` (`csource::facts` is in the unpushed 19, not at the pin), `dataflow::{analyze_unit,
summarize_with_policy, reaches_detailed, ExternalCallPolicy, Reachability,
memory regions/accesses/definitions}`, `export::export_unit`,
`cfg::dispatch` and `IndirectDispatchInfo`, `syntax::scan::{ident, literal,
number, trivia}` split out of `scan/mod.rs`. The crate also carries fixes
Glaurung's copy never had: call-site-sensitive interprocedural flow, pointer-
store dependence with weak updates, interned unresolved identities, the
`recovery_free` / `memory_complete` signals, the conditional-comma parity fix
(`280e35a`), legacy-C recovery (`d11278a`). Glaurung's consumers get all of
these through the dependency; their behavioural effect on Glaurung's own tests
is what step 3 measures.

Struct/enum fields consumers destructure (`FunctionMetrics`, `SourceReport`,
`DataFlow`, `Summary`, `FunctionDef`, `Tree`) are checked by the compiler in
the switch, not by this diff.

## The plan

1. `Cargo.toml`: `cindergraph = { git = "https://github.com/mjbommar/cindergraph.git", rev = "ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825" }`,
   unconditional. The embedded modules were unconditional (`pub mod syntax;
   pub mod csource;` in `src/lib.rs` under every feature set; `source_metrics`
   and `source_cfg` bindings are in the default `python-ext` build), so the
   dependency is too. The crate has one dependency (`regex`, already here), no
   C, MSRV 1.88, edition 2021 — the same floor.
2. `src/lib.rs`: drop `pub mod syntax`; keep `pub mod csource` as the home of
   `lower`, `equiv`, `feasibility`, and re-export the crate's modules from it
   (`pub use cindergraph::csource::{cfg, dataflow, export, lex, metrics,
   normalize, parse}; pub use cindergraph::parity;`) so `glaurung::csource::…`
   stays a working path and there is exactly one implementation behind it.
   `glaurung::syntax` is `pub use cindergraph::syntax;` for the same reason
   (`tests/source_cfg_ged.rs` and the benches import it).
3. Re-point the seven consumers and `lower/*`, `equiv/*`, `feasibility.rs`;
   delete the 55 files; keep the corpus dataflow test as an integration test.
4. Measure: the full `--features` test sweep against 5,263 / 1 / 19, every
   difference by name; the parity-covering tests; every configuration in
   `scripts/feature-build-gate.sh`; `cargo fmt --all -- --check`; the Python
   `source`/`metrics`/`cfg` and `axeyum` selections.
5. Record: `source-001` in `docs/decisions/`, item 10's row in the improvement
   list, this note in `docs/architecture/README.md`.

The Python facades (`python/glaurung/source.py`, `source_cfg.py`) keep their
surface over Glaurung's own `_native` bindings, which now call the crate;
whether they should delegate to the `cindergraph` Python package is answered in
the decision record and not acted on here.
