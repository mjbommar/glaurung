# Cindergraph migration, 2026-09-17

> **Kind:** record · **Date:** 2026-09-17 · **Status:** done on branch
> `gl-cinder-2026-09-17` (sizing, then the switch, then the measurement below)

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

Glaurung depends on what is on GitHub, so the first pin was `ed5e55e`.
Nothing in this migration needed the then-unpushed 19; they were additions
(new exports, new attributes), not changes to the surface Glaurung consumes.
**Nothing waits now:** cindergraph's `main` was pushed at `8bd2051` (27
commits past `ed5e55e`, the 19 plus the parity port of List 1's four
corrections) and Glaurung re-pinned to it the same day; the measurement is
the [re-pin section](#re-pin-to-8bd2051-2026-09-17) at the end of this note.

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
(which has 816 `#[test]` attributes under `crates/cindergraph/src`), two exist under a changed name
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
decision record so the port can carry them across. *(Closed the same day:
ported as cindergraph `3461022`, `657aed4`, `339e19b`, `5c21383` with the ten
tests and a mutation control each, on GitHub in `8bd2051`; the `for (;;)`
rule was decided by the recorded Joern data — see the re-pin section.)*

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

## Verification

Branch `gl-cinder-2026-09-17`; the base is `master` at `af9f826d`. Every
cargo command ran through `cargo-serialized.sh`.

**The Rust sweep, `cargo test --features solver-axeyum --no-fail-fast`.**
The base lists 5,283 tests over 36 binaries (`-- --list` from a detached
worktree at `af9f826d`; the 5,263 / 1 / 19 of `solver-036` plus the five
item-4 tests, all accounted for by name). The branch runs 4,701 over 37
binaries: **4,681 passed / 2 failed / 18 ignored** on the first run, then
the corpus test was restated (below) and passes, so the standing figure is
**4,682 / 1 / 18**. Every difference by name:

| difference | count | what |
|---|---|---|
| gone, `csource::{cfg,dataflow,export,joern,lex,metrics,normalize,parse}::*` and `syntax::*` unit tests | 583 | moved to cindergraph — 571 under the same name, `a_struct_body_is_one_opaque_node_and_declares_no_locals` and `the_corpus_recovers_a_type_for_almost_every_binding` under changed names, and the ten parity tests of List 1 nowhere (the finding) |
| of those, ignored | 1 | `csource::normalize::sanitize_decompiled_c_matches_python_reference_on_real_files` (`#[ignore]`), which is why 19 ignored became 18 |
| new, `tests/source_dataflow_corpus.rs::the_corpus_recovers_a_type_for_almost_every_binding` | 1 | the corpus gate kept over the crate. It failed on the first run at 86.4 % because the crate interns unresolved identities (macro constants used as array bounds: `LCS_MAX`, `GAUSS_DIM`, … — 568 of 4,170 bindings) as bindings with an empty type, which the copy dropped; restated over *declared* bindings it is 100.0 %, and the one unused value binding (`sizeof_array_versus_pointer:pointer`, read only by `sizeof`) is pinned by name, the same pin cindergraph's own copy of the gate carries |
| the one pre-existing failure | 1 | `ir::ast::tests::an_in_place_update_of_a_coalesced_slot_is_an_assignment_not_a_pointer_store`, failing on `master` before this lane |
| doc-tests `identity::cfr (line 49)`, `identity::values (line 59)` | 0 | listed without and run with a `- compile` suffix; the same two tests |

5,283 − 583 + 1 = 4,701. Nothing else moved: the lowering's 87 tests, the
solver-backed 41, the bindings' and `src/metrics`' tests all pass unchanged.
Master's build printed 261 warnings, the branch 259; the two fewer lived in
the deleted files, and the one in a touched file (`unused import: super::*`,
`src/csource/lower/mod.rs:142`) is on `master` too.

**The parity projection.** No in-repo fixture pins its bytes: the ten unit
tests that did are the ones cindergraph lacks, `tests/source_cfg_ged.rs`
skips without `GLAURUNG_DECBENCH_TREE` (the corpus is not on this host),
and `python/tests/test_source_cfg_provider.py` checks shape, determinism and
the two flags, not the graphs. So the bytes were measured directly:
`glaurung._native.csource.parity_cfgs` over every function in
`tests/decbench_corpus/src`, `tests/decompiler_fixtures/src` and
`tests/decompiler_output_canaries` — 930 functions — under `master`'s
extension (the copy) and this branch's (the crate). Same 930 names on both
sides; **42 functions differ**, and in every one the crate's graph is the
smaller. 41 are short-circuit loop tests (`while (*a && *a == *b)`,
`for (…; guard < 64 && right != 0; …)`): one node and two edges fewer per
such loop (36 functions at −1/−2, three at −2/−4, `big151_branch_ladder` at
−26/−52, `wide154_dense_effects` at −41/−82), which is cindergraph's
`elide_redundant_loop_headers` (its `280e35a`/`47f9e35`; Joern has no
structural header there), a fix the copy never had. The 42nd,
`103_computed_goto.c::threaded_interpreter` (16 → 14 nodes, 22 → 20 edges),
is the crate's computed-`goto` dispatch modelled as one fan-out node
(`cfg/dispatch.rs`, `IndirectDispatchInfo`) where the copy emitted a chain of
binary forks — a general-CFG change, not a parity rule. None of the 42 goes
the other way, so none of the four missing Glaurung corrections fires on this
corpus; their effect is on the DecBench shapes the campaign measured, which is
why the port is still owed. The dump-and-diff is
`tools/source_cfg_projection_dump.py`, so the comparison repeats with any two
builds of the extension.

**Every feature configuration.** `scripts/feature-build-gate.sh` reports
FAILED on all eleven cargo lanes and ok on the fuzz crate, exactly as on
`master`: the only errors, confirmed with `cargo check --all-targets
--keep-going` per lane so the bench cannot mask another target, are the two
`recover_types` E0425s in `benches/ir_dataflow.rs` (pre-existing, unrelated).
`cargo fmt --all -- --check` is clean. `cargo clippy --lib --tests
--features solver-axeyum` shows no new warning in any touched file.

**Python.** The extension built with `--release --features python-ext,symbolic`
(a `solver-axeyum` build fails to `dlopen` on this host with "cannot allocate
memory in static TLS block" — 6,928 bytes of static TLS against `master`'s
1,080; `master`'s installed extension has no `axeyum_solver` symbols either,
so this is the solver feature, not the migration, and
`GLIBC_TUNABLES=glibc.rtld.optional_static_tls=1048576` loads it).
`uv run pytest python/tests -k axeyum`: 55 passed.
`uv run pytest python/tests -k "source or metrics or cfg"` (temp files on the
idle disk — on `/data0` at 92 % utilisation the SQLite lock test sat in
`jbd2_log_wait_commit` for 56 minutes with 11 s of CPU): **466 passed, 753
skipped, 25 failed, 11 errors** across 10 test ids. Eight of the ten ids fail
identically on `master` with its own extension (`test_build_configuration_invariants`,
`test_cli_annotate`, `test_decompiler_emission_invariants`,
`test_decompiler_fixture_structural`, `test_gen_pass_reference`; run as one
selection there, same 34 instances). The other two need the gitignored
`tests/decompiler_fixtures/build/` corpus, which a fresh worktree lacks; with
`master`'s 1,676 built files copied in, both pass. The first run of this
selection had one more branch-only failure,
`test_source_dataflow.py::test_the_corpus_types_every_binding_and_declares_nothing_it_does_not_use`
— the Python twin of the corpus gate, failing for the same reason (568
unresolved bindings now carry `type` None). That is the **one public Python
behaviour the crate changed**: `glaurung.source.data_flow` now lists a name it
could not tie to a declaration in `bindings`. It is kept and documented rather
than hidden: the binding exposes the crate's `unresolved_bindings` index list
beside `unused_bindings`, the facade docstring says so, the corpus gate is
restated over declared bindings with the one unused value binding pinned by
name, and `test_an_unresolved_name_is_a_typeless_binding_that_is_listed_as_such`
pins the behaviour on a two-line input. `test_native_stub_current.py` passes
(the `_native` stubs are unchanged, so the surface is the same set of
functions).
`python/tests/test_src_dependency_boundaries.py`: the four new guards pass and
each was killed by exactly one mutant; `test_every_env_var_read_in_src_is_a_reviewed_allowlist_entry`
fails on `master` too (three env reads other lanes added on 2026-09-17:
`TRACE_GIT_REV_ENV`, `CANONICAL_CACHE_ENV`, `MODEL_PREFERENCE_ENV`).

**Did not run:** the DecBench corpus runs (`tests/source_cfg_ged.rs` over
`GLAURUNG_DECBENCH_TREE`, `tools/decbench_matrix.py`, the parity aggregate)
— the corpus and the DecBench fork are not on this host; the `python-ext`
wheel with `solver-axeyum` under pytest (the TLS trap above); the full
`python/tests` suite (only the two selections above). `cargo doc --no-deps --features solver-axeyum` ran: 162 warnings, none naming a `cindergraph::` path (`master`'s count was not measured).


## Re-pin to `8bd2051`, 2026-09-17

Branch `gl-cinder2-2026-09-17` on `master` at `2f1e5493`. cindergraph's
`main` was pushed at `8bd20512158d19d4cf632caba4bbed629271a3e5`, 27 commits
past `ed5e55e`: the 19 that were unpushed above (`repr="ops"`, loop metadata,
the single-parse session, the external-facts contract, the export attributes
`op`/`type`/`line`/`column`/declarator/parameter, `expr_internal` CFG marks,
`__version__`, path-argument errors, a defect conformance corpus) plus the
port of List 1's four corrections (`3461022` dedup, `657aed4` constant-true
loop, `339e19b` literal `if`, `5c21383` ternary loop test, sized and measured
in cindergraph's `docs/benchmarks/glaurung-parity-corrections-2026-09-17.md`).
The `for (;;)` conflict was decided there by the recorded Joern data:
`elide_empty_for_headers` stays for the clause-less `for` and the ported
constant-true rule fires only on a literal condition, so the two never both
fire; the stated residual is `while (1) {}` (a header with a self-cycle)
against `for (;;) {}` (one node). Nothing now waits on an unpushed commit.

`Cargo.toml` moves the one line to the new revision; `cargo update -p
cindergraph` follows in both `Cargo.lock` and `fuzz/Cargo.lock`.

**No consumer changed.** `cargo check --all-targets --keep-going` in every
lane `scripts/feature-build-gate.sh` lists (the ten cargo lanes plus
`--all-features`, `solver-z3` type-checked against the linked libz3 and
`solver-bitwuzla` under `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1`) reports only
the two pre-existing `recover_types` E0425s in `benches/ir_dataflow.rs`; the
fuzz crate checks clean. The gate script itself prints FAILED on the eleven
cargo lanes and ok on the fuzz crate, exactly the `master` state. The only
change to a type Glaurung consumes is additive:
`cindergraph::csource::cfg::FunctionCfg` gains `expression_internal:
Vec<NodeId>`, and no `.rs` file in this repository names that struct. `cargo fmt --all --
--check` is clean.

**The Rust sweep, `cargo test --features solver-axeyum --no-fail-fast`:**
4,701 tests over 37 binaries, **4,682 passed / 1 failed / 18 ignored** — the
same figure as the migration, and the same set by name: the one failure is
`ir::ast::tests::an_in_place_update_of_a_coalesced_slot_is_an_assignment_not_a_pointer_store`
(on `master` before the migration), and the 18 ignored are the migration's
18. The corpus gate `tests/source_dataflow_corpus.rs` passes at the new pin.

**The parity projection.** `tools/source_cfg_projection_dump.py` over the
same 930 functions, the extension built at `ed5e55e` (this branch's tree
before the re-pin) against the extension built at `8bd2051`, both
`--release --features python-ext,symbolic`:
`before 930  after 930  only-before 0  only-after 0  changed 0`, and the two
dumps have the same SHA-256
(`958fcd26f1e9e63d1e7a02be2e8aa6fa7ba2f1dd836bd3be9318ac80eb5ae573`). So the
expected count is the measured one: none of the four corrections fires on the
in-repo corpora, and none of the other 23 commits moves the projection either.
That a zero is not a stale binary is checked two ways: the rebuilt `.so`
differs in size and mtime, and the four corrections fire on their own inputs
through the new extension's `parity_cfgs` — `if (x) {} return x;` is 1 node /
0 edges (2 / 1 at `ed5e55e` per cindergraph's sizing table),
`while (1) { if (x) break; x--; }` 4 / 4 (was 5 / 6),
`if (1) { if (0) g(); } h();` 3 / 3 (was 4 / 5),
`while (i < (x ? 14 : 8)) i++;` 4 / 4 (was 5 / 6), with the residual pair
`while (1) {}` 2 nodes and `for (;;) {}` 1 node as upstream states. The
corpus itself confirms the attribution: no `while (<literal>)` or
`do … while (<literal>)` outside comments, two `for (;;)` (excluded from the
ported detector by construction), no literal `if`, and one ternary in a `for`
*init* clause (`111_self_referential_struct.c`, the rule's negative fixture),
so only the dedup rule could have fired on a shape grep cannot see, and the
diff says it did not. This matches cindergraph's own measurement of the port
(byte-identical over its 930-function copy of the same fixtures).

**Python** (extension as above; `TMPDIR` on tmpfs — the first attempt with
temp files on `/data0`, busy with other lanes at ~300 ms await, sat in
`folio_wait_bit_common` at 68 % for ten minutes, the same trap as the
migration's SQLite lock test, and was killed):
`-k axeyum` **55 passed**; `python/tests/test_src_dependency_boundaries.py`
**11 passed** (the four no-drift-back guards accept the new 40-hex revision;
`test_every_env_var_read_in_src_is_a_reviewed_allowlist_entry` is green
since `2f1e5493`); `-k "source or metrics or cfg"` **501 passed, 753 skipped, 5 failed**
(the migration measured 466 / 753 / 36 failing instances over 10 ids).
Every difference by name: **one failure was the re-pin** —
`test_source_graph.py::test_the_choice_lists_come_from_rust` pins the
`EXPORT_REPRS` set literally and cindergraph now serves `ops`; the pin gains
`"ops"`, and `test_every_representation_and_format_produces_a_named_graph`
now also runs `ops` through the facade in all four formats (+4 instances,
passing). The 5 remaining instances are the migration's: 3 of
`test_decompiler_entrypoint_equivalence` and 1 of `test_decompile_vas_sources`
need the gitignored `tests/decompiler_fixtures/build/` corpus, and
`test_gen_pass_reference` fails on `master` at `2f1e5493` too
(`docs/reference/decompiler-passes.md is stale`, no cindergraph path). The
other 31 instances over seven ids the migration counted as "failing
identically on `master`" (`test_build_configuration_invariants`,
`test_cli_annotate`, `test_decompiler_emission_invariants`,
`test_decompiler_fixture_structural`) all died there on
`FileNotFoundError: 'glaurung'` — the console script was not installed in
that lane's venv — and pass here, where `.venv/bin/glaurung` exists; they
were never a product failure on either side.

**Did not run:** the same as the migration — the DecBench corpus runs
(`tests/source_cfg_ged.rs` over `GLAURUNG_DECBENCH_TREE`,
`tools/decbench_matrix.py`, the parity aggregate; the corpus and the DecBench
fork are not on this host), the `solver-axeyum` wheel under pytest (the
static-TLS trap), the full `python/tests` suite (only the three selections
above), and clippy / rustdoc (no Rust source changed, only the manifest and
lockfiles).

**Delegating `python/glaurung/source.py` to the `cindergraph` package.** It
is now possible for most of the facade and still not made: 16 of
`glaurung.source`'s 18 module-level functions have a same-named counterpart in
`cindergraph.source` at `8bd2051` (which also adds `native_graphs`,
`query_reaches`, `query_reaches_by_id`), but `path_feasibility` and
`source_findings` do not — they are Glaurung's solver-backed
`src/csource/feasibility.rs`, deliberately outside the crate — so a delegating
facade would be two extension modules in one wheel (PyO3 0.29 abi3-py312
against Glaurung's 0.26) with two functions kept native. That is the second
change with its own measurement the decision record names, and this re-pin
does not make it.
