# Source ADR-001 — Depend on cindergraph from GitHub by Git revision; the embedded copy is deleted

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted and implemented 2026-09-17. First record of the
`source-` series: the C source-analysis stack had no decision series of its
own (the `exec-` and `solver-` series are the execution engine and the SMT
integration), and this decision is about a dependency boundary, not a solver.

**Context:** Glaurung's C source-analysis stack — the language-neutral parsing
substrate (`src/syntax/`), the tolerant C lexer/parser, CFG, dataflow, metrics,
graph export and the DecBench parity projection (`src/csource/` minus the
lowering and the solver-backed checks) — was extracted with history into the
standalone `cindergraph` crate at Glaurung `0892552` on 2026-09-14
(cindergraph's `EXTRACTION.md`; its `docs/architecture/glaurung.md` names the
boundary). From that day Glaurung carried a second copy: 54 files, 32,872
lines, 583 unit tests, and neither repository received the other's fixes.
Cindergraph's Milestone H and improvement-list item 10 both name the same exit:
Glaurung cannot silently compile a second implementation. The instruction was
verbatim: "glaurung needs to use the github dependency, not a copied / vendored
version of cinder". The sizing — both divergence lists and the plan — is
[`../development/cindergraph-migration-2026-09-17.md`](../development/cindergraph-migration-2026-09-17.md).

**Decision:**

1. *One dependency line, unconditional:*
   `cindergraph = { git = "https://github.com/mjbommar/cindergraph.git", rev = "ed5e55eb8fb7855b7675ac9ae3f7afbb4941a825" }`
   — the same form as the `axeyum-*` pins ([`solver-001`](solver-001-depend-on-axeyum-by-git-rev.md)):
   the GitHub URL and a full revision, never a `path` to a sibling checkout
   and never a branch. `ed5e55e` is cindergraph's `origin/main` on 2026-09-15
   ("Document design and evaluation references", the 0.1.0 release
   preparation). Unconditional because every consumer is: the
   `source_metrics` / `source_cfg` / `metrics` PyO3 modules build in the
   default `python-ext` wheel, `src/metrics/` is default, and
   `src/csource/lower/` is default. The crate is pure Rust with one
   dependency (`regex`, already here), MSRV 1.88, edition 2021.
2. *The embedded copy is deleted*, not shadowed: `src/syntax/` (23 files) and
   `src/csource/{cfg,dataflow,export.rs,lex,metrics,normalize.rs,parse,joern}`
   (31 files). `src/lib.rs` no longer declares `syntax`. `src/csource/` keeps
   exactly what the extraction excluded on purpose because it needs Glaurung's
   LLIR, symbolic engine or solver seam: `lower/` (S4, C → `LlirFunction`),
   `equiv/` (S5), `feasibility.rs` (S6).
3. *Every consumer imports the crate by name* — `cindergraph::parity`,
   `cindergraph::csource::{cfg,lex,parse,…}`, `cindergraph::syntax::…` — with
   no `pub use` re-export of the crate from `glaurung::csource` or a
   `glaurung::syntax` alias. A path that would only compile with the copy
   present is the drift this record exists to prevent, so
   `python/tests/test_src_dependency_boundaries.py` holds four checks with
   positive controls: the manifest pins by GitHub URL and 40-hex revision (a
   `path =` fails), `src/syntax/` is absent and `src/csource/` holds only the
   three kept modules (a new file beside them fails), no product file names
   `crate::syntax` or `crate::csource::{cfg,…,parity}` (one import fails),
   and `lower/` does not import `parity` (one import fails). Each was killed
   by exactly one mutant before landing.
4. *Tests moved with the code are deleted here by name.* Of the 583 embedded
   unit tests, 571 exist under the same name in cindergraph at `ed5e55e`
   (816 `#[test]` attributes under `crates/cindergraph/src` at that revision), two under a changed name, and ten do not
   exist there at all (below). The one that reads Glaurung's own corpus,
   `the_corpus_recovers_a_type_for_almost_every_binding`, is kept as
   `tests/source_dataflow_corpus.rs` over the crate; `tests/substrate_pipeline.rs`
   (the substrate composed end to end through a made-up language) and
   `tests/source_cfg_ged.rs` never moved and stay as integration tests of the
   dependency. Tests of the lowering and of Glaurung's consumers stay.

**The finding — four Glaurung-side parity corrections cindergraph does not have.**
After the extraction base, four commits on 2026-09-13 changed
`src/csource/joern/{chains,nodes}.rs` for DecBench parity, each measured over
the 85,645-cell oracle in
[`decbench-joern-replacement-2026-09-13`](../history/campaigns/decbench-joern-replacement-2026-09-13/README.md):
`828a41a9` (deduplicate parallel edges before `parity_chains` reads degree),
`0266715f` (drop the impossible false exit of a constant-true loop, keeping its
header), `68b39f18` (elide a bare literal `if` test, keep its fork),
`f9a5cbaa` (collapse the duplicate loop header around a ternary loop test).
None is in cindergraph at `ed5e55e` or in its 19 unpushed commits, and the
constant-loop rule *conflicts* with cindergraph's own `elide_empty_for_headers`
on `for (;;)` (cindergraph deletes the header as Joern does; Glaurung kept it).
They live in `expression_granular`'s private `Work` state and inside `elide`'s
ordering, which the crate does not expose; a faithful shim over the crate's
output is not possible, and reproducing them would mean copying `Work`,
`parity_chains` and `parity_of` under another name — the re-vendoring this
record ends. So the decision is to take the crate's parity projection as it
is, and to port the four corrections upstream as one unit, reconciling the
`for (;;)` rule by hand. Until that lands and Glaurung re-pins, Glaurung's
parity projection differs from `af9f826d`'s on exactly those four shapes. The
ten tests to carry across:

| file (at `af9f826d`) | test |
|---|---|
| `src/csource/joern/chains.rs` | `parallel_empty_branch_edges_are_deduplicated_before_coalescing` |
| `src/csource/joern/nodes.rs` | `constant_true_loop_loses_only_its_impossible_false_exit` |
| | `constant_false_and_unknown_loops_keep_their_false_exits` |
| | `constant_true_empty_loop_keeps_its_cycle` |
| | `nested_literal_if_tests_cost_no_nodes_but_keep_their_forks` |
| | `a_variable_if_test_still_materializes` |
| | `value_only_ternary_in_a_loop_condition_has_one_final_branch` |
| | `a_side_effecting_ternary_arm_keeps_the_expression_but_not_the_duplicate_header` |
| | `ternary_loop_cast_compare_and_load_variants_keep_their_expression_nodes` |
| | `a_ternary_at_the_start_of_a_loop_body_is_not_a_loop_test` |

**Consequences:**

- Glaurung receives cindergraph fixes by bumping `rev`, the way it receives
  Axeyum's; the crate at `ed5e55e` already carries repairs the copy never had
  (call-site-sensitive interprocedural flow, pointer-store dependence with
  weak updates, interned unresolved identities, the `recovery_free` /
  `memory_complete` signals, the conditional-comma parity fix, legacy-C
  recovery). Their effect on Glaurung's own tests is in the verification
  section.
- The Python facades `python/glaurung/source.py` and `source_cfg.py` keep
  their surface over Glaurung's `_native` bindings, which now call the crate.
  Cindergraph ships its own Python package (`cindergraph`, PyO3 0.29,
  abi3-py312) with the same functions. The facades should eventually
  *delegate* to it rather than be retired — Glaurung's KB, CLI and agent tools
  import `glaurung.source`, and a delegating facade keeps that import stable
  while the bindings shrink — but that is a second change with its own
  measurement (two extension modules in one wheel, one PyO3 version each) and
  is not made here.
- Nothing here waits on cindergraph's unpushed 19 commits (`repr="ops"`, loop
  metadata, the external-facts contract, export attributes, `__version__`);
  they are additions. Improvement-list item 10's *pipeline* (decompiled C →
  cindergraph → Axeyum) does want `ops` and the resolved types, so the next
  re-pin should follow their push.
- `tests/substrate_pipeline.rs` and `tests/source_cfg_ged.rs` test the crate,
  not Glaurung; they belong upstream and should move with the parity port.

**Verification** (branch `gl-cinder-2026-09-17`; the full record with every
name is the migration note's verification section):

- `cargo test --features solver-axeyum --no-fail-fast`: `master` lists 5,283
  tests over 36 binaries; the branch runs 4,701 over 37 — **4,682 passed /
  1 failed / 18 ignored**. 5,283 − 583 (moved to cindergraph, one of them
  `#[ignore]`) + 1 (the corpus gate kept as an integration test) = 4,701; the
  one failure is `master`'s pre-existing `ir::ast` decompiler test.
- The parity projection, measured directly since no in-repo fixture pins it:
  930 functions over the in-repo C corpora, `master`'s extension against the
  branch's — 42 differ, all with the crate smaller (41 short-circuit loop
  headers the crate elides, one computed-`goto` dispatch it models as a
  fan-out); none of the four missing Glaurung corrections fires on this
  corpus. `tools/source_cfg_projection_dump.py` repeats it.
- `scripts/feature-build-gate.sh`: every lane `cargo check --all-targets`,
  re-run per lane with `--keep-going`; the only errors are the two
  pre-existing `recover_types` E0425s in `benches/ir_dataflow.rs`, on
  `master` too. The fuzz crate checks clean (its lockfile gains the crate).
- `cargo fmt --all -- --check` clean; clippy and rustdoc show nothing new in
  a touched file.
- Python: `-k axeyum` 55 passed; `-k "source or metrics or cfg"` 466 passed,
  753 skipped, 36 failing instances over 10 ids, of which 8 ids fail
  identically on `master` and 2 need the gitignored fixture corpus (they pass
  with it copied in). One public Python behaviour changed and is pinned by a
  regression test: `data_flow` lists unresolved names as typeless bindings
  and now also returns `unresolved_bindings`.

**Alternatives rejected:**

- *A `path` dependency on the sibling checkout* (the co-development form
  `solver-001` used first): resolves to whatever the local checkout holds —
  here 19 commits ahead of GitHub — so two machines build two crates, which is
  the copy problem in a new place.
- *Keeping `glaurung::syntax` / `glaurung::csource::parse` as re-exports of
  the crate*: compiles the same code, but keeps every old path alive, so a
  re-vendored file could be dropped back in without a consumer changing.
- *A local parity shim carrying the four corrections*: measured above as a
  ~700-line copy of private internals under another name; and the `for (;;)`
  rule needs a decision, not a merge.
- *The crates.io release*: cindergraph 0.1.0 is prepared but the registry
  identity is not yet verified; Milestone H step 5 moves to it once it is.

---

Part of the source-analysis decision series; the index is
[`docs/decisions/README.md`](README.md). The migration note is
[`../development/cindergraph-migration-2026-09-17.md`](../development/cindergraph-migration-2026-09-17.md)
and the kept modules are described in `src/csource/mod.rs`.
