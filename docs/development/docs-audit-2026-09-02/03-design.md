# Audit — `docs/design/*.md` (top level only; `execution-engine/` and `roundtrip/` excluded)

Auditor scope: the 48 markdown files directly inside `docs/design/`, 38,318 lines.
Repo state: `master` @ `b8884687`, 2026-09-02. All verification done read-only against
code, git, and JSON baselines. No builds, no pytest.

---

## Executive summary (read this first)

1. **This directory is 90% engineering record and 10% live guidance.** Of 48 files, 3
   are genuinely live (`README.md`, `decompiler-roadmap.md`, `decompiler-ux-competitive-ranking.md`),
   ~6 carry live architectural knowledge that exists nowhere else, and ~39 are dated
   campaign logs, diaries, defect registers, or superseded plans. The directory's own
   `README.md` says this out loud and is the single best artifact in it.
2. **The nominal "single tracker" has been silently superseded.** `docs/design/README.md`
   names `decompiler-roadmap.md` as "**The plan.** The single tracker." But the newest
   diary in this very directory (`decompiler-roadmap-diary-2026-08-31.md`, Entry 1)
   names a *different* durable plan living outside this scope:
   `docs/development/real-binary-decompiler-roadmap-2026-08-31.md`. Two roadmaps, one
   index that only knows about the older one.
3. **`decompiler-roadmap.md` (3,301 lines) is stale by 399 commits.** Its planning
   baseline is `fb4ee6ba` (2026-08-13); `git rev-list --count fb4ee6ba..HEAD` = **399**.
   Its "Foundations still incomplete" audit is dated 2026-08-15 and several items are
   now factually wrong (see §Cross-cutting #2). CLAUDE.md's claim about it *is* accurate:
   Appendix A really is at line 3209, really is titled "ON DEMAND ONLY", and really is
   not a work queue.
4. **The roadmap's size/fitness numbers are wrong by ~30%.** It says 314 product files /
   166,455 LOC, mean 530.1, `ir/ast.rs` 11,628 lines, 5 of 7 targets missed. Current
   `tools/fitness_baseline.json`: **455 product files / 185,318 product LOC, mean 407.3,
   max 2,268 (`ir/lift_x86.rs`), `ir/ast.rs` = 1,711 product LOC, 6 of 9 targets met.**
5. **Three docs are contradicted outright by the code.** `table-dispatch-arguments-2026-08-12.md`
   documents `95_function_pointer_table:gcc:O2:dispatch_operation` as failing — it is
   `"pass"` in `baseline.json` today. `review-findings-width-effect.md` claim (b) says
   "no lifter emits `Op::Concat` today" — three lifter submodules emit it now.
   `decbench-submission-readiness.md` says "there is no upstream PR, issue, or
   submission" and "do not submit" — the roadmap records DecBench PRs #56/#61/#62 all
   merged upstream.
6. **The 2026-08-31 diary's own conclusions are already obsolete.** Its Entry 6 says
   "Current ARM32 lift code has no matching implementation" for Cortex-M `MRS`/`MSR`
   (class F2a). `src/ir/lift_arm32/sysreg.rs` exists and cites "DecBench class F2a, 31
   rows" in its module doc. The diary is a correct dated record; it is not current state.
7. **Six docs carry knowledge that exists ONLY here and would be lost on delete** (see
   §Cross-cutting #4): the register-view ownership rationale, the x86 flag
   producer/consumer protocol, the goto-sinking negative result, the two dormant
   structural passes and their measured zero fire counts, the `CallGraph` non-viability
   measurement, and the whole-binary serialization survey. Two of these are load-bearing
   for *tests* — `test_loop_hoist_traps.py` and `test_src_dependency_boundaries.py`
   cite design docs by path in assertion messages.
8. **The three "roadmap diary" files plus the two 2026-08-08 DecBench files are 20,507
   lines — 54% of the directory — and are pure append-only session logs.** They should
   be a `docs/history/` tree, not "design".
9. **Duplicated coverage is severe on the architecture story.** Six documents each
   propose a variant of "introduce a typed SSA/MIR spine between LLIR and rendering":
   `decompiler-middle-architecture.md`, `value-model-root-cause-and-plan.md`,
   `typed-ssa-hlir.md`, `semantics-preserving-structuring.md`,
   `glaurung-architecture-redesign-2026-08-05.md`, `decompiler-rearchitecture-2026-08-06.md`.
   The roadmap says it consolidated all six; none was retired.
10. **`FunctionFacts` / `CallFactStore` — the plan's most-duplicated open item — has
    zero occurrences in `src/`.** `function-facts-and-call-facts-2026-08-15.md` still
    says "Nothing here is implemented" and is still literally true; it is the only doc
    here that is both a design and current.
11. **Nothing in this directory should survive a rewrite unedited.** The target is one
    architecture document that absorbs ~6 docs' worth of live knowledge, one live
    roadmap (which belongs in `docs/development/`, where the successor already is), and
    a flat `docs/history/design/` archive for the other ~39.

---

## Per-file record

Ordered alphabetically. "lines" is `wc -l`. Verdicts follow the brief's vocabulary.

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---:|---|---|---|---|---|
| `docs/design/README.md` | 86 | 2026-08-27 `d8665dd8` | index | mostly-current | Accurate about roles and honest ("Three of them are live; the rest are evidence"). But says "30+ documents" when there are 48 top-level + 2 subdirs; and names `decompiler-roadmap.md` as "the single tracker" while `decompiler-roadmap-diary-2026-08-31.md` Entry 1 points the durable plan at `docs/development/real-binary-decompiler-roadmap-2026-08-31.md`. Its per-file annotations (dormant-transforms correction, decbench-defect-reproductions, fixture-expansion) all check out. | `rewrite` — best-written file here; must be re-pointed at the successor roadmap and the new archive layout |
| `armv7-real-defects-2026-08-05.md` | 746 | 2026-08-11 `440e42f3` | record | historical | Dated defect archaeology with per-cluster evidence lines. Cites `tools/arch_roundtrip.py` (exists) and numbers (`210/256`, `cargo test --lib 1737/1737`, `fixture_harness 656 pass`) that are all pinned to 2026-08-05 and long superseded — `arch_baseline.json` now holds **2,473** lanes. Diagnoses (four root causes) are real and were fixed. | `archive` — root-cause narratives are worth keeping as record; nothing here is guidance |
| `backlog-2026-08-05.md` | 159 | 2026-08-13 `3827cf79` | record | superseded | Eight items "preserved from the task list". `defect-register-2026-08-05.md` §Scope provenance says it exists precisely to reconstruct these eight items, and it did. Its lead item (`coalesce_phi_copies` 46% width-ambiguity refusal) is unresolved but is restated in the register. | `archive` — superseded by the defect register it seeded |
| `branch-retirement-2026-08-13.md` | 106 | 2026-08-13 `c6960a22` | record | historical | Pure manifest: branch name → SHA → disposition, for branches deleted in the 2026-08-13 audit. Explicitly kept because "branch deletion is the one step of that audit that cannot be undone by reading the repository". Only value is disaster recovery of orphaned SHAs. | `archive` — irreplaceable as a record, zero design content |
| `decbench-defect-reproductions-2026-08-27.md` | 1004 | 2026-08-27 `d8665dd8` | record + design-proposal | mostly-current | Pinned to Glaurung `5e168798`. Its headline finding — "two of our three named defects were described backwards" — is a correction to other docs in this directory and is why `README.md` says read it first. §10b claims delivered work (ARM/AArch64 scaled-index `lsl #n`, `ldr pc` jump tables); the corresponding fixtures (`207_scaled_index_addressing`) exist. §7's remaining four-workstream plan is a proposal that was never folded into the roadmap (the doc itself says "if adopted, it belongs in decompiler-roadmap.md"). | `revise`+`archive` — extract §7's live plan into the successor roadmap, archive the rest |
| `decbench-full-failure-taxonomy-2026-08-31.md` | 245 | 2026-09-01 `dbf4f5ca` | record | historical | Explicitly self-limiting: "The repository has moved since this measurement. Do not attribute these counts to current `master`." Pins Glaurung `7bc73539`, DecBench `f76dae07`, 803 binaries / 94,575 functions. Referenced from `docs/development/test-estate/EXECUTION.md` and from the successor roadmap. | `archive` — but keep the inbound links working; it is cited evidence for the live plan |
| `decbench-full-leaderboard-data-plan.md` | 810 | 2026-08-31 `2ce51f9d` | roadmap/plan | stale | "Status: execution in progress (run `20260831T180316Z`)". The run it plans has since completed (the taxonomy and score audit are its outputs). Names ~12 `tools/decbench_*.py` scripts that all exist (`decbench_evaluate_sharded.py`, `decbench_merge_shards.py`, `decbench_score_ledger.py`, …). Undated status banner on a finished activity. | `archive` — a completed operational runbook; if a future leaderboard refresh is planned, cherry-pick the pinning procedure |
| `decbench-full-score-audit-2026-08-30.md` | 168 | 2026-08-31 `7bc73539` | record | historical | Pinned score audit at `229fbb1d`: GED 32.275%, type 21.812%, byte 5.893%, union 41.553%. Carefully caveated ("must not be labelled an exact adapter or submission replay"). Cited from `docs/development/decompiler-testing.md:657`. | `archive` — dated measurement, correctly caveated |
| `decbench-gap-analysis-diary-2026-08-08.md` | 3964 | 2026-08-13 `4549aee8` | record | historical | Session diary; 61 commits touched it. Pins Glaurung `c1cfdc97`, DecBench `0a4e85bc`. The roadmap lists it under "Evidence and decision records". Its projected leaderboard ranks are explicitly "projections", and its own companion roadmap now calls its absolute GED/union totals unusable ("recomputed from row-level artifacts rather than adjusted arithmetically"). | `archive` — a diary, not a design |
| `decbench-native-provenance-2026-08-27.md` | 1057 | 2026-08-29 `81feb372` | design-proposal + record | mostly-current | The DecBench-side audit ("we drop `ins.va` at lowering") verified true: `src/ir/ast.rs`'s `Function` carries `entry_va` only. Its §10c named three calibration targets that became `decbench-defect-reproductions-2026-08-27.md`. Cited from `docs/development/decompiler-testing.md:745`. Notes the audit lives only on an unmerged upstream draft branch — knowledge that exists nowhere else. | `merge-into` the new architecture doc for the provenance/`ins.va` analysis; `archive` the pinned-ref narrative |
| `decbench-remediation-roadmap-2026-08-08.md` | 1304 | 2026-08-13 `4549aee8` | roadmap/plan | superseded | Banner: "Status: active, ranked execution plan". It is not — `decompiler-roadmap.md`'s own preamble says it consolidated "the DecBench gap analysis, repair campaign …" and lists this file under "Evidence and decision records". Its planning baseline `020dede` is ~400+ commits behind. 46 commits of churn, all before 2026-08-13. | `archive` — a false "active" banner on a superseded plan is the exact failure mode `README.md` warns about |
| `decbench-submission-readiness.md` | 1165 | 2026-08-07 `0ec35a2e` | record + decision log | **stale (actively misleading)** | Header: "Last updated: 2026-08-02", "It is not merged into `Noelo-Lab/decbench`: there is no upstream PR, issue, or submission", "Current decision: do not submit" (repeated at lines 127/309/410). `decompiler-roadmap.md` Appendix A records PR #56 merged as `08f89158`, #61 as `af02672d`, #62 as `3db5d557`. Direct doc-vs-doc contradiction on a project-boundary-sensitive topic (cf. CLAUDE.md's DecBench boundary rules). | `archive` with a correction banner, or `delete` — its decision has been overtaken and its "no submission exists" statement is false |
| `decompiler-gap-plan-2026-08-01.md` | 1957 | 2026-08-07 `0ec35a2e` | roadmap/plan | superseded | Four workstreams (A: ELF discovery, B: termination, C: value fusion, D: ARM/AArch64) against Ghidra/angr/RetDec. Several sub-items are marked `RESOLVED` inline (A.3, A.4, D.1, D.2). The remainder was consolidated into `decompiler-roadmap.md`. Its `/nas4/data/binary-analysis` corpus is not in this repo, so nothing here is reproducible from a clean checkout. | `archive` — the "RESOLVED" annotations make it a decent history of the Aug-01 campaign; not guidance |
| `decompiler-middle-architecture.md` | 424 | 2026-07-26 `b1959676` | architecture / design-proposal | superseded | The original "introduce one authoritative typed SSA/MIR between LLIR and HIR" thesis (2026-07-26, snapshot `d6144a7`). Its §2 root causes are still the clearest statement of *why* the middle needed rework. Superseded by `glaurung-architecture-redesign-2026-08-05.md` → `decompiler-roadmap.md`. Its Phase 3/4 targets (typed SSA replacing string-numbered SSA; structurer behind shadow mode) are still unbuilt — `src/ir/mir/` exists but has no production consumer. | `merge-into` new architecture doc (§2 root causes, §4 target architecture), then `archive` |
| `decompiler-next-implementation-directive.md` | 124 | 2026-07-25 `ce793833` | record | stale | "`origin/master` is `5b0568e`. The committed fixture baseline is 117 pass, 284 fail, 55 structural." Current `baseline.json`: **839 lanes, 2,895 pass / 433 fail / 121 structural**. Describes a red CI job (`maturin` not found) fixed long ago. A one-off task hand-off note. | `delete` — no durable content; every fact in it is stale |
| `decompiler-plan-2026-07-27.md` | 368 | 2026-07-28 `77fb7465` | roadmap/plan | superseded | Self-labelled the next day: "Status, 2026-07-28: Historical evidence and remaining backlog, not a live implementation checklist." Explicitly supersedes `value-model-root-cause-and-plan.md`'s phase ordering, and is itself superseded by the roadmap. Referenced from `docs/development/2026-07-27-uncommitted-work-handoff.md` and `docs/analysis/decompiler/…-diary.md`. | `archive` |
| `decompiler-rearchitecture-2026-08-06.md` | 365 | 2026-08-07 `d6944e96` | design-proposal | superseded | "Status: proposed, evidence-backed", snapshot `1fc76ab`. Same thesis as the 08-05 redesign, one day later, with a 2026-08-07 implementation checkpoint. Fifth restatement of the same architecture. | `archive` — pure duplicate of the 08-05 redesign's argument |
| `decompiler-refactors.md` | 270 | 2026-07-25 `5e2e7634` | record | historical | "Current metrics (2026-07-25 …)" measured with `/tmp/claude-1000/local_eval.py` — a script that no longer exists and was in `/tmp` (which CLAUDE.md forbids writing to). GED 5.99 vs angr 7.59 etc. are July-25 numbers. Cited by `typed-ssa-hlir.md:488` for an O2 reality check. | `archive` — irreproducible measurements; keep only as dated record |
| `decompiler-roadmap-diary-2026-08-13.md` | 8523 | 2026-08-16 `0acfe208` | record | historical | The single largest file in the directory (22% of it). Entries 1–48, RED→GREEN→VERIFY. 32 commits. Genuinely high-quality evidence, but it is a log. | `archive` to `docs/history/` |
| `decompiler-roadmap-diary-2026-08-16.md` | 2709 | 2026-08-17 `3aa33804` | record | historical | Entries 54–69. Carries two durable lessons in its preamble ("write the command next to the number"; "measure the tool's own noise floor before trusting a diff" — the `HashMap` iteration-order non-determinism in `merge_exact_definition_widths`). Those two paragraphs are the only reusable content in 2,709 lines. | `archive`; hoist the two methodology lessons into CLAUDE.md or a testing doc |
| `decompiler-roadmap-diary-2026-08-18.md` | 623 | 2026-08-18 `610aeb7b` | record | historical | Entries 70–79. Entry 70 is the origin of CLAUDE.md's feature-gate bullet ("`src/lib.rs:65` is `#[cfg(feature = "symbolic")]`"). Note: `src/lib.rs` line number has drifted (CLAUDE.md itself now says line 80, and the tree grew 46%). The lesson has already been promoted to CLAUDE.md, so the diary is redundant for guidance. | `archive` |
| `decompiler-roadmap-diary-2026-08-19.md` | 1212 | 2026-08-19 `08046a87` | record | historical | Entries 80+. Entry 80 (ruff `target-version = "py314"` vs `requires-python = ">=3.11"`) is a real, already-fixed defect. Cited from the roadmap's evidence list. | `archive` |
| `decompiler-roadmap-diary-2026-08-31.md` | 342 | 2026-09-01 `5c4df8d2` | record | historical (contents already actioned) | Entry 1 redirects the durable plan to `docs/development/real-binary-decompiler-roadmap-2026-08-31.md`. Entry 6 says "Current ARM32 lift code has no matching implementation" for Cortex-M `MRS`/`MSR` — **`src/ir/lift_arm32/sysreg.rs` now exists and its module doc cites "DecBench class F2a, 31 rows"**. Entry 6's F1a stdcall-`@N` canonicalization is partly present (`src/symbols/analysis/suspicious.rs` strips `@N`). | `archive` — but its Entry 1 redirect is the single most important navigational fact in the directory and must be carried into the new index |
| `decompiler-roadmap.md` | 3301 | 2026-08-19 `08046a87` | roadmap/plan | stale (structure sound, contents ~400 commits behind) | Banner "Last updated: 2026-08-13", planning baseline `fb4ee6ba`; `git rev-list --count fb4ee6ba..HEAD` = **399**. **Verified still true:** `src/ir/hir/`, `src/lift/`, `src/ir/lifted/`, `src/render/` do not exist; `FunctionFacts`/`CallFactStore` = 0 hits in `src/`; `remap_type_map` still live in `python_bindings/ir/type_maps.rs`; `render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types` still exists; `ProgramEnvironment::types()` still test-only. **Verified now FALSE:** (a) "MIR is not BUILT on a production decompile / `lower_verified_with_image` has two non-test call sites, one env-var-gated" — `5ab8e7d3` and `614cd661` moved it to `python_bindings/ir/pipeline.rs:406` as `PreparedLlir::mir()`, available for every decompilation; (b) all the fitness numbers (see §Cross-cutting #3); (c) `ir/ast.rs` is 1,711 product LOC, not 11,628. **CLAUDE.md's claim about it is accurate**: Appendix A is at line 3209, titled "ON DEMAND ONLY", and is explicitly not a work queue. Its meta-guidance (two tracks; Phases are views not work; `[x]` requires a production caller; capability census first) is the most valuable prose in the directory. | `rewrite` — split into (i) the meta-guidance + non-negotiable design rules → new architecture doc, (ii) the open items → reconcile against `docs/development/real-binary-decompiler-roadmap-2026-08-31.md`, (iii) the Current-state/Phase blocks → archive |
| `decompiler-ux-competitive-ranking.md` | 268 | 2026-08-29 `229fbb1d` | reference / competitive analysis | **current** | Best-sourced document here. Every competitor claim traced to a primary source (Ghidra `master@9f377f1cbd79`, angr `master@72c3b454`, Hex-Rays docs); Glaurung column probed on 2026-08-28, not recalled. Verified: `type_field_uses` exists in `python/glaurung/llm/kb/type_db.py:54` with the only reader in one LLM tool (matching "exists unused" — nearly); `undo_log` in `cli/commands/undo.py` + `llm/kb/xref_db.py`; the 7-value `set_by` ladder incl. `borrowed` in `llm/kb/provenance.py:101`; `Stmt::Origin` does **not** exist, so §4 item 1 (the line map) is still open as stated. Cited from `docs/README.md:35`. Its §4 is a real, ordered, still-valid work queue. | `keep` — the one file here that a rewritten docs tree should promote, not archive. Move to `docs/architecture/` or `docs/product/`; it is not a design proposal |
| `defect-register-2026-08-05.md` | 1088 | 2026-08-07 `02d32c9d` | record | historical | Self-described "authoritative execution checklist" and "live evidence register", but 10 items are CLOSED, 1 FIXED, 1 OPEN, 1 ADJUDICATE, and nothing has touched it since 2026-08-07. Reconstructs `backlog-2026-08-05.md`. Root-cause writeups are good. | `archive` — a closed register; "live" banner is false |
| `dormant-transforms-2026-08-12.md` | 168 | 2026-08-15 `21b0fde9` | record | **current as a correction** | Leads with an unusually honest correction: the original table "was never measured" because `src/ir/loop_form.rs` had zero `pass_stats` references at the commit that added both. Re-measured section is reproducible. **Verified today:** `recover_owned_pretested_do_while` (21 fires), `recover_guarded_do_whiles` (0), `recover_sentinel_search_loops` (0) all still exist in `src/ir/loop_form.rs:237/250/320`; `src/ir/pass_stats.rs` exists and `loop_form.rs` now has 6 `pass_stats` references; fixture `192_pointer_chased_list.c` exists. The "retire or repoint" question is still open. | `keep` (short) or `merge-into` a maintenance/dead-code doc — this is live, unresolved, measured knowledge that exists nowhere else |
| `fixture-expansion-2026-08-27.md` | 319 | 2026-08-27 `d8665dd8` | record | mostly-current | "Status: landed. 14 fixtures, 62 functions, 266 judged cells — 234 pass, 32 fail." **Verified:** fixtures `206_aarch64_wide_dispatch` … `219_rust_iterator_chains` all exist in `tests/decompiler_fixtures/src/`. §0's argument (the execution gate is blind to *structure*) motivated the two structural predicates; `has_switch` and `goto_free` both exist in `tests/decompiler_fixtures/structural.py:202/224`. Its five named new defects are the only writeup of them. | `revise`→`archive` — the §0 argument about what execution-differential testing cannot see belongs in the testing doc; the defect list is record |
| `function-facts-and-call-facts-2026-08-15.md` | 319 | 2026-08-16 `b4232975` | design-proposal | **current** | "Status: design note. Nothing here is implemented." — **still literally true**: `grep -rn "FunctionFacts\|CallFactStore" src/` returns nothing. §6 is a measured correction that reverses §4: the existing `CallGraph` is not fit to keep (fails its own `validate()`; roots absent from `nodes`; 41% of nodes are synthetic `sub_<hex>`; keyed by name). Cited four times from `decompiler-roadmap.md` (lines 435, 1537, 2030, 2123). | `keep` / `merge-into` new architecture doc — the roadmap's most-duplicated open item's only design, plus a negative result that prevents a wrong implementation |
| `ged-recovery-measured-trade.md` | 71 | 2026-07-28 `38eefd00` | record | historical (but test-linked) | "STRICTLY EXPERIMENTAL — do not merge or cherry-pick the AST code." Records a correctness bug in `drop_dead_preamble` on branch `recover-ged-cells` @ `2bde5a8` (branch since retired). **`python/tests/test_loop_hoist_traps.py` cites this file by path in an assertion message (line 171)** — deleting it breaks a live test's diagnostic. | `archive` — but the path must stay resolvable or the test message must be updated |
| `glaurung-architecture-redesign-2026-08-05.md` | 955 | 2026-08-13 `3827cf79` | architecture / design-proposal | superseded | "Status: proposed architecture and dependency-ordered implementation plan." The direct ancestor of `decompiler-roadmap.md` — the roadmap's opening quote ("one semantic spine…") is this document's executive verdict verbatim, and the roadmap lists it first under "Evidence and decision records". Its §Module and file decomposition proposes `src/lift/`, `src/ir/hir/`, `src/render/` — **none of which was ever created**. Its Phase 0–7 ordering is the roadmap's Phase 0–8. | `merge-into` new architecture doc (the design rules and the 3-IR-layer model), then `archive` |
| `glaurung-architecture-review-diary-2026-08-05.md` | 344 | 2026-08-13 `3827cf79` | record | historical | Evidence log for the doc above; deliberately "records observations before recommendations". Checkout `89b220e`. Design-doc-shaped filename, campaign-log content. | `archive` |
| `goto-density-measurement-2026-08-12.md` | 69 | 2026-08-12 `5e24383a` | record | **historical but uniquely valuable** | Written when `src/ir/goto_sink.rs` was deleted (**verified absent**). Carries a measured negative result nothing else records: the pass removed 11% of gotos and cost `statemachine:gcc:O0` a GED of 10 → 35 plus five `byte_match` cells. Also the only place with the goto-density comparison (Glaurung 8.63 / Ghidra 3.18 / angr 1.99 per 100 lines). Its closing "what would have to change first" is a live open design question (what readability metric do we optimize alongside GED?). | `keep` (short) — a negative result that will otherwise be re-derived at cost |
| `ioctl-taint.md` | 176 | 2026-05-25 `019be127` | architecture / design | **current** | Oldest file here (2026-05-25), single commit, and the only one describing a *shipped, self-contained* subsystem: `src/analysis/ioctl_taint.rs` exists (1,081 LOC per `fitness_baseline.json`), and `ioctl_taint` is named in CLAUDE.md's "active frontier". Describes the abstract domain, transfer function, worklist, null-check tracking, Python API, and explicit v1 non-goals. No dated status banner, no campaign framing. | `keep` — move to `docs/architecture/` or the Windows-port tree; this is a module design doc, not a design proposal |
| `master-integration-2026-08-12.md` | 73 | 2026-08-13 `3827cf79` | record | historical | Self-closed: "**RESOLVED, later the same day.**" Records three hand-ported conflicts from `codex/primary-dirty-worktree-20260811` and names the commits (`5e24383`, `b4c7179`, `781e62c`). Referenced from `orphan-adjudication-2026-08-19.md:93`. | `archive` |
| `multi-decompiler-roundtrip-2026-08-04.md` | 257 | 2026-08-13 `3827cf79` | record | historical | Ten DecBench projects × four decompilers, ~6,000 functions. Its most durable statement is a caveat: "Ghidra, IDA, Binja, Kuna and dewolf are not installed … *every* Ghidra/IDA/Binja number in our documents is an imported figure that cannot be recomputed or checked here." That warning is still relevant to every competitor table in this directory. | `archive`; hoist the "imported figures cannot be checked here" caveat into the new index |
| `orphan-adjudication-2026-08-19.md` | 202 | 2026-08-19 `56d7d769` | record | historical | Adjudicates 300 dangling commits at `master@08046a87`; partitions them (127 `index on`, 37 `untracked files on`, 88 dropped stashes with content, 32 named stashes, 16 real commits). Contains a self-correction (the 88 were wrongly folded into "internals"). One-time cleanup record. | `archive` |
| `register-views-and-the-verifier-boundary.md` | 303 | 2026-07-25 `65f7b9ee` | architecture | **partially superseded, still load-bearing** | Documents why `src/ir/regview.rs` exists (**verified present**) and what it replaced. **Partly stale:** it says `ssa.rs::parent64` and `lift_x86::partial_gp_parent` were the duplicated tables to remove — `parent64` still has four live callers (`program/environment.rs:90`, `use_def.rs:28-29`, `value_number/tagging.rs:36`), so the consolidation is incomplete; `partial_gp_parent` is gone. §2 (prepare-then-render verifier boundary) is the only prose explanation of that boundary. Listed in the roadmap's evidence records. | `merge-into` new architecture doc — the "one owner for register views" and "verifier boundary" rationale must survive; the §3 defect table is record |
| `review-findings-cf-closure.md` | 187 | 2026-07-24 `71e5a42c` | record (code-review verification) | stale | Verification of review item #3 against a tree at `/nas4/data/workspace-infosec/glaurung-decbench` (not this repo). Cites `src/python_bindings/ir.rs:596-608` and `src/ir/ast.rs:2345-2350`; `ir.rs` has since been split (`ir/pipeline.rs`, `ir/type_maps.rs`, …) so every line citation is dead. `decompile_range_at_py` still exists (`src/python_bindings/ir.rs:512`). | `archive` or `delete` — a July-24 review verification against a different checkout |
| `review-findings-width-effect.md` | 295 | 2026-07-24 `71e5a42c` | record (code-review verification) | **stale (one claim now false)** | Same shape as above. Claim (b): "Concat → `hi \| lo` without shift — CONFIRMED (latent), **zero blast radius — no lifter emits `Op::Concat` today**". **False now:** `Op::Concat` has 34 occurrences, emitted from `lift_x86/xmm_views.rs:79`, `lift_x86/packed_halves.rs:133,209` and `lift_x86.rs:6147`. All line citations dead after the `ir.rs` split. | `archive` or `delete` |
| `semantics-preserving-structuring.md` | 192 | 2026-07-24 `2ccfb50b` | design-proposal | partially shipped / superseded | §2 root cause 1 ("edge semantics are not first-class; `structure.rs` reconstructs taken/fallthrough from `cond_taken`") — `ControlFlowEdgeKind` is still `core/control_flow_graph.rs`-defined and used in `analysis/cfg.rs:44`. §5 "the verifier comes first" and §3.2 "the structurer must be total, not a better matcher" did ship in spirit: `src/ir/structure/` now has `region.rs`, `verify.rs`, `fallback.rs`, `path_predicates.rs`. Cited by `decbench-defect-reproductions-2026-08-27.md:280` as "the design intent". | `merge-into` new architecture doc (§3 design principles, §5 verifier-first), then `archive` |
| `stack-bias-affine-index-2026-08-13.md` | 77 | 2026-08-13 `c6960a22` | record | **current (unimplemented idea, deliberately preserved)** | Records the one idea from branch `agent/stack-bias` @ `4ac7657` that could not be moved mechanically. **Verified: `affine_of`, `affine_of_expr`, `collect_affine_index_defs` do not exist in `src/`** — the idea is still unimplemented, and the branch is retired (see `branch-retirement-2026-08-13.md`). The roadmap's Appendix A `[x]` "documenting the one stack-bias idea that requires a clean re-port" points here. | `keep` (short) or `merge-into` a backlog — the branch is gone; this file is the only surviving description |
| `string-recovery-root-cause-2026-08-03.md` | 311 | 2026-08-07 `0ec35a2e` | record | historical | Diagnosis pass over extbench Tier A (`tools/extbench/` exists). Its headline is a metric correction ("the recorded 1.10 vs 3.79 string result was not a per-function rate"). Closing table shows the campaign result (all-arch 0.269 → 0.774 vs Ghidra 1.147). Gate numbers (`cargo test --lib` 1,735) are August-03 vintage. | `archive` |
| `table-dispatch-arguments-2026-08-12.md` | 121 | 2026-08-12 `5e24383a` | record | **stale — the defect it documents is fixed** | "The defect: `95_function_pointer_table:gcc:O2:dispatch_operation` fails." **`baseline.json` records `{"dispatch_operation": "pass", "fold_operations": "fail"}`** for that lane. The doc's own framing (a reverted wrong fix, recorded so the next attempt starts from the root cause) means it is now a record of a closed problem — but nothing in it says so, and the roadmap still lists it as evidence. | `archive` with a resolution note — it currently reads as an open defect |
| `typed-ssa-hlir.md` | 492 | 2026-08-07 `03e63eeb` | design-proposal | **partially shipped, still partly live** | Stated goal: "lets us delete `remap_type_map` and the `DEC_PTR_ARGS`/`DEC_PTRS` render-time reconciliation". **`remap_type_map` is still live** (`python_bindings/ir/type_maps.rs:56`, three call sites in `ir.rs`); `DEC_PTR_ARGS`/`DEC_PTRS` are gone but **ten other `DEC_*` thread-locals remain in `src/ir/ast.rs:1365-1419`**, so the render-time-state problem is reduced, not solved. Its Phase 1–5 ladder is the clearest write-up of the value-identity problem. Two dated checkpoints (2026-07-29) are grafted above the design, which makes it read as half diary. | `rewrite` — extract the target design (§2, §3) into the new architecture doc; archive the checkpoints |
| `value-model-root-cause-and-plan.md` | 519 | 2026-07-26 `fc01b52e` | design-proposal | superseded | "Status: proposed", snapshot `d6144a7`. Explicitly superseded by `decompiler-plan-2026-07-27.md` ("This supersedes the phase ordering in `value-model-root-cause-and-plan.md`"), which is itself superseded by the roadmap. §0 (the 92% execution differential that regressed 25 of 56 metric cells with none improving) is a genuinely important cautionary datum about optimizing execution correctness against GED. §1 ("`VReg` is an overloaded key") is the origin of the whole typed-SSA line of work. | `merge-into` new architecture doc (§0 and §1), then `archive` |
| `whole-binary-serialization-2026-08-20.md` | 199 | 2026-08-20 `0b4f95b1` | design-proposal | **current** | Single commit, no diary framing, explicit verified/reported split. **Verified today:** `export --output-format` choices are exactly `json, markdown, header, ida, binja, ghidra, bundle` (`cli/commands/export.py:23`) and `ida`/`binja`/`ghidra` really are script emitters (`export_to_*_script`); the "no single whole-binary artifact" claim holds. `WARP` appears only in `llm/kb/{structural_fingerprint,function_identity,xref_db}.py`, i.e. adoption is partial at best. Cited from `docs/architecture/IDA_GHIDRA_PARITY.md:175` and `docs/architecture/PERSISTENT_PROJECT.md:144`. | `keep` / promote — this is a live, unexecuted design decision with two inbound architecture links |
| `x86-flags.md` | 281 | 2026-07-28 `627f4c43` | architecture / protocol spec | **shipped; still the only explanation** | Describes the producer/consumer protocol for x86 flags and why the naive fix (define all flags everywhere) is wrong. **Shipped:** `src/ir/lift_x86/flags.rs` exists as a dedicated submodule (plus `mul_flags.rs`, `conditions.rs`), and there is an "Implemented checkpoint (2026-07-28)" section. The doc's opening statistics ("seventeen flag definitions in total; `add`, `sub`, … define none") are the *pre-fix* state and read as present tense. Referenced from `docs/development/2026-07-27-uncommitted-work-handoff.md:189`. | `rewrite` as a module design doc in the new architecture tree — the protocol and the "mistake to avoid" section are load-bearing and have no code-side equivalent; the pre-fix stats need a tense fix |

---

## Directory-level summary

### What `docs/design/` is really for

Nominally: architecture proposals. Actually, it is **four different things sharing one
folder**, and the mixture is why `README.md` had to be written at all:

| category | files | lines | share |
|---|---:|---:|---:|
| Session/campaign diaries (`*-diary-*`, gap analysis) | 6 | 17,373 | 45% |
| Dated campaign records (defect registers, measurements, integration notes, audits) | 20 | 8,700 | 23% |
| Superseded plans and roadmaps | 8 | 7,500 | 20% |
| Live design / architecture / reference | 8 | 2,400 | 6% |
| The roadmap + its index | 2 | 3,387 | 9% |

(Shares approximate; a few files straddle categories.)

**Live vs record:** by my count **8 files** carry knowledge that a reader today should
act on — `README.md`, `decompiler-roadmap.md` (its meta-guidance only),
`decompiler-ux-competitive-ranking.md`, `function-facts-and-call-facts-2026-08-15.md`,
`whole-binary-serialization-2026-08-20.md`, `ioctl-taint.md`,
`dormant-transforms-2026-08-12.md`, `goto-density-measurement-2026-08-12.md`. A further
**6** (`x86-flags.md`, `register-views-and-the-verifier-boundary.md`,
`semantics-preserving-structuring.md`, `typed-ssa-hlir.md`,
`decompiler-middle-architecture.md`, `value-model-root-cause-and-plan.md`) contain
architectural rationale that must be *absorbed* before they are archived. The other
**34 files / ~31,000 lines** are records.

### Naming pathology

The `-YYYY-MM-DD` suffix is doing the work a directory should do. 24 of 48 filenames
carry a date. Files without a date are not more current — `ioctl-taint.md` (undated) is
from May and is accurate; `decbench-submission-readiness.md` (undated) is from August
and is wrong. **Filename dates are not a reliable currency signal and should not be one
in the new structure.**

### What a clean structure looks like

The directory should stop being a mixed pile and become three separate things:
(1) an architecture reference under `docs/architecture/`, (2) one live plan under
`docs/development/` beside the successor roadmap that already lives there, and (3) a
dated archive under `docs/history/`. See §Proposed new structure.

---

## Cross-cutting findings

### 1. Two roadmaps, one index

- `docs/design/README.md` (2026-08-27): "`decompiler-roadmap.md` — **The plan.** The
  single tracker."
- `docs/design/decompiler-roadmap-diary-2026-08-31.md` Entry 1 (2026-09-01): "Durable
  plan: [real-binary-decompiler-roadmap-2026-08-31.md](../development/…)".
- `docs/development/real-binary-decompiler-roadmap-2026-08-31.md` exists, has a
  "Progress update — 2026-09-01", and cites `docs/design/decbench-full-failure-taxonomy-2026-08-31.md`
  as its evidence. It also references a `decompiler-roadmap-package-2026-08-31.md`.

A reader following `README.md` gets a plan whose baseline is 399 commits old. This is the
directory's single most damaging defect.

### 2. Roadmap "Foundations still incomplete" — item-by-item against code (2026-09-02)

| roadmap claim (audited 2026-08-15) | today |
|---|---|
| `src/ir/hir/`, `src/lift/`, `src/ir/lifted/`, `src/render/` do not exist | **still true** (all four absent) |
| `FunctionFacts`/`CallFactStore` unbuilt | **still true** (0 hits in `src/`) |
| `remap_type_map` still live | **still true** (`python_bindings/ir/type_maps.rs:56` + 3 callers) |
| `render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types` is the production entry | **still true** (`src/ir/ast/decbench_render.rs:130`) |
| `ProgramEnvironment::types()` has only test callers → store is write-only | **still true** (grep finds no production reader) |
| "MIR is not BUILT on a production decompile; `lower_verified_with_image` has 2 non-test call sites, one env-var-gated and dropped" | **NOW FALSE.** `5ab8e7d3` "ir: make verified MIR reachable outside the debug dump" moved it to `PreparedLlir::mir()` (`src/python_bindings/ir/pipeline.rs:406`) with a doc comment that names this roadmap item verbatim. Still `#[allow(dead_code)]` with no consumer, and the `GLAURUNG_DUMP_PASSES` path at line 507 remains — but the stated blocker is gone |
| "5 of 7 fitness targets missed; 314 product files, 166,455 LOC, mean 530.1; `ir/ast.rs` 11,628 lines; 13 files over 2,000" | **all wrong** — see #3 |

### 3. The fitness numbers are the worst single staleness in the directory

`tools/fitness_baseline.json` at HEAD (the generator `tools/fitness_report.py:3` explicitly
sources its targets from `decompiler-roadmap.md`):

| measure | roadmap says | actual |
|---|---:|---:|
| product files | 314 | **455** |
| product LOC | 166,455 | **185,318** |
| mean LOC | 530.1 | **407.3** (target 450 — now **passing**) |
| median LOC | 276 | **301** (target 250 — still failing) |
| files > 2,000 | 13 | **3** (target 5 — now **passing**) |
| % LOC in files > 1,000 | 44.5% | **18.0%** (target 25% — now **passing**) |
| `src/ir` files > 1,000 | 14 | **13** (target 5 — still failing) |
| largest product file | `ir/ast.rs` 11,628 | `ir/lift_x86.rs` **2,268**; `ir/ast.rs` is **1,711** |
| targets met | 2 of 7 | **6 of 9** |

Two tests (`python/tests/test_fitness_report.py`, `test_large_module_review.py`) and
`tools/fitness_report.py` cite the roadmap section by name, so the doc is load-bearing
for the ratchet even though its numbers are fiction.

### 4. Knowledge that exists ONLY in these docs (lost on delete)

Explicitly, with paths:

1. `docs/design/goto-density-measurement-2026-08-12.md` — the *negative* result for
   goto-sinking: the pass removed 11% of gotos and cost `statemachine:gcc:O0` GED 10 → 35.
   `src/ir/goto_sink.rs` is deleted; nothing in the tree records why.
2. `docs/design/dormant-transforms-2026-08-12.md` — the measured fire counts (21 / 0 / 0)
   for three live passes in `src/ir/loop_form.rs`, plus the reason
   `recover_sentinel_search_loops` cannot match what the pipeline emits. Two of those
   passes are reachable, unverified, and untested-in-production; that fact is recorded
   nowhere else.
3. `docs/design/function-facts-and-call-facts-2026-08-15.md` §6 — four measurements
   proving the existing `CallGraph` cannot be the basis of `FunctionFacts` (fails
   `validate()`, roots not in `nodes`, 41% synthetic nodes, name-keyed). Without this a
   future implementer repeats the wrong first step the roadmap still recommends.
4. `docs/design/x86-flags.md` — the flag producer/consumer protocol and "the mistake to
   avoid". `src/ir/lift_x86/flags.rs` implements it; nothing explains it.
5. `docs/design/register-views-and-the-verifier-boundary.md` — why `src/ir/regview.rs`
   owns register views, and what "prepare, then render" means as a boundary.
6. `docs/design/whole-binary-serialization-2026-08-20.md` — the WARP/adopt-vs-build
   analysis, with two inbound links from `docs/architecture/`.
7. `docs/design/stack-bias-affine-index-2026-08-13.md` — the only surviving description
   of an idea whose branch was deleted (`agent/stack-bias` @ `4ac7657`).
8. `docs/design/decbench-native-provenance-2026-08-27.md` — that DecBench's audit of our
   AST lives only on an unmerged upstream draft branch, and that the external eval-kit
   format cannot carry provenance at all.
9. `docs/design/branch-retirement-2026-08-13.md` — SHAs of deleted branches. Recoverable
   only from this table.

### 5. Docs contradicted by code (with the check that proves it)

| doc | claim | check |
|---|---|---|
| `table-dispatch-arguments-2026-08-12.md` | `95_function_pointer_table:gcc:O2:dispatch_operation` fails | `baseline.json` → `"dispatch_operation": "pass"` |
| `review-findings-width-effect.md` (b) | "no lifter emits `Op::Concat` today" | 34 occurrences; emitted from `lift_x86/xmm_views.rs:79`, `packed_halves.rs:133,209`, `lift_x86.rs:6147` |
| `decompiler-roadmap-diary-2026-08-31.md` Entry 6 | "Current ARM32 lift code has no matching implementation" (Cortex-M MRS/MSR) | `src/ir/lift_arm32/sysreg.rs` exists; module doc cites "DecBench class F2a, 31 rows" |
| `decompiler-next-implementation-directive.md` | baseline "117 pass, 284 fail, 55 structural" | `baseline.json`: 839 lanes, **2,895 pass / 433 fail / 121 structural** |
| `armv7-real-defects-2026-08-05.md` | `arch_roundtrip` numbers over 256 armv7 functions | `arch_baseline.json` now holds **2,473** lanes |
| `register-views-…md` | `ssa.rs::parent64` was a duplicate table to remove | `parent64` still has 4 live callers |
| `typed-ssa-hlir.md` | goal: delete `remap_type_map` and the `DEC_*` render-time cells | `remap_type_map` live; 10 `DEC_*` thread-locals remain in `ast.rs:1365-1419` |
| `review-findings-cf-closure.md`, `review-findings-width-effect.md` | file:line citations into `src/python_bindings/ir.rs` and `src/ir/ast.rs` | both files split since (`ir/pipeline.rs`, `ir/type_maps.rs`, `ast/dec_render.rs`, …); every line citation is dead |

### 6. Doc-vs-doc contradictions

- **DecBench submission status.** `decbench-submission-readiness.md`: "there is no
  upstream PR, issue, or submission" / "do not submit" (×3). `decompiler-roadmap.md`
  Appendix A: PRs #56, #61, #62 all `[x]` merged upstream with SHAs. Given CLAUDE.md's
  strict DecBench upstream boundary, having a doc that misstates what has been submitted
  is a real hazard.
- **What the plan is.** §1 above.
- **Whether jump tables work.** `decbench-defect-reproductions-2026-08-27.md` was written
  specifically because two of three named defects "are described backwards in our own
  docs" — i.e. this directory has already caught itself contradicting itself once, and
  the wrong descriptions were never corrected at source, only appended to.
- **What "dormant transform" means.** `dormant-transforms-2026-08-12.md`'s own preamble
  retracts its own table. The retraction is correct; the retracted table is still printed
  in full below it.

### 7. Duplicated coverage (name the files)

- **"Introduce a typed SSA/MIR spine"** — six documents:
  `decompiler-middle-architecture.md` (07-26), `value-model-root-cause-and-plan.md`
  (07-26), `typed-ssa-hlir.md` (07-24 → 08-07), `semantics-preserving-structuring.md`
  (07-24), `glaurung-architecture-redesign-2026-08-05.md`,
  `decompiler-rearchitecture-2026-08-06.md`. Plus `decompiler-roadmap.md`, which says it
  consolidated them. Seven statements of one thesis.
- **DecBench evaluation** — eight files: `decbench-submission-readiness.md`,
  `decbench-gap-analysis-diary-2026-08-08.md`, `decbench-remediation-roadmap-2026-08-08.md`,
  `decbench-full-leaderboard-data-plan.md`, `decbench-full-score-audit-2026-08-30.md`,
  `decbench-full-failure-taxonomy-2026-08-31.md`,
  `decbench-native-provenance-2026-08-27.md`, `decbench-defect-reproductions-2026-08-27.md`,
  plus roadmap Appendix A.
- **Defect lists** — `backlog-2026-08-05.md` → `defect-register-2026-08-05.md` →
  `armv7-real-defects-2026-08-05.md`, all same week, overlapping items.
- **Competitor comparisons** — `decompiler-refactors.md`, `decompiler-gap-plan-2026-08-01.md`,
  `multi-decompiler-roundtrip-2026-08-04.md`, `string-recovery-root-cause-2026-08-03.md`,
  `decompiler-ux-competitive-ranking.md`. Only the last has traceable primary sources;
  the third warns that the others' Ghidra/IDA numbers cannot be recomputed here.

### 8. The self-correction habit is this directory's real asset

Unusually for a docs tree, several files retract themselves in writing:
`dormant-transforms` ("the table below was never measured"),
`function-facts` §6 ("§4 above says … That is wrong"),
`decbench-defect-reproductions` (a corrections table for other docs),
`decompiler-ux-competitive-ranking` §5 ("a self-audit that flatters is worse than none"),
`orphan-adjudication` ("My first pass … was wrong"),
`decompiler-roadmap` ("The plan double-counts itself"). Whatever replaces this directory
should preserve that norm explicitly — `README.md`'s closing rule ("a number in a document
is not a measurement; write the command next to the number") is the best single sentence
in the repo's documentation and belongs in CLAUDE.md.

---

## Proposed new structure for this scope

```
docs/architecture/                              # live, code-facing, no dates in filenames
├── decompiler-pipeline.md                      NEW (rewrite of decompiler-roadmap.md §Target
│                                               architecture + §Non-negotiable design rules,
│                                               merged with decompiler-middle-architecture.md §2/§4,
│                                               glaurung-architecture-redesign-2026-08-05.md §§1-9,
│                                               semantics-preserving-structuring.md §3/§5,
│                                               value-model-root-cause-and-plan.md §0/§1,
│                                               typed-ssa-hlir.md §2/§3)
│                                               — the ONE place the LLIR→MIR→AST→render
│                                                 story, its stage contracts, and the still-
│                                                 unbuilt parts are described
├── register-model.md                           rewrite of register-views-and-the-verifier-boundary.md
│                                               (regview ownership + prepare/render boundary;
│                                               drop the July defect table)
├── x86-flags.md                                rewrite of docs/design/x86-flags.md
│                                               (protocol spec; fix pre-fix stats to past tense)
├── ioctl-taint.md                              MOVED from docs/design/ (already correct)
├── whole-binary-serialization.md               MOVED from docs/design/whole-binary-serialization-2026-08-20.md
│                                               (drop the date; two docs/architecture/ files link it)
└── competitive-position.md                     MOVED from decompiler-ux-competitive-ranking.md
                                                (already linked from docs/README.md:35)

docs/development/
├── real-binary-decompiler-roadmap.md           EXISTS (2026-08-31) — the actual live plan
├── decompiler-open-design-questions.md         NEW (merge of function-facts-and-call-facts-2026-08-15.md,
│                                               stack-bias-affine-index-2026-08-13.md,
│                                               dormant-transforms-2026-08-12.md "retire or repoint",
│                                               goto-density-measurement-2026-08-12.md "what would have
│                                               to change first", decbench-defect-reproductions §7)
│                                               — unimplemented ideas + measured negative results,
│                                                 each with the experiment that decides it
└── decompiler-testing.md                       EXISTS — absorb fixture-expansion-2026-08-27.md §0
                                                (why execution-differential testing is blind to structure)

docs/history/design/                            ARCHIVED — read-only, dated, no status banners
├── README.md                                   NEW — one line per file: date, what it recorded,
│                                               what superseded it, which claims are now known false
├── roadmap-2026-08-13.md                       archived (decompiler-roadmap.md, whole)
├── diaries/                                    archived: the five decompiler-roadmap-diary-* files
│                                               + glaurung-architecture-review-diary-2026-08-05.md
│                                               + decbench-gap-analysis-diary-2026-08-08.md
├── plans-superseded/                           archived: decompiler-plan-2026-07-27, decompiler-gap-plan-
│                                               2026-08-01, decbench-remediation-roadmap-2026-08-08,
│                                               glaurung-architecture-redesign-2026-08-05,
│                                               decompiler-rearchitecture-2026-08-06,
│                                               decompiler-middle-architecture, value-model-root-cause-
│                                               and-plan, semantics-preserving-structuring,
│                                               typed-ssa-hlir, decompiler-refactors,
│                                               decbench-full-leaderboard-data-plan
├── campaigns/                                  archived: armv7-real-defects, backlog-2026-08-05,
│                                               defect-register-2026-08-05, string-recovery-root-cause,
│                                               table-dispatch-arguments (+resolution note),
│                                               fixture-expansion, multi-decompiler-roundtrip,
│                                               decbench-defect-reproductions, decbench-native-provenance,
│                                               decbench-full-score-audit, decbench-full-failure-taxonomy,
│                                               decbench-submission-readiness (+correction banner),
│                                               ged-recovery-measured-trade
└── repo-operations/                            archived: branch-retirement-2026-08-13,
                                                master-integration-2026-08-12,
                                                orphan-adjudication-2026-08-19

DELETE (nothing durable, every fact stale, no inbound links):
├── decompiler-next-implementation-directive.md
├── review-findings-cf-closure.md
└── review-findings-width-effect.md
```

**Migration hazards for whoever executes this:**

- `python/tests/test_loop_hoist_traps.py:171` embeds
  `docs/design/ged-recovery-measured-trade.md` in an assertion message.
- `python/tests/test_src_dependency_boundaries.py:8`, `test_fitness_report.py:2`,
  `test_large_module_review.py:4` and `tools/fitness_report.py:3` all cite
  `docs/design/decompiler-roadmap.md` (the ownership map / the code-quality section).
  Moving or rewriting the roadmap requires updating these four.
- `CLAUDE.md:214` cites `docs/design/decompiler-roadmap.md` Appendix A.
- `docs/README.md:35` links `design/decompiler-ux-competitive-ranking.md`.
- `docs/architecture/IDA_GHIDRA_PARITY.md:175` and `PERSISTENT_PROJECT.md:144` link
  `design/whole-binary-serialization-2026-08-20.md`.
- `docs/development/decompiler-testing.md:657,745,751` and
  `docs/development/test-estate/EXECUTION.md:14` link four `decbench-*` design docs.
- `src/lib.rs:74,79` link `docs/design/execution-engine/` (out of my scope, but any
  reshuffle of `docs/design/` must not break them).

---

## Ground truth established (for other auditors and the plan writer)

**Repo shape**
- `master` @ `b8884687`, 2026-09-02. `fb4ee6ba` (the roadmap's planning baseline) is
  **399 commits** back.
- `src/` top level: `analysis core data debug decompile demangle disasm entropy exec
  flirt formats hashing io ir logging.rs program python_bindings similarity strings
  symbolic symbols target testing.rs timeout.rs triage unpack winmd.rs` + `error.rs`,
  `lib.rs`.
- `src/decompile/` contains only `mod.rs` and `profile.rs` — the decompiler proper lives
  in `src/ir/`.
- **Do not exist:** `src/ir/hir/`, `src/lift/`, `src/ir/lifted/`, `src/render/`,
  `src/ir/goto_sink.rs`.
- 489 `.rs` files / 290,841 total lines including tests. Product-only (per
  `tools/fitness_baseline.json`): **455 files / 185,318 LOC**, mean 407.3, median 301,
  max 2,268 (`ir/lift_x86.rs`), 23 files > 1,000, 3 files > 2,000, 6 of 9 fitness
  targets met.
- `src/python_bindings/ir.rs` (2,496 lines) has been split — siblings now include
  `ir/pipeline.rs`, `ir/type_maps.rs`, `ir/callee_contracts.rs`.
- `src/ir/ast.rs` is 9,710 total / **1,711 product** lines (it was 11,628 product in
  August). `src/ir/ast/` now holds `dec_render.rs`, `ctx_render.rs`, `decbench_render.rs`,
  `c_render.rs`, `prepare.rs`, and 11 more.

**Cargo features** (`[features]` in `Cargo.toml`): `default = ["triage-core"]`;
`triage-core`, `triage-heuristics`, `triage-containers`, `triage-parsers-extra`,
`python-ext` (= pyo3 + `exec`), `exec`, `symbolic` (= `exec`), `dev-oracle`,
`solver-z3`, `solver-axeyum`, `solver-bitwuzla`, `solver-axeyum-text`.
Confirms CLAUDE.md: `symbolic` is in neither `default` nor `python-ext`.

**Fixture corpus** (`tests/decompiler_fixtures/`)
- `src/` holds **219 fixture sources**: 196 `.c`, 10 `.cpp`, 7 `.rs`, 5 `.go`, 1 `.S`.
  Numbering runs `01_…` to `219_…` (with gaps; `200_` is absent).
- `baseline.json`: **839 lanes**, **2,895 pass / 433 fail / 121 structural**.
- `arch_baseline.json`: **2,473 lanes**.
- `structural_baseline.json`: 7 top-level keys (`closure`, `effects`, `gaps`, …).
- `defuse_baseline.json`: 6 top-level keys (`__toolchain__`, `accepted_regressions`,
  `fixture_lane_totals`, …).
- `sets.toml` names sets including `smoke`, `vector-float`, `region`, `loops`,
  `exceptions`, `o0`, `o2`; `@smoke` is function-scoped and capped at 6 lanes by
  `test_dectest_selection.py`.
- Structural predicates `has_switch` and `goto_free` live in
  `tests/decompiler_fixtures/structural.py:202,224`.

**Tooling**
- `tools/dectest.py` is 1,085 lines and supports `fixture[:compiler[:opt[:function]]]`,
  globs, `@set`, `--arch`, `--stripped`, `--show`, `--list-sets`. `O2strip` is a real
  optimization-slot value. Architectures: `x86_64`, `x86_64_gcc15`, `i386`, `aarch64`,
  `armv7`, `armv7_a32`.
- `benches/`: `analysis_cfg, decompile_pipeline, emulator, entropy, ir_dataflow,
  ir_lift, ir_structure, lang_detect, strings, triage`.
- `scripts/`: includes `decbench-local-gate.sh`, `feature-build-gate.sh`,
  `lint-rust.sh`, `verify_tutorial.py` — all as CLAUDE.md describes.

**CLI subcommand registry** (`python/glaurung/cli/main.py`), 40 entries:
`triage, strings, symbols, disasm, cfg, ask, decompile, explain, name-func, repl,
graph, detect-packer, diff, kickoff, patch, verify-recovery, export, undo, redo,
xrefs, frame, strings-xrefs, view, find, bookmark, rename, comment, label, proto,
journal, classfile, java, java-recovery-report, luac, pe, windows-risk, types,
windows, locks, group`.
`export --output-format` choices: `json, markdown, header, ida, binja, ghidra, bundle`.

**Correction to CLAUDE.md worth flagging to the plan writer:** CLAUDE.md says the
knowledge base is `python/glaurung/kb/`. It is **`python/glaurung/llm/kb/`**
(`provenance.py`, `type_db.py`, `xref_db.py`, `function_identity.py`, …). There is no
`python/glaurung/kb/`. Also, `python/glaurung/` still contains five hand-written
top-level `.pyi` files (`analysis.pyi`, `debug.pyi`, `disasm.pyi`, `engine.pyi`,
`ir.pyi`, `winmd.pyi`) despite CLAUDE.md's "never hand-write a `.pyi`" rule — worth a
separate look by whoever audits `python/`.

**Still-unimplemented identifiers named in design docs** (all verified absent from `src/`):
`FunctionFacts`, `CallFactStore`, `affine_of`, `affine_of_expr`,
`collect_affine_index_defs`, `Stmt::Origin`, any `hir` module.
