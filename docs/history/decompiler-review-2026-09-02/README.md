# Decompiler design review, 2026-09-02

> **Kind:** record · **Date:** 2026-09-02

**Status:** independently checked review (evidence, not a work queue)
**Reviewed at:** `master` @ `5c4df8d2` ("docs: record the R8 workstream and the TDD failure corpus")
**Rechecked at:** `master` @ `b8884687` (2026-09-02)
**Revalidated at:** `master` @ `084ccd64` (no intervening decompiler-path changes)
**Scope:** the decompiler pipeline under `src/ir/` and `src/python_bindings/ir*`,
the defects and trade-offs encoded in the test estate, and the planning
documents under `docs/design/` and `docs/development/`.

This directory records a full read of the decompiler as it exists today, what
the tests say is broken, and ten recommendations. It was produced by reading
code and docs, decompiling fixture functions by hand with the shipped CLI, and
counting rows in the committed baselines and the strict-xfail inventory. No
source file was changed and no DecBench or Joern run was made.

## Independent check

I agree with the central diagnosis: the production decompiler lowers LLIR and
a region tree into `ast::Function`, then performs most semantic cleanup over
that mutable AST; MIR/MemorySSA are not production evidence yet; coarse
structuring fallback and goto-heavy output are the largest measured quality
problem; and the four public entry points still duplicate substantial
orchestration around shared helpers.

Several statements and recommendations need correction or qualification:

| original claim | verdict after checking current code |
|---|---|
| SSA is consumed only by prototype recovery and value numbering | **Too narrow.** SSA also feeds structuring, indirect-destination analysis, return materialisation, and other LLIR preparation. The important criticism still holds: the long cleanup pipeline itself operates on the AST and loses SSA value identity. |
| Four proofs can trigger whole-function structuring fallback | **Essentially correct, but phrase it as policy rather than four peer proofs.** `build_full` has three pre-build shape predicates and one post-build leftover-accounting decision; the later verified-accounting boundary can also replace an unsound result with a whole-function `Unstructured` region. `structure/fallback.rs` houses six helpers, but not six independent top-level triggers. |
| About 7,000 lines of MIR/MemorySSA/`DefinitionOracle` are dormant | **Directionally right, understated.** The current MIR, MemorySSA, and memory-object substrate is about 8,700 lines. `PreparedLlir::mir()` exposes verified MIR on demand but is explicitly `dead_code`; the only other production-path construction is debug dumping. There is still no semantic production consumer. |
| `src/ir/verify.rs` is not compiled | **Confirmed.** The file exists but `src/ir/mod.rs` does not declare it. Its tests and LLIR verifier therefore cannot protect the product. |
| Definition-before-use is skipped for functions containing a goto | **Overstated.** Global never-defined, poisoned-value, and uninitialised-frame-pointer checks still run. Only the path-sensitive used-before-definition walk is disabled for unstructured control flow. The blind spot remains serious, but it is narrower than the headline says. |
| Every O2 row is duplicated because O2 and `O2strip.dwarf` are byte-identical | **Nearly, not universally.** 412 of 419 current pairs are byte-identical; seven Rust pairs differ. Normalising those lane identities reproduces the stated deduplicated axis counts (218/473/67/30), but the inventory must deduplicate by content hash or explicit build provenance, not by filename substitution. |
| Declared prototypes need to become authoritative | **Partly implemented, not end-to-end authoritative.** Analyst declarations outrank DWARF and DWARF locks recovery, but `src/ir/ast/decbench_render.rs:186-202` can still discard the declaration based on recovered arity/output kind or renderability. The `tail_dispatch` observation proves it can still be lost. |
| The performance gate still passes missing, partial, or incomparable evidence | **Stale elsewhere in the docs, but fixed in code before this review.** `tools/perf_gate.py` returns the distinct `NOT_EVIDENCE` exit code 3 for all three states, with focused tests in `test_perf_gate_fails_closed.py`. Provenance, RSS, output identity, and body completeness remain release-report gaps. |

The source tree did not change in the reviewed decompiler paths between
`5c4df8d2` and `084ccd64`; the intervening commits changed test faceting, CI,
and test-estate indexing.
The corrections above are therefore corrections to the review, not architecture
changes that landed after it.

### Review-package integrity

Files 01-05 were written first and 06 last; the independent check above ran
between the two, which is why an earlier version of this page reported 06 as
missing. The seven review files and the implementation `PLAN.md` are present.
The check's corrections were verified by
the original author afterwards: the 412 of 419 byte-identical pairs were
re-counted with `cmp` (the seven that differ are the Rust fixtures 166-171 and
219), and the `verify.rs` orphan and the dead MIR hook were re-grepped.

### Differences resolved by the check

The completed recommendations initially differed from the independent check in
three places. The detailed file now records the reconciled decisions:

- **Recommendation 3, the MIR.** Keep it for one explicitly time-boxed
  production-consumer increment, measure unique decisions and cost, then delete
  it if no consumer demonstrates value. Restore the LLIR verifier either way.
- **Recommendation 4, switch evidence.** Carry typed cases in the CFG beside
  the existing `IndirectJump`. Add `Op::Switch` only if it becomes the single
  target authority rather than duplicating CFG truth.
- **Recommendation 6, declared prototypes.** The authority mechanism exists
  before rendering, but the AST renderer still applies recovery-dependent
  eligibility checks. The review's
  observation stands beside it: `08_indirect_dispatch-gcc-O2.so` carries a
  `DW_TAG_subprogram` for `tail_dispatch` with formal parameter `tag` of type
  `int`, and the shipped output renders `long tail_dispatch(unsigned int arg0,
  ...)`. The mechanism is partial and did not hold; parameter names are never
  applied. The recommendation is to make it hold everywhere.

## Files

| file | what it holds |
|---|---|
| [01-architecture-as-built.md](01-architecture-as-built.md) | The decompiler as the code implements it: representations, structuring, type recovery, verification, dormant subsystems, and the smells. Every claim carries a `file:line`. |
| [02-pipeline-map.md](02-pipeline-map.md) | The ordered pass schedule on the `decbench` path, stage by stage, with repeats and fixpoints called out. |
| [03-observed-output.md](03-observed-output.md) | Six fixture functions decompiled by hand next to their source, and what each one shows. |
| [04-defect-inventory.md](04-defect-inventory.md) | The strict-xfail corpus, hand-written xfails, fixture baselines, DecBench no-body taxonomy, recorded trade-offs, and defect clusters. |
| [05-planning-docs-audit.md](05-planning-docs-audit.md) | What the planning documents decided, tried, abandoned, or left contradictory. |
| [06-recommendations.md](06-recommendations.md) | Ten recommendations, ordered by leverage, each with the evidence it rests on, what the docs already said, and how it would be judged. |
| [PLAN.md](PLAN.md) | Dependency-ordered implementation work packages with exact production/test paths, TDD sequence, gates, measurements, stop conditions, and milestones. |

## Headline findings

1. **The design docs describe one semantic spine; the code is a flat AST with
   two structuring layers.** Copy propagation, constant folding, dead-store
   elimination, DCE, stack promotion and argument recovery all run on
   `ast::Function`, a `Vec<Stmt>` with labels and gotos and no value identity.
   SSA is computed repeatedly and does feed prototype recovery, value
   numbering, structuring, definedness, and indirect-target analysis, but its
   identities do not survive into the AST where the long cleanup pipeline runs.
2. **The LLIR structurer is a pattern-matching tree walk with whole-function
   fallback.** Its region algebra has one `exit` per loop and one `join` per
   conditional. Three pre-build shape predicates and post-build accounting can
   each select whole-function labelled-CFG fallback. An 11,303-line layer of
   about 40 AST control-flow rewrites, several run repeatedly, then tries to
   recover what the 7,041-line structurer could not express. The compensation
   is larger than the thing it compensates for.
3. **Goto in goto-free source is the dominant measured defect:** 715 functions
   and 6,791 `goto` statements, evenly spread across gcc, clang, O0 and O2.
   The type axes are almost entirely Rust fixtures (298 of 307 parameter rows).
   The 48 "unrecovered construct" rows are all switch dispatch.
4. **About 8,700 lines are dormant.** MIR, MemorySSA, memory-object recovery,
   and `DefinitionOracle` have no semantic production consumer;
   `src/ir/verify.rs` is not declared by `src/ir/mod.rs`. Two loop recognisers
   fired zero times over 754 objects (`docs/design/dormant-transforms-2026-08-12.md`,
   re-measured 2026-08-15) and still run on every function; see 01 section 6.
5. **Verification is advisory.** Verifiers log, count, or record and continue.
   On goto-bearing output, global definedness checks still run, but the
   path-sensitive used-before-definition check does not.
6. **The inventory substantially double-counts O2.** 412/419 `-O2` and
   `-O2strip.dwarf` pairs are byte-identical; seven Rust pairs differ.
   Provenance-normalised deduplication yields 218 / 473 / 67 / 30 / 0 / 0
   rather than 307 / 715 / 92 / 48 / 0 / 0.

## The ten recommendations, in one line each

1. Build a total, locally-degrading structurer in shadow mode; then retire the AST compensation passes it makes redundant.
2. Run dataflow on SSA and carry value identity and instruction origin into the AST.
3. Time-box one bounded MIR production consumer; keep MIR only if it demonstrates unique value, and restore the LLIR verifier either way.
4. Add jump-table analysis whose typed case edges reach the structurer as authoritative CFG evidence; add `Op::Switch` only if it replaces that ownership.
5. Build the constraint-based C type recovery proposed twice; report Rust separately and defer a Rust ABI track.
6. Make declared-prototype authority hold across every entry point and producer, including parameter names.
7. Add an expression idiom layer between SSA cleanup and rendering.
8. Give the lifters a shared machine model and a standing capability census.
9. Fail closed on release evidence and typed function health with a typed refusal policy, deduplicate the inventory by provenance or content hash, and consolidate the gates.
10. Finish one pipeline for all four entry points, building on the shared `prepare_llir_for_lowering` and `run_ast_passes`, with declared pass preconditions.

Recommendations 1, 2 and 4 attack the two largest failure classes directly;
3 and 10 are what make 1 and 2 safe to do.
