# Source-CFG front end: build, benchmark and parity plan

> **Kind:** plan · **Status:** proposed

**This document is stage S3 of [`roadmap.md`](roadmap.md), in full.** It covers
one thing: replacing Joern for DecBench's GED metric, and proving the
replacement scores identically. It is the programme's first scored milestone and
the only stage with a large external oracle, which is why it is specified before
the stages that matter more.

Read it against the rest of the set: the behaviour being replaced is
[`joern-behavior.md`](joern-behavior.md); the contract is
[`requirements.md`](requirements.md); the code layout is
[`architecture.md`](architecture.md); the component-by-component breakdown of
what to write, in what order, is
[`implementation-inventory.md`](implementation-inventory.md).

Two things this stage is **not**. It is not the whole programme — S4's lowering
to LLIR is what makes the front end worth more than Joern was, and banking the
metric win and stopping is the likeliest failure mode here. And it is not
scheduled: `docs/design/` is not a work queue, the live plan is
[`development/roadmap/`](../../development/roadmap/README.md), and this joins it
only if someone puts it there.

## 0. Why this is worth doing, and why it is tractable

Three facts, all measured in [`joern-behavior.md`](joern-behavior.md), decide
the shape of the work:

1. **The scored surface is tiny.** GED reads a degree sequence and two boolean
   flags. None of Joern's CPG, type resolution, data flow or query language
   reaches the number.
2. **The graphs are small.** Mean 12.03 nodes; 29% of functions coalesce to a
   single node; 3.1% exceed the metric's own 60-node cap and are scored by a
   subtraction.
3. **A large ground-truth oracle already exists offline.** 800 serialized source
   CFGs and 88,963 stored per-function GED values — 85,645 of them paired with
   the exact decompiled C that produced them. Reproducing them needs **zero Joern runs**.

Against that, what Joern currently costs: a 1.9 GB bundle, a JVM boot per file,
~37 minutes for the 56-cell matrix gate, a recorded supply-chain failure mode
(mismatched `joern-cli` jars silently scoring nothing), and a scoring asymmetry
where a decompiler is judged partly on how palatable its output is to Eclipse
CDT.

The risk is equally clear and should be stated up front: **Eclipse CDT's error
recovery is the thing being reimplemented**, not C parsing. On well-formed `.i`
input any competent parser agrees; on decompiler output the divergences are
exactly where CDT chooses to recover differently. That is what the oracle ladder
below is for.

## 1. The oracle inventory

Everything in this table exists on this machine today. Sizes are from
`uv run python tools/source_cfg_census.py ~/.cache/glaurung/decbench-full/tree`
at `935b7db1`.

| oracle | what it is | size | needs Joern? |
|---|---|---|---|
| published source CFGs | `<tree>/<opt>/<project>/source_cfgs/<stem>.json`, Joern's own output, serialized | 800 files / 91,548 functions / 1,101,674 nodes | no |
| stored GED cells | `<tree>/<opt>/<project>/evaluated/<stem>.toml`, `"<col>.ged.functions.<name>" = <float>` | 88,963 cells, of which **85,645 reproducible** (below) | no |
| the C that produced them | `<tree>/<opt>/<project>/decompiled/<col>_<stem>.c` | 1,606 files, ~200 MB | no |
| complete triples | binaries with all three of the above | 785 of 803 | no |
| DecBench's own pure functions | `decbench/utils/cfg.py`, `cfgutils/transformations.py` | ~200 lines | no |
| `.i` translation units | **not shipped** in the published tree | — | no (needs gcc) |

The gap is the last row: direct source-side comparison needs `.i` input, which
the published dataset strips. Two ways to close it, §2.
**One correction, measured with the harness rather than the census.** The
tree holds **88,963** stored GED cells, but only **85,645** of them (96.3%) sit
in a *complete* triple — a binary that also ships a published source CFG and the
decompiled C. The other 3,318 are in 15 shared-library binaries whose source
CFGs were never published, so their stored value cannot be reproduced offline.
**85,645 is the reproducible oracle**; 88,963 is the inventory.

```bash
# at glaurung 935b7db1, needs the DecBench venv for cfgutils/decbench
PYTHONPATH=$DECBENCH_DIR $DECBENCH_DIR/.venv/bin/python \
  tools/source_cfg_parity.py ~/.cache/glaurung/decbench-full/tree --provider null
# -> binaries 785, cells 85645 stored
```

## 2. Closing the `.i` gap

**Option A — a committed fixture corpus (recommended first).** Take the C
programs this repository already owns — `tests/decbench_corpus/src/*.c` and
`tests/decompiler_fixtures/src/*.c` — preprocess them with `gcc -E`, and capture
Joern's CFGs for them **once**. That capture is the only Joern invocation in this
whole plan, it takes minutes rather than tens of minutes, and it produces a
small, committed, in-repo regression corpus that never needs Joern again.

CLAUDE.md forbids running Joern without being asked, so this step is
approval-gated and is the first thing to ask for. The capture command, for the
record:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
for f in tests/decbench_corpus/src/*.c; do gcc -E -P "$f" > "$TMPDIR/$(basename "$f" .c).i"; done
"$DECBENCH_DIR/.venv/bin/python" - <<'PY'
import json, os, pathlib
from decbench.utils.cfg import extract_cfgs_from_source
from decbench.publish.cfg_export import relabel_cfg
out = {}
for i in sorted(pathlib.Path(os.environ["TMPDIR"]).glob("*.i")):
    cfgs = extract_cfgs_from_source(i)
    out[i.stem] = {
        name: dict(zip(("nodes","edges","labels","entry","exit","degenerate"), relabel_cfg(c)))
        for name, c in cfgs.items()
    }
print(json.dumps(out, indent=2))
PY
```

**Option B — regenerate `.i` for real projects.** DecBench's compile stage emits
`.i` via `-save-temps=obj`; a sailr project compiles on the host. This needs no
Joern either, but it does need a DecBench compile run, which is also
approval-gated. Do it only if Option A's coverage proves too narrow.

## 3. Phases

Each phase names its deliverable, its gate, and the condition under which the
whole effort should stop.

### Phase 0 — instrument, before any code

**Deliverable.** `tools/source_cfg_census.py` (landed with this design) plus
`tools/source_cfg_parity.py`: given a materialized tree and a CFG provider, it
walks the 785 complete triples, computes
`vj_ged(rebuild_cfg(published[fn]), provider(decompiled.c)[fn])` for every
function with a stored value, and reports exact-match count, mismatch
histogram, and coverage delta.

**Gate.** Run the parity harness with **pyjoern itself** as the provider on a
small slice. It must reproduce the stored values exactly. If it does not, the
oracle is not an oracle and everything downstream is unfounded. *(This is the
one place pyjoern is invoked, and only if approval for §2 is given; without it,
run the harness with a trivial provider and check only that the plumbing and
the 88,963-cell inventory are correct.)*

**Stop condition.** If stored GED values cannot be reproduced from the published
source CFGs plus the stored C, there is no offline oracle and this plan is
replaced by one that budgets for real Joern runs.

**Status: the inventory is verified.** The plumbing gate ran on 2026-09-04 and
the oracle is what the plan assumed it was:

```
tree        ~/.cache/glaurung/decbench-full/tree
column      glaurung-229fbb1-clean   provider null
binaries    785
cells       85645 stored
  uncovered 85645  (provider produced no CFG)
  no source 0  (dataset gap, not a failure)
```

```bash
DECBENCH_DIR=/nas4/data/workspace-infosec/decbench \
PYTHONPATH=$DECBENCH_DIR $DECBENCH_DIR/.venv/bin/python \
  tools/source_cfg_parity.py ~/.cache/glaurung/decbench-full/tree --provider null
```

`no source 0` is the load-bearing line: every stored cell has its published
source CFG, so there is no dataset gap silently capping what parity can reach,
and the 85,645 denominator quoted throughout this plan is measured rather than
assumed. The harness imports `cfgutils` and `decbench` as libraries, so it needs
their venv on `PYTHONPATH`; it spawns no JVM, and only the `joern` provider
would.

**Status: the distance half is done and verified.** `src/syntax/ged.rs`
implements G-1, G-2 and G-4, and `tools/ged_cross_check.py` diffs it against
the live reference over real published CFGs rather than against vectors we
chose:

```
pairs in dump   12792        # at static-c-analysis-substrate, DEBUG build
  compared      11979
  agreed        11979  (100.0000%)
  disagreed     0
  skipped       813 above the node cap, 0 unmatched keys
```

```bash
DECBENCH_DIR=/nas4/data/workspace-infosec/decbench \
PYTHONPATH=$DECBENCH_DIR $DECBENCH_DIR/.venv/bin/python \
  tools/ged_cross_check.py ~/.cache/glaurung/decbench-full/tree --run
```

The 813 skipped pairs are above `GED_MAX_NODES`, where our value is
`|Δnodes| + |Δedges|` by design rather than an assignment result; comparing
them would be comparing two different formulas. What remains for this stage is
the front end that produces the decompiled-side CFG, not the distance.

### Phase 1 — the parser

**Deliverable.** `src/csource/` with a tolerant C front end meeting REQ-IN-1..4
and REQ-NORM-1..4. Ports of the normalization functions come first because they
are small, pure, and independently checkable.

**Decision point.** Hand-rolled recursive descent versus `tree-sitter-c`
(REQ open question 1). Resolve it with a measurement, not a preference: build
the hand-rolled route to the point where it parses a statement grammar, run the
coverage gate below, and compare against a `tree-sitter-c` spike on the same
corpus. Adopt whichever reaches coverage first; record the loser in
`docs/decisions/`.

**Gate — coverage.** Parse all 1,606 stored decompiled `.c` files and every
preprocessed fixture. Report: files parsed, functions found, functions Joern
found that we did not (a loss), functions we found that Joern did not (a gain).
Target REQ-ROB-1: source-side loss ≤ 5.01%, decompiled-side loss ≤ 0.04%.

**Stop condition.** If, after the spike, neither route is within 5 percentage
points of the coverage target and no path to closing it is visible, stop: the
CDT-recovery risk has materialized and the cost/benefit no longer holds.

### Phase 2 — CFG construction

**Deliverable.** REQ-CFG-1..11: node-granular construction, coalescing, derived
entry/exit flags, the singleton-funcend rule, degeneracy, per-TU resolution,
and the DecBench serialization (REQ-OUT-1).

**Gate — L0, pure functions.** Rust unit tests asserting byte-exact agreement
with the Python originals on real inputs (a real `.i`, real decompiler output
with an embedded ANSI escape, the four sanitize quirks). Cheap and total.

**Gate — L1, structural fixtures.** Against the §2 Option-A corpus: exact
`(nodes, edges, entry, exit, degenerate)` per function, then the strong form —
identical degree-sequence multiset. Every construct in
[`joern-behavior.md`](joern-behavior.md) §4 gets a named fixture: `if`/`else`,
`&&`, `||`, `?:`, `switch` with and without `default`, fall-through,
`while`, `for`, `do`, `break`, `continue`, `goto`, a single-`return` function
that must coalesce to one entry-and-exit node, and a multi-`return` function
that must lose its funcend and end with **no exit flag**.

**Stop condition.** None; this phase is where the work is.

### Phase 3 — parity against the 85,645-cell oracle

**Deliverable.** Nothing new — this is the measurement Phase 0 built.

**Status, 2026-09-04: 79,790 of 85,645 exact (93.1636%), zero uncovered.**

```
binaries    785
cells       85645 stored
  attempted 85645
  exact     79790  (93.1636%)
  mismatch  5855
  uncovered 0  (provider produced no CFG)
  no source 0  (dataset gap, not a failure)
  gained    4333  (functions Joern did not produce)
mismatch by |delta|:  <=1 1527   <=5 2454   <=20 1463   >20 411
  worst ssh-keysign:process_config_line_depth: expected 366.0, got 1433.0
```

```bash
DECBENCH_DIR=$HOME/.cache/glaurung/decbench-full/decbench \
PYTHONPATH=$HOME/.cache/glaurung/cp312-site:$DECBENCH_DIR \
  $DECBENCH_DIR/.venv/bin/python tools/source_cfg_parity.py \
  ~/.cache/glaurung/decbench-full/tree --provider glaurung
```

**Correction (recorded because it was published wrong).** An earlier revision
of this section, and commit `3d50103c`, attributed the whole step from 72.8776%
to 93.1636% to the harness fix. That was measured on a shared checkout in which
the jump-elision change to `src/csource/joern/nodes.rs` was already present but
uncommitted, so the two causes were confounded. Measured in isolation, one file
different, both sides from a clean release wheel:

```
                                  exact    rate      <=1    <=5    <=20   >20
  harness fix only              62,487  72.9605%   1,365  6,392  10,325  5,076
  harness fix + jump elision    79,790  93.1636%   1,527  2,454   1,463    411
```

The harness fix is worth **+71 cells**; the front-end change is worth
**+17,303**, and takes the `> 20` bucket down 92%. Attributing it the other way
round pointed at the wrong place for the remaining work, which is the reason to
record the error rather than quietly restate the number.

What the harness fix genuinely was: this harness learning what the stored cells
are. They are
`decbench.metrics.ged.GEDMetric._compute_uncached` -- isomorphism fast path,
size-delta above the cap, and `max(1.0, vj_ged(...))` -- and we were diffing
against the third step unclamped. Since a non-isomorphic pair can never be
stored as 0 while bare `vj_ged` returns 0 whenever the degree multisets agree,
the clamp alone accounted for most of the gap. `syntax::ged`'s node cap was
also 60 against the reference's 200 (`f216a179`).

The remaining shape gap is 5,855 cells, and the `<= 1` bucket is now the
largest of them at 1,527 -- larger than before the fix, because cells that used
to miss by more moved down into it.

How it got there, on the three-binary slice the components were measured
against (2,525 cells): the anchor alone scored 31 exact (1.23%); F-9 took it to
30 (1.19%) while moving 27 cells out of the `>20` bucket; F-11/F-12 plus the
Joern-shaped chain partition took it to 2,178 (86.26%). Scored with our own
`syntax::ged` over the whole corpus the same three variants give 2.36%, 0.60%
and 72.44% — the middle figure being F-11/F-12 on the *general* partition,
which is **worse than shipping none of it**, and the reason those two landed
together. That 72.44% against this harness's 72.88% is also an independent
cross-check of `syntax::ged` on the full corpus, not just the 11,979 pairs
`tools/ged_cross_check.py` covers.

`uncovered 0` is the structural claim: the front end produced a CFG for every
stored cell. What is left is shape
agreement on 23,229 cells, of which 1,382 are within one.


**Gate — L3, the primary gate.** For each of the 85,645 reproducible cells, our
CFG of the stored decompiled C must reproduce the stored value exactly. The
harness is `tools/source_cfg_parity.py`; it fails on any mismatch **and on any
coverage loss**, because a front end that silently produces nothing would
otherwise exit 0 having proved nothing. Report as
`exact / total`, with mismatches bucketed by `|Δged|` and by function size, and
the worst offenders listed with their source line ranges so a divergence is
localizable without re-running anything.

Two known weaknesses of this gate, both to be stated whenever it is quoted:

* it is an **end-to-end** check, so a mismatch says a divergence exists but not
  where — which is why L1 exists above it;
* GED can coincide across different degree sequences (§2 of
  [`joern-behavior.md`](joern-behavior.md) shows GED 0 for two structurally
  different graphs), so an exact match is strong evidence, not proof. Report
  degree-sequence agreement wherever it is directly checkable (L2), and treat
  L3 as the outer envelope.

**Ratchet.** Commit the pass count as a baseline under `tests/` and fail the
gate on any decrease, in the style of the existing fixture baselines.

### Coverage and cost, measured

Two claims this stage rests on, measured rather than quoted.

**Coverage.** Comparing, per binary, the function names Joern published against
those our front end recovers from the stored decompiled C -- 785 binaries,
90,092 distinct functions:

```
  both recover        88162   97.86%
  only we recover      1880    2.09%
  only Joern recovers    50    0.06%
```

Of the 1,880, only 64 are TU-resolution artifacts (the name is published
elsewhere in the same project); **1,816 appear in no published CFG anywhere in
their project** -- real functions, including bash's `_rl_timeout_handle`,
`rl_get_char` and `ibuffer_space`.

**Read that as coverage breadth, not as Joern failing.** The two sides parse
different inputs: Joern the original `.i`, us the decompiled C. A function in
one set and not the other can be inlining, static merging or decompiler naming.
Joern produced a CFG for **all 91,548** published functions, none empty and
2.77% degenerate, so it is not crashing on this corpus. The harness's `gained`
counter is looser still -- it counts functions with no stored *cell*, which
conflates "Joern produced nothing" with "the pair was never scored" -- and an
earlier revision of this file quoted it as the former.

**Cost.** Every function in every stored decompiled file, release build (cp312
wheel), single process, single thread:

```
  files      1606
  functions  188716
  input      415.1 MB of C
  wall       17.91 s   (11.2 ms/file, 95 us/function)
  throughput 23.2 MB/s
```

Against a JVM per file, and a 56-cell gate at 6:28 wall / 5,078 user
CPU-seconds on eight workers. That is the argument for the stage: not that
Joern is wrong, but that 95 us/function runs inside an edit loop and a JVM
launch per file does not.

### What the remaining gap would cost

The 5,855 cells that still differ are not one problem, and two of the three
groups are bounded by *evidence* rather than by effort:

* **411 beyond delta 20.** 260 are undershoots where S2 prunes statements
  control cannot reach (`REQ-GEN-1`, `src/csource/cfg/reach.rs`) and Joern,
  being syntax-directed, keeps them --- 105 published functions carry an
  unreachable component. `sshd process_server_config_line_depth` is 1,743 lines
  with 258 `goto`s where we emit 48 nodes against a published 663. Tractable,
  and the only group that is straightforwardly ours to fix.
* **1,527 within one.** Diagnosed and *not* a flag problem: 42 are unwinnable
  (our CFG is role-isomorphic to the published **source** CFG where Joern's of
  the decompiled text was not, so we score 0 where the metric's `max(1.0, ...)`
  floor stores 1 --- we are penalised for recovering the original shape), 8 are
  the size lower bound off by one, and corpus-wide only **8 of 5,855**
  mismatches have the signature a flag defect must have.
* **The remaining 1,477 + 3,917 are shape differences nobody can localize
  offline.** The tree publishes Joern's CFG of the *source*, never of the
  decompiled C, and a scalar GED under-determines the graph that produced it.
  Distinguishing "we emit one node too many here" from "one too few there"
  needs either a published decompiled-CFG dump or real Joern runs.

So the honest ceiling on offline docking is roughly the 260-cell group plus
whatever the `<= 5` band yields to the same reachability fix. Past that,
closing the gap is a **data** request, not an engineering one, and it should be
costed as such rather than pursued by guessing. `uncovered 0` is what makes the
remainder a shape argument rather than a coverage one.

### Phase 4 — source-side parity

**Deliverable.** Direct comparison of our `.i` CFGs against published source
CFGs, for whatever `.i` corpus §2 produced.

**Gate — L2.** Per function: node count, edge count, entry set size, exit set
size, degeneracy verdict, and degree-sequence multiset. This is the only gate
that compares *our* graph against *Joern's* graph rather than against a scalar,
so it is the one that localizes construct-level divergence.

### Phase 5 — integration

**Deliverable.**

* `glaurung source-cfg` (REQ-API-3). Adding a CLI subcommand drifts a tutorial
  fixture; refresh with `uv run python scripts/verify_tutorial.py --chapter
  01-install --capture` and read the diff — it should be the command list and
  nothing else.
* A PyO3 surface (REQ-API-2) and `tools/decbench_source_cfg.py`, a shim that
  substitutes `decbench.utils.cfg.extract_cfgs_from_source` and
  `extract_cfgs_from_decompilation` in-process, so DecBench can be run
  end-to-end on our front end with no DecBench change.
* Optionally REQ-API-4, a native `vj_ged`, which turns structural distance into
  a local gate with no external dependency at all.

**Gate — L4, drop-in A/B.** Run `decbench evaluate-tree` twice over the same
materialized tree, once with each provider, and diff `scoreboard.toml` and
`function_results.json`. Expected: identical. Any difference is a finding, with
the function named. This is opt-in and expensive; it is the release gate, not
the iteration gate.

**Gate — estate.** New tests land in `python/tests/` with the existing marks;
the parity lane is `slow` and the DecBench A/B lane is `decbench`, so neither
runs by default. `cargo test --features python-ext` covers the Rust side. Adding
a top-level `src/` module means updating the env-var allowlist in
`test_src_dependency_boundaries.py` and the reviewed-file lists in
`test_large_module_review.py` and `test_stranded_doc_comments.py`; it is not a
module *split*, so the four fixture baselines are untouched.

### Phase 6 — performance

**Deliverable.** `benches/source_cfg.rs` alongside the existing ten criterion
benches.

**Gate.** REQ-PERF-1: 56 cells' worth of CFG extraction in under a minute, and a
median TU under 10 ms. Measure on a release build (`uv run maturin develop
--release`) and write the build next to every number — `maturin develop` is
debug and its profile shares are not the ones shipped.

**Reference point.** The current cost is one JVM per file; the 56-cell matrix
gate is ~37 minutes end to end. Quote the delta as CFG-extraction time, not
whole-gate time, since the rest of the gate is unchanged.

## 4. What "matches" means, in one table

| level | compares | denominator today | localizes? | needs |
|---|---|---|---|---|
| L0 | our normalization vs DecBench's, byte-exact | ~200 lines of pure Python | yes | nothing |
| L1 | our CFG vs Joern's CFG, per construct | §2 fixture corpus | yes | one gated Joern capture |
| L2 | our CFG vs Joern's CFG, per function | published source CFGs + regenerated `.i` | yes | gcc |
| L3 | our GED vs stored GED, per function | 85,645 cells | no | nothing |
| L4 | DecBench scoreboard, provider A/B | whole tree | no | a DecBench run |

L3 is the workhorse: it is the largest, needs nothing, and is the number that
would be quoted. L1 and L2 are what make an L3 failure actionable. L0 is free
and should be written first. L4 is the release gate.

## 5. Risks, and what each would look like

| risk | early signal | response |
|---|---|---|
| CDT error recovery is not reproducible on decompiler C | Phase-1 coverage stalls above the loss target | fall back to `tree-sitter-c`; if that also stalls, stop (Phase 1 stop condition) |
| Short-circuit / ternary shapes diverge | L1 fixtures for `&&`, `||`, `?:` fail while `if` passes | this is the highest-value single fix; three nodes and four edges per operator ride on it |
| Funcend rule mis-implemented | half the corpus's exit flags flip; L3 mismatches cluster on multi-`return` functions | REQ-CFG-10 is precise; test both regimes explicitly |
| Computed `goto` population is larger than assumed | L2 mismatches cluster in parser-generated code (`yyparse`) | measure the population first (REQ open question 2) |
| The oracle itself is wrong | Phase-0 gate fails: pyjoern cannot reproduce stored values | stop and re-plan with budgeted Joern runs |
| Scope creep into a CPG | a "while we're here" AST/DDG appears in review | §8 of [`requirements.md`](requirements.md) is the list of things this component does not do |
| We build something *better* than Joern | L3 mismatches that are all in our favour | a better CFG that scores differently is a regression against this component's purpose; put it behind a non-parity mode |

## 6. What this does not do

It does not change Glaurung's DecBench score. GED is computed from our decompiled
C either way; this replaces the machine that reads it, not the output being
read. The wins are cost (a JVM per file becomes a function call), reliability
(no 1.9 GB bundle, no silent mismatched-jar failure), reach (a structural gate
that can run in the ordinary iteration loop instead of an opt-in 37-minute
lane), and understanding (a metric we can reason about rather than one we submit
to).

It also does not touch the DecBench upstream boundary. Everything here is local
evidence and local code; per CLAUDE.md, no issue, comment or pull request goes
upstream from an agent.
