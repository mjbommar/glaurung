# Interpreting a DecBench result

> **Kind:** design · **Status:** maintained
>
> Every figure measured 2026-09-04 against the published corpus.

Every number below was computed offline from the published corpus at
`~/.cache/glaurung/decbench-full/`, and every one names the command or the tool
that produced it. Nothing here required a Joern run or a DecBench pipeline run.

The short version: **DecBench's headline scores are dominated by trivial
functions and by who chose to attempt them.** A reader who takes a
`perfect_percentage` at face value will rank a stub above Ghidra and an
LLM that attempted 0.3% of the corpus above every full-coverage decompiler.
Both of those happen in the published data, not in a hypothetical.

## 1. The null baseline: a stub scores 27.24%

A "decompiler" emitting `int f(void) { return 0; }` for every function is
**27.24% GED-perfect** — above Ghidra (25.52%) and Binary Ninja (20.58%).

24,243 of 89,014 scorable functions have a one-node CFG, and `return 0;`
parses to exactly that shape (one node, zero edges, entry and exit both set).
Our own parity layer confirms the shape; the count is a property of the corpus.

| decompiler | perfect % | skill |
|---|---:|---:|
| kuna | 37.02 | +0.134 |
| ida | 36.61 | +0.129 |
| angr | 34.74 | +0.103 |
| **null (`return 0;`)** | **27.24** | **0** |
| ghidra | 25.52 | −0.024 |
| binja | 20.58 | −0.091 |
| r2dec | 17.42 | −0.135 |
| phoenix | 9.42 | −0.245 |
| dewolf | 3.15 | −0.331 |

`skill = (perfect% − null%) / (100% − null%)`, so a negative skill means the
column is beaten by the stub. Only three of thirteen columns clear the floor.

```bash
uv run python tools/metric_stratify.py \
  ~/.cache/glaurung/decbench-full/published_function_results.json \
  --tree ~/.cache/glaurung/decbench-full/tree
```

The tool derives the null from whatever corpus it is pointed at rather than
hard-coding 27.24%, so the floor moves with the data.

## 2. Where the points come from: stratify or be misled

The null scores **100% in the one-node band and 0% in every other band**. So
every point a real column earns above the floor is earned on functions with
control flow — and there the rates collapse.

| band (nodes) | N | null % | best column |
|---|---:|---:|---:|
| 1 | 24,249 | 100.0 | 86.7 (angr) |
| 2–3 | 11,386 | 0.0 | 42.9 (kuna) |
| 4–7 | 18,544 | 0.0 | 25.9 (ida) |
| 8–15 | 17,138 | 0.0 | 13.4 (ida) |
| 16–31 | 10,406 | 0.0 | 5.4 (ida) |
| 32–60 | 4,471 | 0.0 | 2.1 (ida) |
| >60 | 2,820 | 0.0 | 1.5 (kuna) |

62.5%–100% of every column's perfect cells come from the one-node band. All
2,808 of dewolf's perfect cells are branchless functions.

## 3. Own-denominator scoring rewards not attempting

Scored against only what it attempted, **claude-code is first of thirteen at
55.37% and codex second at 53.91%** — above every full-coverage decompiler.
They attempted **242 and 243 of 89,014 functions** (0.3% coverage).

On the population everyone else is judged on, both sit ninth and tenth at
0.15%, skill −0.372 — decisively below the stub.

| column | scored | coverage | own % | shared % |
|---|---:|---:|---:|---:|
| claude-code | 242 | 0.3% | 55.37 | 0.15 |
| codex | 243 | 0.3% | 53.91 | 0.15 |
| ida | 81,900 | 92.0% | 39.79 | 36.61 |
| ghidra | 72,961 | 82.0% | 31.13 | 25.52 |

Any comparison across columns must state which denominator it used.

## 4. `type_match` has the same weakness, and it is larger

Measured over real DWARF from 321 functions across 30 fixture binaries, scored
by DecBench's own `TypeMatchMetric`:

| synthetic backend | mean | perfect functions |
|---|---:|---:|
| width-echo (`undefinedN` at the right slot) | 0.9051 | **236/321 = 73.5%** |
| everything typed `int` | 0.8110 | 193/321 = 60.1% |
| everything typed `undefined8` | 0.0582 | 12/321 = 3.7% |

**A backend that recovers no type at all — only each slot's width — is scored
perfect on 73.5% of functions by a metric named "Type Correctness."** Causes:
89.2% of the ground-truth variable population is integer or bool scalars
(pointers 9.9%, aggregates 1.0%), and 52% of functions have two or fewer
ground-truth variables, so most denominators are 1 or 2.

## 5. `type_match` is recall, not a Jaccard — extra variables are free

`tp + fp + fn` is identically `len(ground_truth_vars)`: the reference builds a
`decided` array indexed by ground-truth variable, and a decompiled variable
that corresponds to nothing is never counted in any of the three. Verified
across **10,272 differential cases, 10,272 of 10,272**.

The only cost of inventing a variable is indirect — it can *collide* on ABI
index, stack offset or name and shadow a real one, turning a true positive into
a false positive. Placed anywhere unoccupied it does not move the score.

The inventory row that called this "a Jaccard over variables, so spurious extra
variables cost you" has been corrected.

## 6. GED does not detect semantic defects

`tools/metric_mutation.py` injects defects and measures whether the metric
notices. Restricting to the ten mutation classes that cannot change the CFG by
construction:

* **12 detected of 1,188** on published sources
* **0 detected of 2,817** on decompiled output

Flipped comparisons, wrong constants, broken arithmetic, swapped arguments —
invisible. The 12 detections are all `logic-flip`, where `&&` → `||` changes
the short-circuit block count, so GED is reacting to the *syntax* of the
condition rather than the semantics of the defect.

Overall on 285 published functions: **sensitivity 21.8%, specificity 95.3%**
(20.5% / 99.2% on 1,500 of our own decompiled outputs).

Two specific behaviours worth knowing:

* **goto-ification is free.** Replacing a `while` with a label and a
  conditional `goto` leaves the CFG byte-identical: 30/30 undetected on our
  corpus. `docs/development/traps.md` records the same fact from the execution
  side — goto soup passes every fixture.
* **Duplicating a join block is a false alarm 60–64% of the time.** Real
  structuring algorithms do this; GED charges a median of 5.0 for it.

## 7. Two mechanical traps in the metric itself

**The clamp.** The stored cell is
`decbench.metrics.ged.GEDMetric._compute_uncached`, which is three steps:
isomorphism fast path → 0.0; above `GED_MAX_NODES` (200) →
`max(1.0, |Δnodes| + |Δedges|)`; otherwise `max(1.0, vj_ged(...))`. A
non-isomorphic pair can therefore never be stored as 0, while bare `vj_ged`
returns 0 whenever the degree multisets agree. Comparing against bare `vj_ged`
instead of the recorded semantics cost us **eleven percentage points** of
apparent disagreement before we noticed.

**You can be penalised for being right.** In 42 cells our CFG is
role-isomorphic to the published *source* CFG where Joern's CFG of the
decompiled text was not. We score 0; the floor stores 1.0; we are marked wrong
for having recovered the original shape.

## 8. What `vj_ged` reads, and what that costs

The distance reads exactly four things per node: in-degree, out-degree,
`is_entrypoint`, `is_exitpoint`. Statements, types, operators and identifiers
never reach it. Two structurally different graphs with the same degree
multiset score 0.

A consequence worth recording as a negative result: **1-WL colour refinement is
complete on this corpus.** Over the non-degenerate published CFGs it yields
8,034 classes, and VF2 isomorphism inside every bucket yields the same 8,034.
A Weisfeiler-Lehman kernel would therefore distinguish nothing the existing
isomorphism check does not — graph kernels are not the upgrade path.

## 9. Coverage and cost against Joern

Comparing, per binary, the function names Joern published against those our
front end recovers from the stored decompiled C — 785 binaries, 90,092
functions:

```
both recover        88,162   97.86%
only we recover      1,880    2.09%
only Joern recovers     50    0.06%
```

Of the 1,880, only 64 are translation-unit resolution artifacts; **1,816 appear
in no published CFG anywhere in their project** — real functions, including
bash's `_rl_timeout_handle`, `rl_get_char` and `ibuffer_space`.

**Read that as coverage breadth, not as Joern failing.** The two sides parse
different inputs — Joern the original `.i`, us the decompiled C — so a
difference can be inlining, static merging, or decompiler naming. Joern
produced a CFG for **all 91,548** published functions, none empty, 2.77%
degenerate. It is not crashing on this corpus.

Cost, release build, single process, single thread:

```
files      1,606
functions  188,716
input      415.1 MB of C
wall       17.91 s   (11.2 ms/file, 95 us/function)
throughput 23.2 MB/s
```

Against a JVM launch per file, and a 56-cell gate recorded at 6:28 wall /
5,078 user CPU-seconds on eight workers. Per cell that is ~90.7 CPU-seconds
against ~0.022 s — **three to four orders of magnitude**, and deliberately not
quoted more precisely than that: the 56-cell figure includes decompilation and
scoring as well as Joern, the files-per-cell ratio is assumed rather than
measured, and the two runs are over different corpora. An exact figure needs a
sanctioned side-by-side Joern run.

The defensible claim needs no ratio: **95 µs/function runs inside an edit loop;
a JVM launch per file does not.**

## 10. A checklist for reading any DecBench number

1. **What does the null score on this population?** If it is not published
   beside the result, the result is uninterpretable.
2. **Own denominator or shared population?** The two orderings disagree
   violently, and the own-denominator one rewards attempting less.
3. **What is the size distribution?** Every per-band rate is far below the
   headline; a single aggregate hides that the metric is mostly scoring
   one-node functions.
4. **Is this `perfect_percentage` or a distance?** Perfect-rate is an
   indicator over a threshold and discards all magnitude information.
5. **For `type_match`, how many ground-truth variables?** At one or two
   variables per function the score is nearly binary.
6. **Was the comparison against the stored semantics or bare `vj_ged`?** They
   differ by the clamp and the isomorphism path.

## Where our own numbers stand

For completeness, since these are easily confused with the published
`glaurung` column (which is a stale 240-function submission at 0.08%): our
native parity layer scores **79,790 of 85,645 stored cells exact (93.1636%)
with zero coverage loss**, and our GED implementation agrees with the live
reference on **12,713 of 12,713** comparable pairs.

## Related

* [`what-ged-measures.md`](what-ged-measures.md) — the full audit this
  summarizes, with the per-column derivations.
* [`calibration.md`](calibration.md) — the mutation catalogue and its contract.
* [`evidence.md`](evidence.md) — every scratch script, verbatim, with command
  lines and raw output.
* [`../static-c-analysis/parity-plan.md`](../static-c-analysis/parity-plan.md)
  §3 — the parity measurements and the remaining-gap analysis.
