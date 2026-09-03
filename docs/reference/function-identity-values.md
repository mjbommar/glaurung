# Value fingerprints (the L3 rung)

> **Kind:** reference · **Status:** maintained

**A first slice, implemented and measured, x86-64 only.** Everything below is
in `src/identity/values/`. It is plan item 12 of
[`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md),
following vSim (Wang & Lin, *vSim: Semantics-Aware Value Extraction for
Efficient Binary Code Similarity Analysis*, NDSS 2026,
[paper](https://raw.githubusercontent.com/whj0401/whj0401.github.io/refs/heads/master/files/2026/vSim_NDSS2026.pdf),
[code](https://github.com/OSUSecLab/vSim), DOI 10.14722/ndss.2026.240213).
The plan budgets six to ten weeks for the whole rung; this is the part that
could be measured, and [What the next slice
needs](#what-the-next-slice-needs) says what was left out and what it is worth.

## The idea

Two builds of one function disagree about registers, block order, addresses and
instruction selection. They agree about the numbers the function produces. So:

1. Run the function under bounded execution from a few fixed initial states.
2. Write down every value a register write or a memory store produced.
3. Throw away the ones that are obviously addresses.
4. Normalise the rest to width-free signed integers.
5. Compare two functions by weighted Jaccard over the resulting multisets.

No graph, no model, no training step, and — unlike approximate graph edit
distance — the comparison induces a genuine metric, so it can index a corpus.

vSim is the reason to believe this is worth doing before doing it: it is
explicitly non-ML, beats jTrans and CLAP cross-compiler on the PEM dataset at
pool size 10,000 (Recall@1 0.642 against 0.420 and 0.596), and is *four times
more stable* across BinKit's toolchains (Recall@1 range 0.611-0.711, standard
deviation 0.026, against jTrans's 0.078-0.441 at 0.107).

## The rule table

The left column is what vSim does; the right is what this implementation does.
Where the two differ the reason is stated, because a simplification whose cost
is not written down is indistinguishable from a bug.

### Execution

| | vSim | Here |
|---|---|---|
| Engine | angr, under-constrained symbolic execution over VEX | `src/exec/`, the in-tree **concrete** interpreter over LLIR, unmodified |
| Granularity | one basic block at a time, fresh symbols per block | one whole function per run, following real control flow |
| Trial values | symbolic variables, substituted afterwards with a five-element array `A = [57, 44, 13, 81, 52]` | the substitution happens *during* execution: each run fixes one element of that same array as the value of every uninitialised read |
| Runs per function | one symbolic pass, then `alpha!` evaluations per expression (`alpha <= beta = 6`) | `seeds` concrete runs, three by default |
| Stack | base and stack pointers concretized before the run | identical; `STACK_BASE = 0x7fff_0000_0000` |
| Initial memory | uninitialised except read-only sections | identical: an initialised, read-only image VA reads its real bytes, everything else reads the run's trial scalar |
| Bound | none stated (block granularity bounds it) | `max_steps` retired LLIR instructions per run, 20,000 by default, counted by `exec::Budget`. **No wall clock**, so a fingerprint does not depend on how busy the machine was |
| Calls | replaced by summaries where modelled; the address set is extended with `malloc`-shaped returns | a registered SimProcedure where one exists, otherwise the return register takes a deterministic sentinel keyed on the callee's **external name** (`internal` / `indirect` when there is none). No execution into the callee |
| Unmodelled values | symbolised | `Op::Undef` writes the run's trial scalar instead of poisoning the register, so an unmodelled flag does not stop the run |

### What is recorded

vSim's Table II records the register name and value on a register load or
store, and the address and value on a memory load or store; Algorithm 1 then
keeps only the *stored* values. That is what happens here:

* every instruction's definition, read out of the register file after the step
  (`Op::Load`'s destination included — a load's result is a register store);
* every `Op::Store` / `Op::CondStore` source, read before the step, because a
  store's value cannot be read back afterwards;
* every effective address either kind of access formed, into set `A`;
* branch conditions, separately (element class E2 below).

### Filtering

| Rule | vSim | Here |
|---|---|---|
| F1 | HC1: `v` inside a data section | `v >= ADDRESS_FLOOR` **and** `v` inside any mapped image range |
| F2 | HC2: `v` inside an executable section | folded into F1: `ProgramImage::memory_kind_at` covers both, and the distinction never changes the verdict |
| F3 | HC3: `abs(v - bp) <= eps`, `eps` about 1 GiB | `abs(v - STACK_BASE) <= 1 MiB` — we *choose* the stack pointer, so the window can be the largest plausible frame rather than the largest plausible stack |
| F4 | `v in A`: the run used `v` as an address | identical, over the addresses the concrete run actually formed |
| F5 | HS1/HS2/HS3, over symbolic expression trees | **not implemented.** Concrete execution has no expression trees. F4 subsumes the case that fires most often — a value is a pointer because something dereferenced it |
| F6 | (not needed) | width-1 values are dropped: a flag is 0 or 1 and carries nothing on its own |
| F7 | (not needed) | at most `site_cap` distinct values per instruction site per run, 4 by default |

F6 and F7 have no vSim counterpart because vSim does not need one: it records
branch conditions separately, so flags never enter the value set, and it
executes one basic block at a time, so no loop is ever unrolled. We execute
whole functions, so a loop that runs ten thousand times would otherwise
contribute ten thousand induction values and drown everything else.

**`ADDRESS_FLOOR = 0x10000` is the one deviation that changes results, and it
is not cosmetic.** vSim's corpus is non-PIE executables based at `0x400000`, so
HC1/HC2 never touch a small integer. Our in-house corpus is entirely x86-64 **shared
objects** whose image maps below `0x10000` (the highest function entry in a
fixture is around `0x1800`), and there the unguarded rule deletes
`0`, `1`, `-1`, every structure size and every loop bound — precisely the
population vSim's own ablation says carries the most signal (removing concrete
values costs it 24.2% Recall@1). The floor is the conventional low-address
guard: Linux ships `vm.mmap_min_addr` at 65536, so nothing a loader maps a real
object over. The cost, stated rather than hidden: on the fixture corpus
F1/F2 contribute nothing and the filter is carried by F3 and F4. On Cisco
Dataset-1, whose binaries are executables based at `0x400000`, all four fire.

### Normalisation and the element space

| | vSim | Here |
|---|---|---|
| Concrete values | drop the bit width, read as signed | identical: sign-extend from the producing width to 64 bits, keep the two's-complement bits. A 32-bit `-1` and a 64-bit `-1` become one element, which is what buys 32-to-64-bit matching |
| Symbolic values | normalise the expression tree (drop widths, rewrite `Concat`), then concretize against `A`, sorting the results into a tuple | there is no expression tree: the concretization already happened during execution, so the value *is* the number. One element per run rather than one tuple over all runs |
| Branch conditions | split into `(comparison, constant)`; extend each with equivalent forms **learned** from a held-out project built at several optimisation levels | `(comparison, constant)` read statically off the LLIR, with strict forms folded into non-strict ones over the integers (`x > k` **is** `x >= k+1`). A sound rewrite, so no learned table is needed |
| Variable permutation | up to `alpha!` orderings, because symbolic-variable identity is arbitrary | not needed: every uninitialised read in one run takes the same scalar, so there is nothing to permute |

Two element classes share one `u64` key space:

* **E1, a computed value.** The key *is* the normalised number. A fingerprint is
  readable, which vSim treats as a feature and so does this.
* **E2, a branch condition.** `(kind, constant)` mixed into a high band no small
  integer reaches.

A cross-class collision is a 2^-64 event per pair and costs one spurious shared
element; hashing E1 would cost the ability to read a fingerprint at all.

### Comparison

vSim's Equation 2 is a weighted Jaccard over element **sets**, with
distinguishability weight `W(v) = 1 / ln(Occ(v) + 1)` from a corpus occurrence
table. Both are implemented: `weighted_jaccard_set` is Equation 2 verbatim and
is the default, `weighted_jaccard` is the multiset generalisation
(`sum_v W(v) min(c_A, c_B) / sum_v W(v) max(c_A, c_B)`), which reduces to
Equation 2 when every count is capped at one. `OccurrenceWeights` is vSim's
weight over a document-frequency table; the harness builds one per corpus
(`ValueScheme::prime`), explicitly and before scoring, so no score depends on
the order the driver happened to visit samples in.

`1 - J_w` is the Ruzicka distance: symmetric, zero exactly on equal
fingerprints, and satisfying the triangle inequality, so it is a pseudo-metric
on functions and a metric on their fingerprint classes. `distance(a, b) = 0`
says the two have the same fingerprint — not that they are the same function.

### The version triple

`(major, minor, settings)`, with **every** knob packed into `settings`: the two
flag bits, the role-seed bit, the seed count, the site cap and the step budget.
Two fingerprints whose settings differ answer `0.0` to each other rather than a
low score, because a different filter set is an unanswerable question rather
than a distant function. Scheme name: `glaurung-values-v1`.

## Measured numbers

Every number below is from a **release** run on 2026-09-03, scored by
`tests/identity_retrieval/` — the same driver, the same filtered population,
the same seeded 100-negative draw and the same pessimistic tie rule as every
other scheme in
[Identity measurement](../development/identity-measurement.md). Sampled pool
101 throughout, so chance Recall@1 is 0.0099. The commands are in
[Running it](#running-it).

### In-house fixture matrix

1,787 functions from 206 C sources, two compilers, two optimisation levels,
x86-64 ELF shared objects.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 | R@50 |
|---|---|---|---|---|---|---|---|---|---|
| **XO-gcc** | optimisation | 389 | 410 | **0.9059** | **0.6274** | **0.5219** | 0.7635 | 0.8638 | 0.9640 |
| XO-clang | optimisation | 366 | 377 | 0.8565 | 0.4574 | 0.3634 | 0.5765 | 0.6995 | 0.9344 |
| XC-O0 | compiler | 487 | 494 | 0.9688 | 0.7724 | 0.6797 | 0.9014 | 0.9630 | 0.9979 |
| XC-O2 | compiler | 357 | 377 | 0.9056 | 0.5654 | 0.4706 | 0.6723 | 0.7843 | 0.9692 |
| **XM** | compiler + optimisation | 365 | 377 | **0.8518** | **0.4937** | **0.4055** | 0.5918 | 0.7096 | 0.9397 |
| XM-S | + queries <20 blocks | 308 | 377 | 0.8458 | 0.4830 | 0.4026 | 0.5779 | 0.6916 | 0.9351 |
| XM-M | + queries 20-100 blocks | 54 | 377 | 0.9169 | 0.4909 | 0.3889 | 0.6852 | 0.7407 | 0.9815 |
| XM-L *(underpowered, n=3)* | + queries >100 blocks | 3 | 377 | 0.7233 | 0.6667 | 0.6667 | 0.6667 | 0.6667 | 0.6667 |

### Beside the other rungs, same rows, same run

| | CTPH | `structural` (L1) | `cfr` (L2) | `cfr-normalized` | **`values` (L3)** |
|---|---|---|---|---|---|
| XO-gcc AUC | 0.5015 | 0.7536 | 0.7569 | 0.7583 | **0.9059** |
| XO-gcc MRR10 | 0.0051 | 0.1753 | 0.2543 | 0.2657 | **0.6274** |
| XO-gcc R@1 | 0.0051 | 0.1183 | 0.1799 | 0.2031 | **0.5219** |
| XC-O0 AUC | 0.5020 | 0.9390 | 0.9663 | 0.9663 | **0.9688** |
| XC-O0 R@1 | 0.0062 | 0.4723 | **0.8706** | 0.8624 | 0.6797 |
| XC-O2 AUC | 0.5030 | 0.7238 | 0.8921 | 0.8856 | **0.9056** |
| XC-O2 R@1 | 0.0084 | 0.1709 | 0.5014 | **0.5182** | 0.4706 |
| XM AUC | 0.5025 | 0.7026 | 0.7296 | 0.7329 | **0.8518** |
| XM MRR10 | 0.0058 | 0.1117 | 0.1990 | 0.2120 | **0.4937** |
| XM R@1 | 0.0055 | 0.0685 | 0.1342 | 0.1425 | **0.4055** |

**Reading it.** Three things, and the second is the one that would be easy to
leave out.

1. **It wins where the optimisation level is free, and it wins by a lot.**
   XO-gcc Recall@1 0.5219 against the CFR's 0.1799 — the right function first
   on more than half the lane, where the best graph representation manages one
   in five. XM (both variables free, the hardest task this corpus expresses)
   goes 0.1342 to 0.4055. That is the specific claim vSim makes and it
   reproduces on a different corpus, a different IR and a much simpler engine.
2. **The CFR still wins cross-compiler Recall@1, and by a wide margin.**
   XC-O0 0.8706 against 0.6797. Two compilers at `-O0` build so nearly the same
   *graph* that a canonical form over it is almost exact, and there is no reason
   a value multiset should beat that. These are complementary rungs, not a
   replacement: the values lane owns the optimisation axis and the CFR owns the
   cross-compiler-at-fixed-optimisation axis. Anything that quoted only the
   rows where this scheme wins would be choosing its evidence.
3. **AUC and ranking do not move together.** XM-M has the highest AUC of the
   XM strata (0.9169) and the *lowest* MRR10 (0.4909). Marcelli warns about
   exactly this, and it is why both are in the table.

### Cisco Talos Dataset-1, x86-64 lanes

Marcelli's corpus, so these rows sit beside published tables. **The three
lanes below are the only ones this scheme can run**: `fingerprints_for_path`
refuses a non-x86-64 image, so XB (x86), XA-arm64, XA-mips64, XA+XB-arm32,
XA+XB-mips32 and XA+XO all fail extraction on every pool sample — 228 to 279
failures each, asserted in `cisco_values_x86_64_lanes` rather than quietly
omitted. Why: `glaurung::exec::Machine::new` builds an **x86-64 register
file**, and running ARM or MIPS through it would read every register as zero
and return a fingerprint that looked like a measurement.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 |
|---|---|---|---|---|---|---|---|---|
| XO | optimisation | 50 | 229 | 0.9569 | 0.8440 | 0.8000 | 0.9000 | 0.9200 |
| XC | compiler | 65 | 348 | 0.9368 | 0.8348 | 0.7846 | 0.9077 | 0.9385 |
| XM | compiler + optimisation | 36 | 262 | 0.9516 | 0.8375 | 0.7500 | 1.0000 | 1.0000 |

Read the `Scored` column before the accuracies. Fifty, sixty-five and
thirty-six queries are above the harness's 30-query floor for quoting a row
and a long way below the point at which a difference of a few points means
anything; the numbers are higher than the in-house corpus's mostly because
Dataset-1's shared functions are larger.

### Cost and coverage

Measured over the in-house corpus, release build, on a shared machine.

| | |
|---|---|
| Extraction, cold, whole images | **732 to 766 us/function** (three runs; the per-scheme report line ranged 709 to 986 us on the same box, which is machine load, not the scheme) |
| ...in the same release process, for comparison | `structural` **220 us**, CTPH **65 us**, `cfr` **4,088 us**, `cfr-normalized` **4,656 us** |
| Instructions retired per function | **2,046**, summed over all three seeds |
| Runs that hit the 20,000-instruction budget | **1.44%** |
| Functions whose runs all hit the budget *before producing any value* | **0.00%** (0 of 1,787) |
| Harvested values the address rules removed | **14.01%** |
| Extraction on Cisco Dataset-1 | 12,129 us/function over 2,441 samples — Dataset-1's images are whole programs, and the per-image cost is amortised over far fewer sampled functions |

**Bounded execution is five and a half times cheaper than the CFR here**, in
the same process on the same rows -- 738 us against 4,088 us -- and inside
TikNib's published 20 to 1,030 us band. That is not the result the words "run
the function" predict, and the reason is that the CFR pays for SSA
construction and three Weisfeiler-Lehman iterations over a whole-image graph
while this pays for about two thousand interpreted instructions. It does mean
the L3 rung is not the expensive one, which inverts the cost ordering the plan
document assumed.

One number in the JSON reports is **not** a measurement and should not be
quoted: `values-weighted` records 0.5 us/function, because the weighted
configuration is primed over the whole corpus before it is scored and its
cache is therefore warm when the driver times it. `ValueScheme::prime` is a
no-op for the unweighted configurations precisely so that theirs are real.

### Ablations

Every row is the same corpus, the same driver and the same negatives; only the
setting named changes. Recall@1 on the five powered lanes.

| Configuration | XO-gcc | XO-clang | XC-O0 | XC-O2 | XM | Mean delta vs default |
|---|---|---|---|---|---|---|
| **default** | 0.5219 | 0.3634 | 0.6797 | 0.4706 | 0.4055 | — |
| filter off (F1-F4) | 0.5039 | 0.3415 | 0.6940 | 0.4762 | 0.3808 | **-0.0089** |
| branch conditions off (E2) | 0.4936 | 0.3534 | 0.6715 | 0.4482 | 0.3626 | -0.0224 |
| multiset Jaccard (counts) | 0.2596 | 0.2077 | 0.7495 | 0.5014 | 0.2082 | -0.1029 |
| corpus DF weights | 0.5193 | 0.3579 | 0.6715 | 0.4538 | 0.4055 | -0.0066 |
| role-keyed seeds | 0.4550 | 0.3224 | 0.6940 | 0.4314 | 0.3342 | -0.0408 |
| 1 seed | 0.3085 | 0.1967 | 0.4497 | 0.3249 | 0.2521 | -0.1818 |
| 5 seeds | 0.5090 | 0.3716 | 0.6817 | 0.4678 | 0.4027 | -0.0017 |
| site cap 1 | 0.2776 | 0.2131 | 0.4415 | 0.3417 | 0.2356 | -0.1863 |

**The filter is worth 0.009 Recall@1 here, and vSim reports 0.09.** The order
of magnitude is the deviation documented above, not a disagreement about the
rule. The whole in-house corpus is shared objects whose image maps below
`ADDRESS_FLOOR`, so F1 and F2 fire on nothing there and the ablation is
really measuring F3 and F4 alone. Those two still remove **14.01%** of
harvested values, so the ablation is not vacuous — it is a smaller filter than
the one vSim measured. The sign also flips on the two cross-compiler lanes
(XC-O0 -0.0143, XC-O2 -0.0056 in the filter's favour becoming *against* it),
which is recorded because it is real: at a fixed optimisation level the stack
offsets two compilers pick are themselves a weak signal, and F3 deletes it.
vSim's other reported cost of dropping the filter — 2.8x the comparison time —
does not appear here at all: extraction reads 709 us filtered against 713
unfiltered, within the run-to-run noise.

**Three seeds is the knee.** One seed costs 0.18 Recall@1; five buys nothing
(-0.0017, i.e. noise) for 30% more extraction time. Three is the default for
that reason and not by analogy with vSim's five-element array.

**The set form is right and the multiset form is not — except cross-compiler.**
Capping counts at one (vSim's Equation 2) beats the count-weighted
generalisation by 0.10 Recall@1 on average, and loses to it by 0.07 on XC-O0
and 0.03 on XC-O2. Optimisation changes how many times a value is produced
(unrolling, duplication, CSE) far more than it changes which values are
produced; a compiler swap at fixed `-O` does not. Both forms ship
(`weighted_jaccard_set`, `weighted_jaccard`); the set form is the default.

**The corpus weighting does not earn its place yet.** vSim's
`W(v) = 1 / ln(Occ(v) + 1)` is implemented (`OccurrenceWeights`) and measures
*worse* on four of the five powered lanes and ties on the fifth — AUC 0.9059
to 0.8869 on XO-gcc, Recall@1 0.5219 to 0.5193, mean -0.0066. A
document-frequency table is only as good as the corpus it came from, and 1,787 functions from 206 sources is a corpus in which a genuinely rare
value and a value seen once by accident are indistinguishable. It is reported
rather than adopted, and it is the first thing to re-measure when a larger
corpus exists.

**Role-keyed seeds lose.** Giving each uninitialised register its own trial
value raises AUC slightly (0.9059 to 0.9103 on XO-gcc) and costs 0.04
Recall@1, with XM-M collapsing from 0.9169 AUC to 0.7131. It makes the
fingerprint depend on two builds agreeing about register allocation, which is
the thing the representation exists to be blind to. Off by default.

## What the next slice needs

Stated here rather than discovered later.

1. **Callee-to-caller propagation.** vSim's largest omission from this slice,
   and its ablation puts it at 0.08 Recall@1 — the same order as the whole
   filter. It unions a callee's fingerprint into its caller's, to depth
   `gamma = 3`, which is what makes the representation survive differential
   inlining (the field's unsolved failure mode: roughly 82 to 84 per cent of
   failures in the best tools involve it). It needs a call graph and a bounded
   fixpoint over it, neither of which this slice has.
2. **AArch64 and the other architectures.**
   `glaurung::exec::Machine::new_with_arch` already takes `RegArch::AArch64`, so the interpreter is not the blocker;
   what is missing is the seeded-register list in `seeds.rs`, a return-register
   choice per ABI, and the decision about whether one fingerprint should be
   comparable across architectures at all (the width-free normal form says it
   could be). MIPS and PowerPC have no lifter, so they are out regardless.
3. **F5, the symbolic address rules.** They need expression provenance, which
   means either a symbolic domain (`src/symbolic/` has one behind the `symbolic`
   feature) or a taint bit threaded through the concrete run. The second is
   cheap and would recover the "a pointer that was computed but never
   dereferenced" case F4 misses.
4. **An inverted index.** Retrieval here is a flat scan, which the protocol
   document says is right below about 1e5 vectors and wrong above it. The
   element space is `u64` and rare elements are exactly what carries the
   signal, so the rare-element inverted index the CFR lane needs is the same
   index.

## Running it

```bash
# The unit tests: hand-built LLIR whose values are known by hand.
cargo test --features python-ext identity::values

# The retrieval numbers, in the harness that scores every identity scheme.
cargo test --release --features exec --test identity_retrieval values

# The full sweep -- every configuration, the ablation, the cost. Minutes.
cargo test --release --features exec --test identity_retrieval \
  values_full_sweep -- --ignored --nocapture
```

From Python:

```python
import glaurung as g

rows = g.analysis.value_fingerprints_path("libmathlib.so")
left, right = rows[0], rows[1]
print(left.digest, left.values[:8])
print(g.analysis.value_similarity(left, right))
```

## See also

* [Identity measurement](../development/identity-measurement.md) — the
  protocol, the filters, and every scheme's numbers side by side.
* [The Canonical Function Representation](function-identity-cfr.md) — the L2
  rung, the scheme this one is measured against.
* [Structural function identity](function-identity-structural.md) — L1.
* [WARP function GUIDs](function-identity-warp.md) — L0.
