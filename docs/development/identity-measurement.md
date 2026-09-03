# Measuring function identity

> **Kind:** guide · **Status:** maintained

> **Shipped harness, measured numbers.** Every figure on this page was
> read off a run on 2026-09-02 and is pinned as a ratchet in the test that
> produced it. This is plan items 1 and 9 of
> [`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md)
> — the measurement harness the four identity schemes (WARP GUIDs, L1
> structural invariants, the CFR feature vector, L3 value fingerprints) are
> ranked against, over **two corpora**: the matched-build fixture matrix, and
> Cisco Talos Dataset-1, which supplies the cross-architecture and
> cross-bitness lanes the fixture matrix cannot express and puts our rows
> beside Marcelli's published tables. Jump to
> [Cisco Dataset-1](#cisco-dataset-1) for the second.

## Why this exists

Four function-identity schemes are being built. Nothing can rank them, or say
whether any of them beats what already ships, without a protocol that produces
comparable numbers — and the protocol document is blunt about the cost of not
having one:

> No number from this work is comparable to anything unless it states the pool
> size and the set of free compilation variables. The same tool, SAFE, scores
> MRR 0.918 and 0.17 in two published papers on different protocols.

So this harness scores every scheme the same way over the same filtered
population, and no result can be printed or serialised without its pool size
and its free-variable set attached.

Three schemes are scored below, and the three results say different things.
**CTPH** (`glaurung::similarity`, the byte digest) is at chance on every task.
**The Python structural fingerprint**
(`python/glaurung/llm/kb/structural_fingerprint.py`) reaches AUC 0.73 and MRR10
0.22 cross-compiler — which is the FunctionSimSearch band the literature
predicts for its representation class — and collapses to chance the moment the
optimisation level is also free. **`structural`** (`glaurung::identity::structural`,
the L1 rung, plan item 2) reaches AUC 0.94 cross-compiler, does **not**
collapse when both the compiler and the optimisation level are free (AUC
0.70), and reaches AUC 0.95 across an architecture change on Dataset-1 —
clearing every other scheme's cross-architecture floor by a wide margin. All
three results are below.

## The protocol

### Corpus

`tests/decompiler_fixtures/build/` — 206 C sources, two compilers (`gcc`,
`clang`), two optimisation levels that keep a symbol table (`O0`, `O2`),
x86-64 ELF shared objects. That makes `(fixture stem, symbol name)` an exact,
free ground-truth key.

The directory is **gitignored** (it is produced by the fixture harness, ~40
minutes), so both harnesses resolve it in this order:

1. `GLAURUNG_IDENTITY_CORPUS` — a path to a populated build directory. This is
   how an agent worktree, or any second checkout, points at one that exists.
2. `<repo>/tests/decompiler_fixtures/build`.

When neither is populated the harnesses **skip loudly** — a printed reason on
the Rust side, a `pytest.skip` with the same text on the Python side. Neither
passes vacuously.

`GLAURUNG_IDENTITY_CORPUS` is read from `tests/` and `python/tests/`, never
from `src/`, so it is outside the env-var allowlist
`python/tests/test_src_dependency_boundaries.py` enforces over the product
tree. It is documented here instead, which is the whole of its registration.

### Ground truth and the published filters

Two functions are the same iff they have the same fixture source and the same
symbol name. Before anything is counted, the filters Marcelli et al.
(USENIX'22) and TikNib apply are applied here, because a number computed
without them is not comparable to a published one — and a number computed
*with* them is not comparable to one computed without.

Measured on 2026-09-02, Rust lane, all four slices:

| Filter | Removed | Note |
|---|---|---|
| Zero-sized text symbols (skipped before `considered`) | 5,702 | Where the CRT boilerplate actually goes: gcc and clang emit `frame_dummy`, `register_tm_clones`, `_init` with `st_size == 0` |
| Considered after that | **4,017** | Sized, named text symbols across the four slices |
| Not in `.text` | 0 | Single-translation-unit shared objects; nothing lands elsewhere |
| PLT / thunk / CRT name | 0 | ELF `.symtab` carries no `@plt` names — that spelling is objdump's and IDA's — and the CRT symbols were already skipped as unsized |
| No CFG body discovered | 12 | |
| Fewer than **5 basic blocks** | **2,218** | The dominant filter, as in the literature |
| Duplicate `(name, normalized instruction hash)` | 0 | 206 distinct sources; few identical helpers survive the 5-block floor |
| **Kept** | **1,787** | gcc/O0 506, gcc/O2 410, clang/O0 494, clang/O2 377 |

Two of those zeroes deserve their own line, because a filter that removes
nothing looks exactly like a filter that is not running. Both the `.text` rule
and the PLT/CRT rule have **direct unit tests**
(`corpus::tests::plt_and_crt_names_are_recognised`,
`test_filter_predicates_match_the_rust_harness`) so their zero here is evidence
about the corpus rather than about the code. They exist because the harness is
meant to take a linked multi-object binary later, where all three signals fire.

The "normalized instruction hash" is FNV-1a over the function's **mnemonic
sequence** (a linear sweep through the architecture's disassembler, operands
discarded) on the Rust side, and the structural fingerprint itself — which is
already a hash of normalized instruction tokens plus the CFG — on the Python
side.

### Tasks

Marcelli's taxonomy, restricted to the free variables this corpus has.

| Task | Query | Pool | Free variables |
|---|---|---|---|
| XO-gcc | gcc/O0 | gcc/O2 | optimisation |
| XO-clang | clang/O0 | clang/O2 | optimisation |
| XC-O0 | gcc/O0 | clang/O0 | compiler |
| XC-O2 | gcc/O2 | clang/O2 | compiler |
| XM | gcc/O0 | clang/O2 | compiler + optimisation |
| XM-S | gcc/O0 | clang/O2 | compiler + optimisation, queries <20 blocks |
| XM-M | gcc/O0 | clang/O2 | compiler + optimisation, queries 20-100 blocks |
| XM-L | gcc/O0 | clang/O2 | compiler + optimisation, queries >100 blocks |

**Tasks this corpus cannot express**, recorded in every JSON report so their
absence is a stated gap: **XA** (cross-architecture), **XB** (cross-bitness),
**XC+XB**, **XA+XO**, and BinKit's **NoInline** lane. All but NoInline now run
on a *second* corpus — see [Cisco Dataset-1](#cisco-dataset-1) below, which
varies architecture, bitness, compiler, compiler version and optimisation. The
`dectest --arch` matrix (i386, armv7, aarch64) builds the same 206 sources for
other targets and remains the cheapest route to an in-house XA/XB lane if one
is wanted.

### Negative sampling

100 negatives per positive, so the ranked pool is 101 and chance Recall@1 is
1/101 = 0.0099.

Negatives are drawn from the **task's own pool slice**, which makes Marcelli's
discipline ("in XO, the negative shares the architecture") structural rather
than a rule someone has to remember: a cross-optimisation negative necessarily
shares the compiler, a cross-compiler negative necessarily shares the
optimisation level, and there is no code path that can draw one from anywhere
else. Every candidate sharing the query's label is excluded.

The PRNG is **SplitMix64** (Steele, Lea and Flood, 2014) seeded from the
constant `0x9E3779B97F4A7C15` mixed with the task name and the query's index in
the sorted query list. It is eight lines, has no dependency, and produces the
same stream on every platform — none of which is true of `std::hash::RandomState`
or a thread RNG. Both harnesses pin the first four values of the stream against
an independent implementation, so they cannot agree on the seed while
disagreeing on the generator and silently draw different negatives.

### Metrics

* **AUC** over positive and negative pairs, as the Mann-Whitney U statistic
  with mid-ranks for ties. 0.5 is chance.
* **MRR10** and **Recall@1** over the 101-candidate sampled pool.
* **Recall@k** for k in {1, 5, 10, 50}. Marcelli shows models that tie on AUC
  diverge sharply on ranking, so the curve is reported, not only `@1`.
* **A global-pool lane**: the same query ranked against the *entire* pool
  slice (377-494 candidates here), with its own chance line.
* **Extraction cost** in microseconds per function, with the build profile
  named. TikNib is 20-1030 us; a design that cannot hit that order is not
  usable for a 6,000-function kernel diff.

**Ties are resolved pessimistically**: a candidate scoring exactly what the
true twin scores is counted as ranking *ahead* of it. This is stricter than
`tests/similarity_retrieval.rs`, which sorts the pool and keeps the first
candidate on a tie — under that rule a scheme scoring every pair 0.0 lands at
chance, which credits it with luck it does not have. Under the rule here it
lands at zero. The chance line is printed next to every result so the two can
be read together.

**Rows with fewer than 30 scored queries are flagged `[UNDERPOWERED]`** and
must not be quoted. `XM-L` has 3. Its Recall@1 can only be 0, 1/3, 2/3 or 1;
that is not a measurement, and printing it without saying so is how a harness
manufactures a result.

## Running it

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"

# --- Rust: the schemes over glaurung's own API. ~13s including corpus load.
cargo test --features python-ext --test identity_retrieval

# From a worktree or any checkout whose build directory is empty:
GLAURUNG_IDENTITY_CORPUS=/path/to/tests/decompiler_fixtures/build \
  cargo test --features python-ext --test identity_retrieval

# Both corpora, so the XA and XB lanes run too. ~62s.
GLAURUNG_IDENTITY_CORPUS=/path/to/tests/decompiler_fixtures/build \
GLAURUNG_CISCO_CORPUS="$HOME/.cache/glaurung/corpora/cisco-talos-dataset1" \
  cargo test --features python-ext --test identity_retrieval

# Every task's every number, no ratchet in the way, markdown rows for the
# table below. Use this when a scheme lands or a ratchet fires.
cargo test --features python-ext --test identity_retrieval -- --ignored --nocapture

# The CFR lanes specifically, with the weighted-vs-unweighted delta table.
# Note the profile: `cfr` extraction is 1,810 us/function in release and
# 12,004 in debug, so a full sweep is minutes either way -- but the retrieval
# numbers are bit-identical, so measure in release and gate in debug.
cargo test --release --features python-ext --test identity_retrieval -- \
  --ignored --nocapture cfr_full_sweep
GLAURUNG_CISCO_CORPUS=... cargo test --release --features python-ext \
  --test identity_retrieval -- --ignored --nocapture cisco_cfr_full_sweep

# --- Python: the production structural fingerprint. ~70s, `slow`-marked.
uv run pytest python/tests/test_identity_retrieval_protocol.py -q
```

Both write a JSON report to `target/identity-eval/<scheme>.json`
(`CARGO_TARGET_DIR` is honoured) carrying the filter counts, the slice sizes,
the sampling parameters, the build profile, the per-task numbers, and the list
of unsupported tasks. `test_python_and_rust_harnesses_agree_on_the_corpus`
reads the Rust report when it is present and fails if the two populations have
drifted more than 25% apart — the rules are implemented twice, in two
languages, and two harnesses quietly filtering different populations produce
two uncomparable sets of numbers while both look correct.

## Results

### CTPH — `glaurung::similarity`, byte-level context-triggered piecewise hash

Rust lane, 2026-09-02, debug profile, extraction **41.2 us/function** over
1,787 samples. Sampled pool 101 (chance R@1 0.0099) throughout.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 (chance) |
|---|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | optimisation | 389 | 410 | 0.5015 | 0.0051 | 0.0051 | 0.0051 | 0.0051 | 0.0051 | 0.0051 (0.0024) |
| XO-clang | optimisation | 366 | 377 | 0.5029 | 0.0091 | 0.0082 | 0.0109 | 0.0109 | 0.0109 | 0.0082 (0.0027) |
| XC-O0 | compiler | 487 | 494 | 0.5020 | 0.0066 | 0.0062 | 0.0082 | 0.0082 | 0.0082 | 0.0041 (0.0020) |
| XC-O2 | compiler | 357 | 377 | 0.5030 | 0.0084 | 0.0084 | 0.0084 | 0.0084 | 0.0084 | 0.0056 (0.0027) |
| XM | compiler + optimisation | 365 | 377 | 0.5025 | 0.0058 | 0.0055 | 0.0055 | 0.0082 | 0.0082 | 0.0055 (0.0027) |
| XM-S | + queries <20 blocks | 308 | 377 | 0.4999 | 0.0004 | 0.0000 | 0.0000 | 0.0032 | 0.0032 | 0.0000 (0.0027) |
| XM-M | + queries 20-100 blocks | 54 | 377 | 0.5181 | 0.0370 | 0.0370 | 0.0370 | 0.0370 | 0.0370 | 0.0370 (0.0027) |
| XM-L *(underpowered, n=3)* | + queries >100 blocks | 3 | 377 | 0.4867 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 (0.0027) |

**Reading it.** AUC is 0.50 on every powered row: CTPH is at chance. The mean
positive pair scores 0.0003 and the mean negative 0.0001 — at function
granularity two digests essentially never share a block, whether or not they
are the same function. Note also that XM (0.5025) is *not* worse than XO
(0.5015): the digest carries so little that neither transformation can make it
carry less.

This is the published behaviour of the representation class, not a defect in
`ctph_hash`, and it is the reason the protocol document says byte digests keep
exactly one role — file-level near-duplicates — and must not be extended to
functions.

### Python structural fingerprint — `llm/kb/structural_fingerprint.py`

Python lane, 2026-09-02, extraction **25.5 ms/function** over 1,786 samples.
Corpus: considered 11,514 -> kept 1,786 (dropped: plt/thunk/crt 4,944, <5
blocks 4,784, duplicate 0); gcc/O0 504, gcc/O2 409, clang/O0 494, clang/O2 379.
Sampled pool 101 (chance R@1 0.0099) throughout.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 (chance) |
|---|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | optimisation | 389 | 409 | 0.5825 | 0.0670 | 0.0257 | 0.1080 | 0.1954 | 0.4139 | 0.0154 (0.0024) |
| XO-clang | optimisation | 366 | 379 | 0.5278 | 0.0433 | 0.0273 | 0.0683 | 0.0929 | 0.1585 | 0.0109 (0.0026) |
| **XC-O0** | compiler | 485 | 494 | **0.7296** | **0.2404** | 0.1753 | 0.3381 | 0.4082 | 0.7381 | 0.0804 (0.0020) |
| **XC-O2** | compiler | 356 | 379 | **0.7287** | **0.2241** | 0.1573 | 0.3146 | 0.4270 | 0.7444 | 0.0815 (0.0026) |
| XM | compiler + optimisation | 364 | 379 | 0.5150 | 0.0357 | 0.0165 | 0.0549 | 0.1016 | 0.1593 | 0.0110 (0.0026) |
| XM-S | + queries <20 blocks | 307 | 379 | 0.5007 | 0.0240 | 0.0098 | 0.0423 | 0.0684 | 0.1238 | 0.0065 (0.0026) |
| XM-M | + queries 20-100 blocks | 54 | 379 | 0.5934 | 0.0852 | 0.0556 | 0.1481 | 0.2037 | 0.3519 | 0.0370 (0.0026) |
| XM-L *(underpowered, n=3)* | + queries >100 blocks | 3 | 379 | 0.5844 | 0.0833 | 0.0000 | 0.3333 | 0.3333 | 0.3333 | 0.0000 (0.0026) |

**Reading it.** Three things worth taking away.

1. **It reverses the intuition the corpus was built with.** Swapping
   *compilers* at a fixed optimisation level is far easier for this
   fingerprint (AUC 0.73, MRR10 0.22) than swapping *optimisation levels* with
   the compiler fixed (0.58 / 0.53). The token normalization was designed to
   survive register reallocation and address shifts, and it does; it does not
   survive what `-O2` does to the block structure. `tests/similarity_retrieval.rs`
   records CTPH treating the two transformations as equally cheap, but for the
   opposite reason — it carries nothing either way.

2. **MRR10 0.22-0.24 lands right in the FunctionSimSearch band** the protocol
   document names as this representation class's published ceiling (0.26).
   That is a useful independent check that the harness is measuring what it
   claims to, on a corpus and an implementation neither the band nor the
   harness was fitted to.

3. **It collapses when both variables are free.** XM AUC 0.515, essentially
   chance. This is exactly the collapse-with-multiple-free-variables the
   independent evaluations report for token-level representations, and it is
   the specific gap the CFR is meant to close.

The **cost** is the other finding: 25.5 ms/function against TikNib's 0.02-1.03
ms, twenty-five times the top of the published band. It is structural, not
incidental — `structural_fingerprint` takes its slow path on ELF
(`build_va_table` is PE-only and returns `[]`, so `fast_path` is `False`) and
calls `disassemble_window_at(path, ...)` **per basic block**, re-reading the
file off disk every time. Anything that wants this fingerprint at corpus scale
has to fix that first.

### structural — `glaurung::identity::structural`, L1 CFG invariants

Rust lane, 2026-09-02, debug profile, extraction **223-655 us/function**
(sixteen-plus repeated runs; see "A note on reproducibility" below) over 1,787
samples. Sampled pool 101 (chance R@1 0.0099) throughout. Table below is one
representative run (`267.03 us/function`); the ratchets in
`tests/identity_retrieval/main.rs` are floored under the observed minimum of
each ratcheted column rather than pinned to this run's exact digits.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 (chance) |
|---|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | optimisation | 389 | 410 | 0.7536 | 0.1753 | 0.1183 | 0.2545 | 0.3342 | 0.8355 | 0.0797 (0.0024) |
| XO-clang | optimisation | 366 | 377 | 0.7052 | 0.1171 | 0.0738 | 0.1639 | 0.2568 | 0.7787 | 0.0464 (0.0027) |
| **XC-O0** | compiler | 487 | 494 | **0.9387** | **0.5824** | 0.4723 | 0.7146 | 0.8111 | 0.9877 | 0.3162 (0.0020) |
| **XC-O2** | compiler | 357 | 377 | **0.7238** | **0.2381** | 0.1709 | 0.3277 | 0.4062 | 0.7619 | 0.1176 (0.0027) |
| XM | compiler + optimisation | 365 | 377 | **0.7026** | 0.1117 | 0.0685 | 0.1671 | 0.2521 | 0.7644 | 0.0438 (0.0027) |
| XM-S | + queries <20 blocks | 308 | 377 | 0.6739 | 0.0819 | 0.0422 | 0.1266 | 0.2013 | 0.7435 | 0.0260 (0.0027) |
| XM-M | + queries 20-100 blocks | 54 | 377 | 0.8527 | 0.2868 | 0.2222 | 0.3889 | 0.5000 | 0.9259 | 0.1296 (0.0027) |
| XM-L *(underpowered, n=3)* | + queries >100 blocks | 3 | 377 | 0.9978 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.3333 (0.0027) |

**Reading it.** Three things worth taking away, in the same order as the
Python fingerprint's section above so the two are easy to set side by side.

1. **It does NOT reverse the intuition the corpus was built with.** Unlike
   the Python fingerprint (compiler-swap far easier than optimisation-swap),
   `structural` is strong on both: XO-gcc 0.75, XC-O0 0.94. Block/edge/
   instruction-count ratios and the MD-index are sensitive to what an
   optimiser does to control flow, but they are *also* sensitive to what a
   different compiler's codegen does to it -- just less so, because two
   compilers at the same optimisation level still produce recognisably
   similar block structure for the same source.

2. **XC-O0 0.9387 / MRR10 0.5824 is the strongest cell either scheme reaches**
   on this corpus, well past the Python fingerprint's XC-O0/XC-O2 ceiling
   (~0.73 / ~0.22-0.24) and the FunctionSimSearch band (MRR10 0.26) the
   protocol document names for token-level representations -- a CFG-shape
   scheme is not in that representation class, and this is where the
   difference shows most.

3. **It does not collapse on XM.** AUC 0.7026, against the Python
   fingerprint's 0.5150 (chance) on the identical task. This is the
   specific comparison "Where the numbers go next" (below, in the version of
   this document before this scheme landed) named as the question a new
   scheme would have to answer, and this is the answer: a representation
   built from CFG shape rather than instruction tokens does not lose its
   signal when both the compiler and the optimisation level move at once.

**The cost** is higher than CTPH (223-655 us against 41 us) because this
scheme re-decodes each function's instruction stream for the mnemonic SPP and
the rare-constant multiset -- `glaurung::identity::structural::code_facts_from_function_bytes`,
added to `src/identity/structural/code.rs` for this harness (see "Adding a
scheme" below) -- but it is still inside TikNib's published 20-1030 us band,
unlike the Python fingerprint's 25,500 us.

**A note on reproducibility.** CTPH and the Python fingerprint are pure
functions of `sample.bytes`, so a fixed corpus gives them bit-identical
scores run to run. `structural` reads the *discovered CFG* itself, and
`analysis::cfg`'s per-function walk carries a wall-clock budget
(`Budgets::timeout_ms` / `total_timeout_ms`) that can recover a handful of
functions' block/edge structure slightly differently between runs on a shared
machine -- the same class of effect CLAUDE.md's "Baseline regen needs a quiet
machine" note describes, now observed downstream of discovery rather than
only inside it. Measured over sixteen repeated runs of `structural_full_sweep`
on a shared, otherwise-idle machine: XO-gcc AUC in `[0.752733, 0.753918]`,
XC-O2 AUC in `[0.723691, 0.724972]`, XM AUC in `[0.702408, 0.704658]` -- a
spread of one to two thousandths of AUC, never enough to change which scheme
wins a comparison in this document, but enough that the ratchets in
`tests/identity_retrieval/main.rs` are floored with margin under the observed
minimum rather than pinned to one run's exact digits.

**Fixed, 2026-09-02.** `docs/design/cfg-discovery-determinism-2026-09-02.md`
traced the spread above to `Budgets::default().timeout_ms` (100ms): a
*per-function* wall clock, restarted at every seed, whose firing point
depends on CPU contention rather than on the bytes analysed -- on a loaded
machine the same binary produced 6/6 distinct discovery digests, one
function's block count moving between a 148-block timeout truncation and the
full, deterministic 2048-block `max_blocks` cap run to run. `timeout_ms: 0`
does **not** disable the check (unlike `total_timeout_ms`, where `0` means
unbounded), so the harness now builds its own budget --
`tests/identity_retrieval/corpus.rs`'s `harness_budgets()`, used everywhere
the harness discovers, both corpora -- with `timeout_ms: u64::MAX` and the
deterministic step budgets (`max_blocks`, `max_instructions`, `max_functions`)
left at their defaults. No `src/` change was needed. Three repeated runs of
`structural_full_sweep` afterward reproduced **0.753603** (XO-gcc), and every
other in-house `structural` task, bit for bit -- not merely within the bands
above. `tests/identity_retrieval/corpus.rs::tests::
discovery_is_deterministic_with_harness_budgets` now asserts this directly: it
discovers one fixture binary twice and requires an identical `(entry, blocks,
edges)` digest with no function carrying `FunctionFlags::CFG_WALK_TIMEOUT`.
The ratchet floors above are unchanged (the margin they carry is now a
cushion against legitimate future scheme changes rather than against
measurement noise), but the exemption described in "A note on reproducibility,
sharpened" below no longer applies -- see there for the Dataset-1 numbers.

### cfr — `glaurung::identity::cfr`, the L2 Canonical Function Representation

Rust lane, 2026-09-02, **release** profile, extraction **1,810 us/function**
over 1,787 samples (12,004 us/function in a debug build; the retrieval numbers
are bit-identical between the two, and were read off the release run and
reproduced by the debug ratchet run in the same commit). Sampled pool 101
throughout, so chance Recall@1 is 0.0099. Uniform weights — the weighted rows
are the section after this one.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@5 | R@10 | R@50 | Global R@1 (chance) |
|---|---|---|---|---|---|---|---|---|---|---|
| XO-gcc | optimisation | 389 | 410 | 0.7569 | 0.2543 | 0.1799 | 0.3393 | 0.4550 | 0.7815 | 0.1131 (0.0024) |
| XO-clang | optimisation | 366 | 377 | 0.7135 | 0.1808 | 0.1120 | 0.2760 | 0.3634 | 0.7432 | 0.0683 (0.0027) |
| **XC-O0** | compiler | 487 | 494 | **0.9663** | **0.9162** | **0.8706** | 0.9713 | 0.9836 | 0.9938 | 0.7680 (0.0020) |
| **XC-O2** | compiler | 357 | 377 | **0.8921** | **0.5688** | 0.5014 | 0.6499 | 0.7227 | 0.9216 | 0.4034 (0.0027) |
| XM | compiler + optimisation | 365 | 377 | **0.7296** | 0.1990 | 0.1342 | 0.2877 | 0.3836 | 0.7945 | 0.0795 (0.0027) |
| XM-S | + queries <20 blocks | 308 | 377 | 0.7030 | 0.1637 | 0.1039 | 0.2240 | 0.3506 | 0.7565 | 0.0617 (0.0027) |
| XM-M | + queries 20-100 blocks | 54 | 377 | 0.8708 | 0.3125 | 0.2037 | 0.4815 | 0.6296 | 0.9444 | 0.1296 (0.0027) |
| XM-L *(underpowered, n=3)* | + queries >100 blocks | 3 | 377 | 0.9967 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 (0.0027) |

**Reading it, in the same three-point form as the sections above.**

1. **It does not reverse the intuition, and it does not collapse.** XO-gcc
   0.7569 and XC-O0 0.9663: strong on both axes, like `structural` and unlike
   the Python fingerprint. XM is 0.7296, above `structural`'s 0.7026 — which is
   the bar the previous version of this page set for a new scheme ("the bar for
   the CFR is not 'does not collapse' but 'beats 0.70'"). It clears it, though
   only just, unweighted.

2. **The margin is in the ranking, not the AUC.** XC-O2 AUC 0.8921 against
   `structural`'s 0.7238 is a large gap; XC-O2 **MRR10 0.5688 against 0.2381**
   is a much larger one, and MRR10 is the metric Marcelli warns diverges from
   AUC. FunctionSimSearch's published ceiling for token-shaped representations
   is MRR10 0.26; `structural` sits just above it at 0.238–0.582 depending on
   the task; the CFR's XC-O0 MRR10 is 0.9162.

3. **It is expensive, and structurally so.** 1,810 us/function against CTPH's
   41 and `structural`'s 267, all release-or-debug-labelled above. This is the
   only scheme in the harness that lifts to LLIR and runs SSA rather than
   reading bytes or a discovered CFG, and it is an order of magnitude past
   TikNib's published 20–1030 us band. For a 6,000-function kernel diff that is
   eleven seconds of extraction, which is fine; for a corpus-scale index it is
   the number to improve.

### cfr-weighted — the same features under a corpus TF-IDF table

Plan item 5. The weight table is
`src/identity/cfr/weights.rs` — `idf(f) = ln((N + 1) / (df(f) + 1))`, quantised
into 512 buckets over `[0, 16]` nats — and the design is documented in
[`docs/reference/function-identity-cfr.md`](../reference/function-identity-cfr.md).

**The population is half the corpus, and the comparison is against a control on
the same half.** A weight table that has counted the exact function being
retrieved has seen the answer, weakly but unboundably, so the harness splits:
SplitMix64 over the ground-truth label (`scheme::cfr_in_training_half`) puts
each function in training or held out **in every slice at once**, so a
function's `-O0` build never trains the table that scores its `-O2` build. The
weighted row and the unweighted control (`cfr-heldout`) score the identical
population — `cfr_weighting_ratchets` asserts the two `scored` counts are equal,
because two rows over two populations are not a delta.

This is *stricter* than production. BSim counts its IDF over the corpus it later
searches, as does every TF-IDF retrieval system, because a document frequency is
a property of the collection rather than a fitted parameter. So these numbers
understate what the weighting is worth in a deployment that indexes what it
searches.

In-house corpus, release, 2026-09-02. Weight table
`cfr-1.0-s0-idf512-48359a7a35563d79`: 910 training-half functions, 39,969
weighted features. Sampled pool 101 throughout.

| Task | Scored | Global pool | AUC unw. → wtd. | MRR10 unw. → wtd. | R@1 unw. → wtd. |
|---|---|---|---|---|---|
| **XO-gcc** | 187 | 200 | 0.7800 → **0.8592** (+0.0791) | 0.2549 → **0.5080** (+0.2531) | 0.1872 → **0.4064** (+0.2193) |
| **XO-clang** | 178 | 184 | 0.7419 → **0.8152** (+0.0733) | 0.1829 → **0.3729** (+0.1901) | 0.1124 → **0.2809** (+0.1685) |
| XC-O0 | 241 | 243 | 0.9679 → 0.9938 (+0.0259) | 0.9501 → 0.9557 (+0.0056) | 0.9253 → 0.9253 (+0.0000) |
| XC-O2 | 172 | 184 | 0.8935 → 0.9461 (+0.0526) | 0.5681 → 0.6549 (+0.0868) | 0.5116 → 0.5698 (+0.0581) |
| XM | 177 | 184 | 0.7625 → 0.8131 (+0.0506) | 0.1984 → 0.4232 (+0.2247) | 0.1243 → 0.3333 (+0.2090) |
| XM-S | 141 | 184 | 0.7474 → 0.7963 (+0.0490) | 0.1699 → 0.4128 (+0.2429) | 0.0922 → 0.3191 (+0.2270) |
| XM-M | 34 | 184 | 0.8355 → 0.8797 (+0.0442) | 0.2394 → 0.4303 (+0.1909) | 0.1176 → 0.3235 (+0.2059) |
| XM-L *(underpowered, n=2)* | 2 | 184 | 0.9975 → 0.9825 (−0.0150) | 1.0000 → 0.6000 (−0.4000) | 1.0000 → 0.5000 (−0.5000) |

**Reading it.**

1. **The plan's hypothesis holds, on every metric.** The research synthesis
   predicted the weighting would lift **XO** most, and it does: the largest AUC
   gain (+0.0791) and the largest ranking gains in the table (+0.2531 MRR10,
   +0.2193 Recall@1). The mechanism is visible in the row that gains least —
   XC-O0 was already at AUC 0.9679 with Recall@1 0.9253 and had nothing left to
   gain, while XO sat at 0.7800, and what separates a function from its `-O2`
   twin's *size-matched* neighbours is exactly the rare structure a uniform
   weighting drowns in `mov`-shaped noise.

2. **Ranking gains far outrun AUC gains.** XM moves +0.05 AUC and +0.22 MRR10.
   AUC asks whether a positive pair outscores a random negative pair, which the
   unweighted CFR already mostly gets right; MRR10 asks whether the twin
   outranks a hundred size-matched negatives, and that is the question rarity
   answers. **A lane evaluated on AUC alone would have reported this work as a
   modest improvement.** That is the most transferable finding here and it is
   exactly the divergence Marcelli documents.

3. **XM-L is two queries.** Its Recall@1 can only be 0, 0.5 or 1. It is flagged,
   it is not ratcheted, and it must not be quoted — the same rule as everywhere
   else on this page.

### cfr and cfr-weighted on Dataset-1

Release, 2026-09-02, extraction **25,331 us/function** over 2,441 samples across
six architectures. Uniform weights over the whole corpus, which is the row
comparable with CTPH and `structural` above.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@10 |
|---|---|---|---|---|---|---|---|
| **XO** | optimisation | 50 | 229 | **0.9127** | 0.7570 | 0.6800 | 0.9000 |
| **XC** | compiler | 65 | 348 | **0.9638** | 0.9667 | 0.9385 | 1.0000 |
| **XM** | compiler + optimisation | 36 | 262 | **0.8806** | 0.7301 | 0.6667 | 0.8611 |
| **XB** | bitness | 72 | 260 | **0.9353** | 0.6695 | 0.5694 | 0.8889 |
| **XA-arm64** | architecture | 47 | 228 | **0.9131** | 0.8045 | 0.7447 | 0.9149 |
| XA-mips64 | architecture | **0** | — | — | — | — | — |
| XA+XB-arm32 *(underpowered, n=25)* | architecture + bitness | 25 | 241 | 0.8280 | 0.5124 | 0.4400 | 0.6800 |
| XA+XB-mips32 | architecture + bitness | **0** | — | — | — | — | — |
| XA+XO *(underpowered, n=23)* | architecture + optimisation | 23 | 228 | 0.8203 | 0.4167 | 0.3043 | 0.6957 |

Against `structural`'s table above, on the identical tasks:

| Task | CTPH | `structural` | `cfr` |
|---|---|---|---|
| XO | 0.4990 | 0.8283 | **0.9127** |
| XC | 0.5402 | 0.8851 | **0.9638** |
| XM | 0.5121 | 0.8045 | **0.8806** |
| XB | 0.4997 | 0.8985 | **0.9353** |
| XA-arm64 | 0.5000 | **0.9486** | 0.9131 |
| XA-mips64 | 0.4998 | 0.5742 | *no lifter* |
| XA+XB-mips32 | 0.5000 | 0.5524 | *no lifter* |

**Two things, and the second is the more important one.**

**Four of five improve, and the exception is where a CFG-shape scheme was
already strongest.** `structural` keeps XA-arm64 (0.9486 against 0.9131). The
question the previous version of this page posed for the CFR was whether it
would "beat `structural`'s own XA-mips64 (0.5742) and XA+XB-mips32 (0.5524) —
the two rows where a CFG-shape-only representation is weakest, which is exactly
where dataflow information the CFR adds might help most." **The answer is that
it cannot run there at all**, and that is the second thing.

**The two MIPS rows score zero queries, deliberately.** `src/ir/lift/` covers
x86, x86-64, ARM and AArch64 and reaches MIPS not at all, so `CfrScheme::extract`
consults `SampleArch::is_liftable` and **refuses** — visibly, counted, and
printed beside the result — rather than returning an empty vector that would
score 0.0 against everything and read as a measured failure. CTPH scored those
rows at exactly chance and `structural` at 0.574 and 0.552; the CFR scores them
not at all. `CISCO_CFR_UNLIFTABLE_TASKS` asserts the zero, so if a MIPS lifter
ever lands the test fires and says to promote them. The difference between
"wrong" and "cannot answer" is the whole reason `SchemeError` exists.

The weighted Dataset-1 rows are on the held-out half, which leaves 9–30 queries
per task and puts most of them under the quotable threshold. They are reported
for completeness and only the first five should be read at all:

| Task | Scored | Pool | AUC unw. → wtd. | MRR10 unw. → wtd. | R@1 unw. → wtd. |
|---|---|---|---|---|---|
| **XO** | 18 | 106 | 0.8880 → **0.9902** (+0.1023) | 0.5718 → 0.8426 (+0.2708) | 0.5000 → 0.7222 (+0.2222) |
| XC | 29 | 171 | 0.9586 → 0.9972 (+0.0386) | 0.9483 → 0.9425 (−0.0057) | 0.8966 → 0.8966 (+0.0000) |
| XM | 18 | 125 | 0.8681 → 0.9291 (+0.0610) | 0.5802 → 0.6543 (+0.0741) | 0.5000 → 0.6111 (+0.1111) |
| XB | 30 | 127 | 0.9642 → 0.9844 (+0.0202) | 0.7001 → 0.8722 (+0.1721) | 0.5667 → 0.8000 (+0.2333) |
| XA-arm64 | 19 | 115 | 0.9185 → 0.9855 (+0.0670) | 0.8132 → 0.8921 (+0.0789) | 0.7895 → 0.8421 (+0.0526) |
| XA+XB-arm32 *(n=9)* | 9 | 128 | 0.9667 → 0.8878 (−0.0789) | 0.7778 → 0.8148 (+0.0370) | 0.7778 → 0.7778 (+0.0000) |
| XA+XO *(n=9)* | 9 | 115 | 0.8635 → 0.8983 (+0.0348) | 0.4251 → 0.3529 (−0.0722) | 0.2222 → 0.1111 (−0.1111) |

**XO gains most here too** (+0.1023 AUC), which is the in-house finding
reproduced on a corpus with different compilers, different sources and a
different ground truth. **The two rows that go backwards are the two with nine
queries**, where one query is 11 percentage points of Recall@1; they are flagged
and unratcheted for exactly that reason.

### Head to head

| | CTPH | Python structural fingerprint | `structural` (L1) | `cfr` (L2) | `cfr` weighted | `cfr` normalised + weighted |
|---|---|---|---|---|---|---|
| XO-gcc AUC | 0.5015 | 0.5825 | 0.7536 | 0.7569 | 0.8592\* | **0.8717**\* |
| XC-O0 AUC | -- | -- | 0.9387 | 0.9663 | 0.9938\* | **0.9942**\* |
| XC-O2 AUC | 0.5030 | 0.7287 | 0.7238 | 0.8921 | 0.9461\* | **0.9487**\* |
| XM AUC | 0.5025 | 0.5150 | 0.7026 | 0.7296 | 0.8131\* | **0.8390**\* |
| XC-O2 MRR10 | 0.0084 | 0.2241 | 0.2381 | 0.5688 | 0.6549\* | **0.6723**\* |
| XM MRR10 | 0.0058 | 0.0357 | 0.1117 | 0.1990 | 0.4232\* | **0.4405**\* |
| Extraction | **41 us** (debug) | 25,500 us | 223-655 us (debug) | 1,810 us (release) | 1,810 us (release) | 2,113 us (release) |

\*The two rightmost columns are scored on the **held-out half** of the corpus
(187-241 queries against the others' 357-487), so they are not on the same
denominators as the four columns to their left. The comparison they belong in is
with `cfr-heldout`, which is in the weighted section above; they are here so the
shape of the ladder is visible in one place. The last column turns both levers
on at once -- the peephole normaliser and a TF-IDF table counted over normalised
vectors -- and the 2x2 that separates them, with the one cell where they do not
compose, is in
[`reference/function-identity-cfr.md`](../reference/function-identity-cfr.md#the-two-levers-together).

The first four columns are over the same tasks, the same tie rule and the same
sampling. They are **not** over the same rows: the harnesses filter 1,787,
1,786 and 1,787 functions from populations discovered differently (see "Two
known differences" below), so treat the comparison as between representations,
not as a per-function A/B. `structural` was the first scheme in this table that
did not collapse on XM, and it reaches that without a model, a corpus, or a
training step -- exactly what the research synthesis predicted for the identity
ladder's L1 rung. `cfr` improves on it everywhere here, most sharply on the
ranking metrics, and at seven times the extraction cost.

## Cisco Dataset-1

> **Status: shipped lane, measured numbers, 2026-09-02.** Plan item 9 of the
> research package. This is the corpus that gives the harness its **XA**
> (cross-architecture) and **XB** (cross-bitness) lanes, and whose published
> tables our rows are meant to sit beside.

### What was fetched and where it lives

The artifact of Marcelli et al. (USENIX Security '22),
[`Cisco-Talos/binary_function_similarity`](https://github.com/Cisco-Talos/binary_function_similarity),
**MIT**. Every URL, byte size and SHA-256 — and the comparison against the
checksums upstream publishes — is in
[`docs/development/corpora.md`](corpora.md), which is the canonical provenance
record for any downloaded corpus. In summary:

* **`Binaries/Dataset-1`** — 12 GB, 5,489 unstripped ELF binaries, 7 projects,
  **6 architecture/bitness combinations** (x86, x64, arm32, arm64, mips32,
  mips64), **8 compilers** (gcc 4.8/5/7/9, clang 3.5/5.0/7/9), **5
  optimisation levels** (O0-O3, Os), inlining disabled throughout.
* **`DBs/Dataset-1`** — 356 MB of ground-truth CSVs: the selection table and
  the published pair files. Extracted out of a 5.07 GB archive whose remaining
  contents are IDA-derived features; the archive was deleted, because importing
  someone else's features would measure their extractor.
* **`Binaries/Dataset-Vulnerability`** — 12 MB, six OpenSSL `libcrypto` builds
  including two lifted from real firmware. Fetched and recorded; **no lane
  consumes it yet.**

Located by **`GLAURUNG_CISCO_CORPUS`**, pointing at the directory holding
`Binaries/` and `DBs/`. Unset, every Dataset-1 test skips loudly and asserts
nothing. Like `GLAURUNG_IDENTITY_CORPUS` it is read from `tests/` and never
from `src/`, so it is outside the allowlist
`python/tests/test_src_dependency_boundaries.py` enforces over the product
tree; this page is the whole of its registration.

### Ground truth: theirs, not ours

The population is `testing_Dataset-1.csv` — one row per selected function with
`idb_path, fva, func_name, start_ea, end_ea, bb_num, project, library, arch,
bit, compiler, version, optimizations`. Labels, entry VAs and extents all come
from that file; `glaurung::analysis::cfg` is used **only** to obtain the CFG at
each listed VA. Two functions are the same iff they share `(library,
func_name)` — `library` and not `project`, because `main` in `ncat` and `main`
in `nping` are two different functions.

The `testing` split, deliberately: Marcelli's published Tables 3 and 4 are
computed on it, and a number measured on `training` is not comparable to them
however similar it looks. That split holds two projects, `nmap` (libraries
`ncat`, `nmap`, `nping`) and `z3`.

**The <5-basic-block filter is applied on the published count and removes
zero.** Upstream's `flowchart_Dataset-1.csv` is *defined* as the functions with
at least five basic blocks and the selection CSV is drawn from it, so a nonzero
count here would mean the loader is reading a population that is not Marcelli's
— and the test asserts the zero for that reason.

Which surfaces something the in-house corpus could never have shown. Where our
own discovery disagrees with IDA on the same function it is recorded rather
than filtered:

| Slice | Functions | Recover <5 blocks under `glaurung::analysis::cfg` |
|---|---|---|
| x64-gcc-9-O0 | 335 | 0 (0%) |
| x64-gcc-9-O2 | 229 | 0 (0%) |
| x64-clang-9-O2 | 262 | 6 (2%) |
| x64-clang-9-O0 | 348 | 10 (3%) |
| x86-gcc-9-O2 | 260 | 17 (7%) |
| arm32-gcc-9-O2 | 241 | 19 (8%) |
| arm64-gcc-9-O2 | 228 | 1 (0%) |
| **mips64-gcc-9-O2** | 279 | **159 (57%)** |
| **mips32-gcc-9-O2** | 259 | **223 (86%)** |

Every one of those functions has five or more basic blocks according to IDA.
On x86-64 we agree exactly; on **MIPS32 we recover fewer than five blocks for
86% of them**. That is a statement about Glaurung's CFG recovery on MIPS, not
about the corpus, and it is a bug report this harness produced as a side effect
of having a cross-architecture lane at all. It does not move any denominator
below — the filter runs on the published count — but it does mean every
CFG-shaped scheme's MIPS numbers should be read with it in view.

### The default lane

Nine configurations of the newest compiler pair in the corpus (gcc 9 and clang
9), over the three `nmap`-project libraries. All three are loaded because two
leave the MIPS32 slice below the 101 candidates a ranking pool needs. **27
binaries, 2,544 selection rows, 2,441 functions after the dedupe (103 removed
by the `(name, normalized instruction hash)` rule), 43-49 seconds to load in a
debug build.**

Tasks, with the free variables asserted against the configurations rather than
merely declared (`cisco::tests::declared_free_variables_match_the_configurations`):

| Task | Query | Pool | Free variables |
|---|---|---|---|
| XO | x64-gcc-9-O0 | x64-gcc-9-O2 | optimisation |
| XC | x64-gcc-9-O0 | x64-clang-9-O0 | compiler |
| XM | x64-gcc-9-O0 | x64-clang-9-O2 | compiler + optimisation |
| **XB** | x64-gcc-9-O2 | x86-gcc-9-O2 | bitness |
| **XA-arm64** | x64-gcc-9-O2 | arm64-gcc-9-O2 | architecture |
| **XA-mips64** | x64-gcc-9-O2 | mips64-gcc-9-O2 | architecture |
| **XA+XB-arm32** | x64-gcc-9-O2 | arm32-gcc-9-O2 | architecture + bitness |
| **XA+XB-mips32** | x64-gcc-9-O2 | mips32-gcc-9-O2 | architecture + bitness |
| **XA+XO** | x64-gcc-9-O0 | arm64-gcc-9-O2 | architecture + optimisation |

Negative sampling, tie handling, the metrics and the 100-negatives-per-positive
pool are the *same code* as the in-house lane — `metrics::evaluate_slices` is
shared — so the two corpora's rows differ only in what they are computed over.
The negative-constraint discipline is structural here too: negatives come from
the task's pool slice, and every candidate in a pool slice provably shares that
slice's whole five-dimensional configuration
(`cisco_tasks_have_sound_ground_truth_and_constrained_negatives` asserts it).

**One cost of using the published population, stated plainly.** The selection
CSV samples roughly a tenth of each binary's functions, independently per
binary. So slices are large (228-348, comfortably past 101) while the *twin
join* between two slices is small: a task scores 23-72 queries. Two rows fall
below the 30-query threshold at which a number may be quoted and are flagged
`[UNDERPOWERED]` and not ratcheted. Marcelli hit the same wall and answered it
with explicit pair files; see "The published pools" below.

### Results: CTPH on Dataset-1

Rust lane, 2026-09-02, debug profile, extraction **87-193 us/function** over
2,441 samples — two runs an hour apart on a shared developer machine, which is
why the ceiling in the test is 400 and not a tight floor. Sampled pool 101
throughout, so chance Recall@1 is 0.0099 and chance AUC is 0.5000. The AUC,
MRR and Recall columns are byte-identical between those two runs; only the
wall-clock number moved.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@10 |
|---|---|---|---|---|---|---|---|
| XO | optimisation | 50 | 229 | 0.4990 | 0.0000 | 0.0000 | 0.0000 |
| **XC** | compiler | 65 | 348 | **0.5402** | 0.0457 | 0.0308 | 0.1077 |
| XM | compiler + optimisation | 36 | 262 | 0.5121 | 0.0278 | 0.0278 | 0.0278 |
| XB | bitness | 72 | 260 | 0.4997 | 0.0000 | 0.0000 | 0.0000 |
| XA-arm64 | architecture | 47 | 228 | 0.5000 | 0.0000 | 0.0000 | 0.0000 |
| XA-mips64 | architecture | 57 | 279 | 0.4998 | 0.0000 | 0.0000 | 0.0000 |
| XA+XB-mips32 | architecture + bitness | 34 | 259 | 0.5000 | 0.0000 | 0.0000 | 0.0000 |
| XA+XB-arm32 *(underpowered, n=25)* | architecture + bitness | 25 | 241 | 0.5000 | 0.0000 | 0.0000 | 0.0000 |
| XA+XO *(underpowered, n=23)* | architecture + optimisation | 23 | 228 | 0.5000 | 0.0000 | 0.0000 | 0.0000 |

**Reading it.** Only **XC (0.5402)** is meaningfully off chance, and that is
the single-free-variable case the published table shows byte hashes doing best
on. Every row with an architecture free is 0.5000 to four decimals — not *near*
chance, **exactly** chance. Two CTPH digests over two instruction sets never
share a block, so every pair scores 0.0000, and under this harness's
pessimistic tie rule every candidate then ranks ahead of the twin. A scheme
that carries nothing looks exactly like this, and it is worth having the shape
on record: it is the floor the CFR has to clear on the lanes that matter most.

Note also that XB — same instruction-set family, different width — is 0.4997,
no better than a foreign architecture. Shi et al. name cross-bitness as the
task that separates IR representations from token representations; a byte
digest does not even reach the starting line.

### Results: structural on Dataset-1

Rust lane, 2026-09-02, debug profile, extraction **693-1388 us/function**
over 2,441 samples, three-plus runs under `Budgets::default()`, three
further runs under `harness_budgets()` (see "A note on reproducibility,
sharpened" below). Sampled pool 101 throughout. Table below is one
representative run; as of the `harness_budgets()` fix all nine scored rows
are bit-identical across repeated runs, including the two MIPS rows that
used to vary.

| Task | Free variables | Scored | Global pool | AUC | MRR10 | R@1 | R@10 |
|---|---|---|---|---|---|---|---|
| XO | optimisation | 50 | 229 | **0.8283** | 0.2797 | 0.2000 | 0.5400 |
| **XC** | compiler | 65 | 348 | **0.8851** | 0.4043 | 0.3077 | 0.6769 |
| XM | compiler + optimisation | 36 | 262 | **0.8045** | 0.3178 | 0.2500 | 0.4722 |
| **XB** | bitness | 72 | 260 | **0.8985** | 0.4884 | 0.3056 | 0.8333 |
| **XA-arm64** | architecture | 47 | 228 | **0.9486** | 0.5953 | 0.4681 | 0.8298 |
| XA-mips64 | architecture | 57 | 279 | **0.5742** | 0.0592 | 0.0175 | 0.2105 |
| XA+XB-mips32 | architecture + bitness | 34 | 259 | **0.5524** | 0.1005 | 0.0588 | 0.2059 |
| XA+XB-arm32 *(underpowered, n=25)* | architecture + bitness | 25 | 241 | 0.8559 | 0.3759 | 0.2800 | 0.6400 |
| XA+XO *(underpowered, n=23)* | architecture + optimisation | 23 | 228 | 0.8455 | 0.1794 | 0.1304 | 0.3913 |

**Reading it against CTPH's table just above.** Every row clears CTPH's by
0.3 to 0.45 AUC — including XA-arm64 and XB, the two rows where CTPH sits at
*exactly* 0.5000 because two digests over different instruction sets or
widths never share a block. **XA-arm64 0.9486** is the standout: a CFG's
block/edge counts, MD-index and loop structure survive an ISA change from
x86-64 to AArch64 almost as well as they survive nothing at all, because
related compiler backends at the same optimisation level preserve
control-flow shape closely even when the instruction encoding is unrelated.
**XB 0.8985** confirms Shi et al.'s claim that cross-bitness is the task that
separates IR/CFG-shaped representations from token ones — CTPH scored 0.4997
here, no better than a foreign architecture; `structural` scores its
second-highest AUC on this exact task.

**XA-mips64 and XA+XB-mips32 are the weakest rows**, and — unlike CTPH's
uniform exactly-chance floor on every architecture-free task — the weakness
here is specific to MIPS, not to crossing an architecture in general. This
reads together with the MIPS CFG-recovery finding earlier in this document
(the "Where our own discovery disagrees with IDA" table above shows 0% for
both MIPS slices on this branch, after the endianness fix at `441f669d`) as
the representation meeting a genuinely different ISA's branch-delay-slot and
register-window conventions on a corpus where the CFG itself is now recovered
soundly — the shortfall is not a rediscovery of the pre-fix MIPS bug.

**A note on reproducibility, sharpened.** The in-house section above
establishes that `structural`'s CFG-dependence makes it sensitive to
`analysis::cfg`'s per-function wall-clock budget, at a spread of one to two
thousandths of AUC. On Dataset-1 this effect was **not uniform across
architectures**: XO, XC, XM, XB and XA-arm64 were bit-identical or
near-identical (spread under 0.0003) across four runs, while the two
MIPS-crossing tasks moved by 0.007 to 0.023 AUC between runs of the identical
binary set —

| Task | Run 1 | Run 2 | Run 3 | Run 4 |
|---|---|---|---|---|
| XA-mips64 | 0.587764 | 0.604009 | 0.581433 | *(not re-measured)* |
| XA+XB-mips32 | 0.580190 | 0.573209 | 0.577915 | 0.585727 |

`tests/identity_retrieval/main.rs`'s `CISCO_STRUCTURAL_NOISY_TASKS` used to
exist because of exactly this table: `XA+XB-mips32`'s fourth run is the one
that caught it, tripping "improved more than `RATCHET_SLACK` above the
ratchet" on a floor set from the first three. Reading the two tables
together: run-to-run CFG-discovery jitter was not evenly distributed across
architectures, and it concentrated where this project's own CFG recovery is
documented as most marginal — which fits the mechanism identified below,
since a truncated MIPS function's walk has more block/edge structure at
stake per timeout than a small x86-64 one.

**Fixed, 2026-09-02.** Same root cause and same fix as the in-house section
above: `Budgets::default().timeout_ms` (100ms) is a per-function wall clock
whose firing point depends on CPU contention, and MIPS discovery apparently
sits closest to that clock on this corpus, which is why its jitter was larger
than the other seven tasks' rather than a MIPS-specific correctness issue.
`docs/design/cfg-discovery-determinism-2026-09-02.md` traces the mechanism;
`tests/identity_retrieval/corpus.rs`'s `harness_budgets()` (`timeout_ms:
u64::MAX`, step budgets left at their defaults) is now used for both corpora.
Three repeated runs of `cisco_structural_full_sweep` afterward reproduced the
exact same `f64` for both previously noisy tasks — `0.5741782086795937`
(XA-mips64) and `0.5524480968858132` (XA+XB-mips32) — not merely within a
band. Both moved from `CISCO_STRUCTURAL_NOISY_TASKS` into
`CISCO_STRUCTURAL_MIN_AUC` with floors read off that run (0.572000 and
0.550000, the same small-margin discipline as every other row).
`CISCO_STRUCTURAL_NOISY_TASKS` is kept as an empty constant rather than
deleted, so a future scheme that reintroduces genuine run-to-run noise on some
other task has a named place to land.

### Where these sit against the published tables

Marcelli's own numbers, read out of
`Results/notebooks/metrics_and_plots/Dataset-1/` in the upstream repository
(`df_auc.csv` is Table 3, `df_MRR@10_Recall@K_<task>_min.csv` is Table 4). His
ranking protocol is **the same pool size as ours — 1 positive + 100 negatives**
— and his AUC is over 50k positive + 50k negative pairs per task where ours is
over the scored queries of a much smaller slice. The rows are therefore
comparable in kind and not in confidence interval; the free-variable set is
identical.

**AUC (his Table 3), several free variables:**

| Approach | XA | XC | XC+XB | XM |
|---|---|---|---|---|
| Catalog1, bytes, size 128 | 0.43 | 0.74 | 0.67 | 0.56 |
| FunctionSimSearch, graphlets only | 0.69 | 0.72 | 0.73 | 0.71 |
| FunctionSimSearch, G+M+I | 0.58 | 0.73 | 0.71 | 0.65 |
| Zeek (strands) | 0.84 | 0.84 | 0.85 | 0.84 |
| GNN s2v + Gemini's 7 features | 0.80 | 0.81 | 0.82 | 0.81 |
| GMN (Li et al.) + BoW opcodes | 0.86 | 0.85 | 0.86 | 0.86 |
| **Glaurung CTPH (this lane)** | **0.4998-0.5000** | **0.5402** | no lane | **0.5121** |
| **Glaurung `structural` (this lane)** | **0.5742-0.9486** | **0.885** | no lane | **0.805** |

Our XA cell is a range because this lane keeps the two foreign architectures
apart (CTPH: `XA-arm64` 0.5000, `XA-mips64` 0.4998; `structural`: `XA-arm64`
0.9486, `XA-mips64` 0.5742) rather than pooling them: "cross-architecture"
averaged over ARM and MIPS hides which of the two a scheme fails on, and for a
scheme that fails on both the average is the only thing a single cell could
report. `structural`'s XA range spans further than CTPH's because it is
carrying real, uneven signal — 0.9486 on ARM64, 0.5742 on MIPS64 — rather
than sitting at chance on both ends. Against the published table, `structural`
on XC (0.885) sits between Zeek's strands (0.84) and GMN+BoW opcodes (0.85),
and on XM (0.805) above every non-GNN row in the table — a CFG-shape scheme
with no model reaching a band the literature associates with learned,
graph-neural approaches. `XC+XB` has no lane here because no loaded pair of
configurations varies compiler and bitness and nothing else.

**AUC (his Table 3), one free variable** — the regime the protocol document
warns is flattering:

| Approach | arch | bit | comp | opt | ver |
|---|---|---|---|---|---|
| Catalog1-128 | 0.43 | 0.76 | 0.86 | 0.92 | 0.99 |
| FSS graphlets | 0.81 | 0.89 | 0.68 | 0.74 | 0.87 |
| GMN + BoW opcodes | 0.99 | 0.99 | 0.77 | 0.89 | 0.99 |
| **Glaurung CTPH (this lane)** | **0.4998-0.5000** | **0.4997** | **0.5402** | **0.4990** | no lane |
| **Glaurung `structural` (this lane)** | **0.5742-0.9486** | **0.899** | **0.885** | **0.754**\* | no lane |

Catalog1 is the closest published analogue to CTPH — a byte-level hash — and
the comparison is instructive in both directions. It reaches 0.92 on
optimisation and 0.99 on compiler version where CTPH sits at 0.4990, so a
byte-level scheme *can* carry a one-variable signal and ours does not at
function granularity. And it collapses to **0.43** cross-architecture, below
chance, which is the same wall CTPH hits at 0.5000.

`structural`'s `bit` cell (0.899) beats every published row in the table
except GMN's 0.99, on the exact task Shi et al. name as separating IR/CFG
representations from token ones. \*The `opt` cell is the **in-house** XO-gcc
number (0.754, Dataset-1 has no single-optimisation-only lane loaded by
default) — included for the row to be complete, not directly comparable to
the other columns' Dataset-1 provenance.

**MRR@10 and Recall@1, 1 positive + 100 negatives (his Table 4):**

| Approach | XA MRR10 / R@1 | XC MRR10 / R@1 | XM MRR10 / R@1 |
|---|---|---|---|
| Catalog1-128 | 0.000 / 0.000 | 0.313 / 0.280 | 0.093 / 0.075 |
| FSS graphlets | 0.187 / 0.140 | 0.187 / 0.130 | 0.235 / 0.185 |
| FSS G+M+I | 0.041 / 0.020 | 0.229 / 0.180 | 0.132 / 0.085 |
| Zeek | 0.274 / 0.170 | 0.274 / 0.165 | 0.276 / 0.125 |
| GNN s2v + Gemini features | 0.359 / 0.260 | 0.398 / 0.325 | 0.363 / 0.275 |
| GMN + BoW opcodes | 0.522 / 0.445 | 0.529 / 0.460 | 0.533 / 0.450 |
| **Glaurung CTPH (this lane)** | **0.000 / 0.000** | **0.046 / 0.031** | **0.028 / 0.028** |
| **Glaurung `structural` (this lane)** | **0.059-0.595 / 0.018-0.468** | **0.404 / 0.308** | **0.318 / 0.250** |

Catalog1's XA row is 0.000 / 0.000 and so is ours (CTPH); that is the one
place where a byte hash and a byte hash agree exactly, and it says the
failure is the representation class rather than the implementation.
`structural`'s XA range (again ARM64 vs MIPS64 kept apart) already clears
GMN+BoW's 0.522/0.445 on the ARM64 end (0.595/0.468) while trailing badly on
the MIPS64 end — the same unevenness the AUC tables above show, for the same
documented reason.

Every row in every table above states its pool size (101 for the ranking
metrics) and its free-variable set, because a number without both is not
comparable to anything.

### The published pools

`DBs/Dataset-1/pairs/testing/{pos,neg}_rank_testing_Dataset-1.csv` are
Marcelli's own ranking pools: four tasks (XA, XC, XC+XB, XM), **200 queries
each**, **exactly 100 negatives per query** — verified, not assumed, by
`published_ranking_pools_hold_one_hundred_negatives_per_positive`, which is a
test on the ground truth rather than on any scheme. It is what licenses quoting
his Table 4 next to our rows: our sampler was set to 100:1 to match this, and
now something checks that it does.

Scoring those pools *verbatim* would make our rows directly comparable to Table
4 rather than comparable in kind. It is not done, and the reason is measured:
the four pools draw on **921 distinct binaries**, 229 of them z3 at ~30 MB
each. `cisco::PublishedPairPool::coverage` exists for it, and it is deliberate
that it reports *fully* resolvable queries only — dropping some of a query's
negatives shrinks its pool and inflates its rank, which is exactly the silent
inflation Marcelli names as a frequent source of overstated published results.

### Running it

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"

GLAURUNG_CISCO_CORPUS="$HOME/.cache/glaurung/corpora/cisco-talos-dataset1" \
  cargo test --features python-ext --test identity_retrieval

# Every number, no ratchet in the way, markdown rows for the table above:
GLAURUNG_CISCO_CORPUS=... cargo test --features python-ext \
  --test identity_retrieval -- --ignored --nocapture cisco
```

The report lands in `target/identity-eval/cisco-ctph.json`, the same shape as
`ctph.json` plus a `corpus`, a `coverage_notes` array and this corpus's own
`unsupported_tasks`. Both corpora together run in **~62 seconds** in a debug
build.

### What Dataset-1 still cannot say

Written into every Dataset-1 report so the gap is stated rather than
unexamined:

* **NoInline.** Dataset-1 disables inlining *throughout*, which is Marcelli's
  own simplification and sidesteps the field's dominant failure mode — Shi et
  al. measure 81.8% of HermesSim's failures as involving differential inlining.
  Only BinKit 2.0 has the lane, and BinKit is hundreds of GB and deliberately
  not ingested.
* **Obfuscation.** Obfuscator-LLVM SUB/BCF/FLA exist only in BinKit.
* **Pools of 10k and 100k.** Shi et al. report 2.1-15.1 MRR points lost between
  them. Reaching those sizes means loading z3.
* **The XM size strata.** Runnable, but an XM row here already holds 36
  queries; splitting it three ways would produce three underpowered rows.
* **IR-shaped schemes on MIPS.** `src/ir/lift/` covers x86, x86-64, ARM and
  AArch64; `disasm::registry` reaches MIPS only through Capstone. Two of the
  nine slices are therefore a coverage hole for an IR scheme and not a result,
  and `SampleArch::is_liftable` is the switch such a scheme must consult so its
  extraction *fails* there rather than returning a degenerate signature.
  `structural` is CFG- and byte-shaped, not IR-shaped, and its decoder comes
  from `disasm::registry` directly, so it *does* cover MIPS -- its XA-mips64
  and XA+XB-mips32 rows are real, and now ratcheted, results (see "A note on
  reproducibility, sharpened" above).

## Adding a scheme

The Rust harness plugs new schemes in through one trait
(`tests/identity_retrieval/scheme.rs`):

```rust
pub trait Scheme {
    type Sig: Send + Sync;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn extract(&self, sample: &FunctionSample) -> Result<Self::Sig, SchemeError>;
    fn similarity(&self, a: &Self::Sig, b: &Self::Sig) -> f64;
}
```

`FunctionSample` carries the function's bytes, its entry VA, the image path and
the discovered CFG (blocks sorted by start VA, edges in index form). That is
the whole input surface on purpose: CTPH uses only `bytes`; `structural` uses
`blocks`, `edges` and `bytes` (the graph half needs only the first two, the
mnemonic-SPP and rare-constant halves re-decode the third); WARP and the CFR
need `image_path` and `va` so they can re-open the image and lift it.

Implement the trait, add a test that calls `metrics::evaluate(&scheme, corpus,
TASKS)`, and pin what it measures. Nothing in `corpus.rs` or `metrics.rs` has
to change. `structural` has landed (`StructuralScheme` in `scheme.rs`); the
two remaining slots are documented at the bottom of `scheme.rs`:

* **`structural`** — **landed.** `src/identity/structural/`, the L1 rung.
  `Sig` is `StructuralSignature`: the invariant tuple (MD-index
  top-down/bottom-up/relaxed, small-primes product over normalized
  mnemonics, block/edge/loop/SCC counts and cyclomatic complexity),
  `similarity` is the crate's own `ranking_similarity`. `extract` builds the
  graph half straight from `sample.blocks`/`sample.edges` (no decode needed)
  and the mnemonic-SPP/rare-constant half by re-decoding `sample.bytes`
  through `code_facts_from_function_bytes` — a small accessor added to
  `src/identity/structural/code.rs` for this harness, because the production
  `ImageCode::facts` needs a whole container image to resolve its
  relocation-address mask and this harness's sample carries only one
  function's own bytes. `StructuralScheme` caches one disassembler backend
  per `(Architecture, Endianness)` pair across the whole scored corpus, the
  same discipline `ImageCode` uses within one image, because
  `registry::for_arch` is a real per-call cost on the Capstone-backed
  architectures.
* **`warp`** (`src/identity/warp.rs`, L0) — a `uuid::Uuid` and exact equality,
  so its Recall@1 *is* its coverage. Read the pool size before believing
  either end of that.
* **`cfr`** (`src/identity/cfr/`, L2) -- **landed.** `CfrScheme` in
  `scheme.rs`, in three configurations: `unweighted` (whole corpus),
  `unweighted_held_out` and `weighted`, the last two over the identical
  population so their difference is the weight table and nothing else. `Sig` is
  an `Arc<CfrSignature>` -- the sorted `(u32 feature_hash, u16 count)` multiset
  -- and `similarity` is BSim's merge-join cosine.

  It is the only scheme here that needs `image_path` and `va` and reads neither
  `bytes` nor `blocks`: the representation is over LLIR after SSA, and a
  `FunctionSample` carries no IR. So it re-opens the image and lifts, and signs
  the **whole image** on the first sample that names it, keeping the last four
  images' signatures (`CFR_IMAGE_CACHE`). Four is enough because the driver
  walks samples in ground-truth-label order and a label starts with the fixture
  or the library, so consecutive samples come from the same image.

  It is also the only scheme that must **fail for a whole architecture**.
  `src/ir/lift/` has no MIPS lifter, so on a MIPS slice it consults
  `SampleArch::is_liftable` and returns a `SchemeError` -- which is why its two
  Dataset-1 MIPS rows score zero queries where CTPH's score exactly chance.

The contract the harness enforces on every scheme: `extract` is deterministic,
`similarity` is symmetric and in `[0, 1]`, and `similarity(a, a) == 1.0`. Those
are the metric axioms the protocol document asks to ship with the first hash,
and they are tested separately from the retrieval numbers because they hold for
a scheme that is otherwise useless.

## Ratchets

Every constant in both harnesses was **read off a run before it was written
down** — the discipline `tests/similarity_retrieval.rs` established. A number
may only tighten. Drifting more than the slack (0.02 in Rust, 0.05 in Python)
*above* its floor also fails, with a message saying to raise the constant in
the same commit: a ratchet that has silently fallen behind reality has stopped
reporting regressions.

The two timing ceilings (`CTPH_MAX_EXTRACTION_US`, `FP_MAX_EXTRACTION_MS`) are
deliberately loose. They are wall clock on a shared developer machine, where a
tight floor fails for reasons unrelated to the code; they still catch an
extraction that becomes an order of magnitude more expensive.

## Two known differences between the harnesses

Both change the denominator, so both are stated rather than smoothed over.

1. **The Python lane's discovery is unseeded.** The Rust lane seeds
   `analyze_functions_bytes` with the symbol VAs; the Python binding surface
   exposes no seeded entry point, so the Python lane takes
   `analyze_functions_path` and reads names off whatever discovery found.
   Measured effect: 1,786 kept against 1,787, and per-slice differences of at
   most two functions. The cross-check test allows 25% and would fire long
   before a real divergence mattered.

2. **The Python lane has no `.text` filter.** Nothing in the binding surface
   reports a function's section. The Rust lane measured that filter removing
   **zero** functions on this corpus, so the omission costs nothing here; on a
   linked multi-object binary it would.

## Where the numbers go next

Plan items 2 (structural), 3+4 (the CFR) and 5 (its TF-IDF weighting) have
landed in this harness. Plan item 6 (WARP GUIDs) has landed in the tree but not
yet here, and plan items 8 (the peephole normaliser) and 12 (value
fingerprints) still produce schemes that will. When one does:

* On the **in-house corpus**, the row to beat is now `cfr-weighted`'s
  **XC-O0 AUC 0.9938 / MRR10 0.9557**, and the row that says whether a new
  representation is actually better is **XM MRR10 0.4232** rather than XM AUC:
  the weighting lane above moved AUC by 0.05 and MRR10 by 0.22 on that task,
  which is the clearest demonstration on this page that AUC saturates long
  before ranking does. The next scheme should be judged on the ranking column.
* On **Dataset-1**, the floor is now `structural`'s own **XA-arm64 AUC
  0.9486 / XB AUC 0.8985**, not CTPH's chance-level 0.5000 / 0.4997 — a
  CFG-shaped L1 scheme already clears FunctionSimSearch's graphlets (XA AUC
  0.69) and sits close to Zeek's strands (0.84) on XC and XM. The CFR adds a
  typed SSA dataflow graph on top of the CFG shape `structural` already
  reads, so the honest target for it was not "beat chance" but "beat
  `structural`'s own XA-mips64 (0.5742) and XA+XB-mips32 (0.5524)" — the two
  rows where a CFG-shape-only representation is weakest. **It cannot run there
  at all**: those two slices are MIPS and `src/ir/lift/` has no MIPS lifter, so
  the CFR refuses rather than answering. Those two rows are now the strongest
  argument in this document for a MIPS lifter, and until there is one they
  belong to `structural`.

Two things a new scheme must do that CTPH did not have to, and that
`structural` already does. It must consult `SampleArch::is_liftable` (or, for
a CFG/byte-shaped scheme like `structural`, simply attempt decode and let a
real backend failure speak for itself) and **fail** extraction rather than
return a degenerate signature — the harness counts and prints extraction
failures for exactly this. And when its numbers move, both
`target/identity-eval/<scheme>.json` and `target/identity-eval/cisco-<scheme>.json`
are diffable artifacts: a change that improves one corpus and quietly ruins
the other is the case a single-row summary hides.

A third thing `structural` discovered that CTPH's design never surfaced: a
CFG-shaped scheme's numbers were not exactly reproducible run to run on a
shared machine, because `analysis::cfg`'s per-function wall-clock budget could
recover a handful of functions' blocks/edges slightly differently between
runs. Fixed 2026-09-02 (`docs/design/cfg-discovery-determinism-2026-09-02.md`):
every discovery call in this harness now goes through
`tests/identity_retrieval/corpus.rs`'s `harness_budgets()`, which sets
`timeout_ms: u64::MAX` so that clock can never fire. Any future scheme that
reads the discovered CFG (the CFR will) should call `harness_budgets()` too,
rather than `Budgets::default()` or a bespoke budget of its own -- see
`corpus::tests::discovery_is_deterministic_with_harness_budgets` for the test
that guards this directly. There should no longer be a need to measure
ratchets from several repeated runs to find a stable floor; a single run
under `harness_budgets()` is expected to reproduce bit for bit.

## See also

* [`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md)
  — the design, the identity ladder, and the four literature surveys behind it.
* [`docs/development/corpora.md`](corpora.md) — provenance for every
  downloaded corpus: URLs, sizes, SHA-256s, licences, and how to fetch again.
* [`docs/development/decompiler-testing.md`](decompiler-testing.md) — how the
  fixture corpus this harness reads is built.
* `tests/similarity_retrieval.rs` — the earlier, narrower CTPH measurement.
  Its numbers are **not** comparable to the ones here: it scores every named
  text symbol with first-wins tie handling, this harness scores only functions
  of 5 blocks or more with ties counted against the twin.
