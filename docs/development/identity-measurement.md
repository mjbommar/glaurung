# Measuring function identity

> **Status: shipped harness, measured numbers.** Every figure on this page was
> read off a run against the matched-build fixture corpus on 2026-09-02 and is
> pinned as a ratchet in the test that produced it. This is plan item 1 of
> [`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md)
> — the measurement harness the four identity schemes (WARP GUIDs, L1
> structural invariants, the CFR feature vector, L3 value fingerprints) are
> ranked against.

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

Two schemes already in the tree have been retro-scored, and the two results
say opposite things. **CTPH** (`glaurung::similarity`, the byte digest) is at
chance on every task. **The Python structural fingerprint**
(`python/glaurung/llm/kb/structural_fingerprint.py`) reaches AUC 0.73 and MRR10
0.22 cross-compiler — which is the FunctionSimSearch band the literature
predicts for its representation class — and collapses to chance the moment the
optimisation level is also free. Both results are below.

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
**XC+XB**, **XA+XO**, and BinKit's **NoInline** lane. The `dectest --arch`
matrix (i386, armv7, aarch64) builds the same 206 sources for other targets
and is the cheapest route to XA and XB; Shi et al. name XB as the task that
separates IR representations from token representations, so it is the
highest-value missing lane.

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

# Every task's every number, no ratchet in the way, markdown rows for the
# table below. Use this when a scheme lands or a ratchet fires.
cargo test --features python-ext --test identity_retrieval -- --ignored --nocapture

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

### Head to head

| | CTPH | Python structural fingerprint |
|---|---|---|
| XO-gcc AUC | 0.5015 | **0.5825** |
| XC-O2 AUC | 0.5030 | **0.7287** |
| XM AUC | 0.5025 | **0.5150** |
| XC-O2 MRR10 | 0.0084 | **0.2241** |
| XM MRR10 | 0.0058 | **0.0357** |
| Extraction | **41 us** (debug) | 25,500 us |

Both columns are over the same tasks, the same tie rule and the same sampling.
They are **not** over the same rows: the two harnesses filter 1,787 and 1,786
functions from populations discovered differently (see "Two known differences"
below), so treat the comparison as between representations, not as a
per-function A/B.

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
the whole input surface on purpose: CTPH uses only `bytes`, the L1 invariants
will use `blocks`/`edges`, and WARP and the CFR need `image_path` and `va` so
they can re-open the image and lift it.

Implement the trait, add a test that calls `metrics::evaluate(&scheme, corpus,
TASKS)`, and pin what it measures. Nothing in `corpus.rs` or `metrics.rs` has
to change. The three slots are documented at the bottom of `scheme.rs` with
what each `Sig` and `similarity` should be:

* **`structural`** (`src/identity/structural.rs`, L0/L1) — the invariant tuple:
  MD-index top-down/bottom-up/relaxed, small-primes product over normalized
  mnemonics, block/edge/loop/SCC counts, call degree.
* **`warp`** (`src/identity/warp.rs`, L0) — a `uuid::Uuid` and exact equality,
  so its Recall@1 *is* its coverage. Read the pool size before believing
  either end of that.
* **`cfr`** (`src/identity/cfr/`, L2) — the sorted `(u32 feature_hash, u16
  count)` multiset, compared with BSim's merge-join cosine.

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

The protocol document's plan items 2, 3, 4 and 6 all produce schemes that land
in this harness. When one does, the row to beat is the Python structural
fingerprint's **XC-O2 AUC 0.7287 / MRR10 0.2241**, and the row that says
whether the representation is actually better is **XM AUC 0.5150** — the task
with both variables free, where every token-level representation in the
literature falls over.

## See also

* [`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md)
  — the design, the identity ladder, and the four literature surveys behind it.
* [`docs/development/decompiler-testing.md`](decompiler-testing.md) — how the
  fixture corpus this harness reads is built.
* `tests/similarity_retrieval.rs` — the earlier, narrower CTPH measurement.
  Its numbers are **not** comparable to the ones here: it scores every named
  text symbol with first-wins tie handling, this harness scores only functions
  of 5 blocks or more with ties counted against the twin.
