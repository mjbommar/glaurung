# Measuring function identity

> **Status: shipped harness, measured numbers.** Every figure on this page was
> read off a run on 2026-09-02 and is pinned as a ratchet in the test that
> produced it. This is plan items 1 and 9 of
> [`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md)
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

Our XA cell is a range because this lane keeps the two foreign architectures
apart (`XA-arm64` 0.5000, `XA-mips64` 0.4998) rather than pooling them:
"cross-architecture" averaged over ARM and MIPS hides which of the two a scheme
fails on, and for a scheme that fails on both the average is the only thing a
single cell could report. `XC+XB` has no lane here because no loaded pair of
configurations varies compiler and bitness and nothing else.

**AUC (his Table 3), one free variable** — the regime the protocol document
warns is flattering:

| Approach | arch | bit | comp | opt | ver |
|---|---|---|---|---|---|
| Catalog1-128 | 0.43 | 0.76 | 0.86 | 0.92 | 0.99 |
| FSS graphlets | 0.81 | 0.89 | 0.68 | 0.74 | 0.87 |
| GMN + BoW opcodes | 0.99 | 0.99 | 0.77 | 0.89 | 0.99 |
| **Glaurung CTPH (this lane)** | **0.4998-0.5000** | **0.4997** | **0.5402** | **0.4990** | no lane |

Catalog1 is the closest published analogue to CTPH — a byte-level hash — and
the comparison is instructive in both directions. It reaches 0.92 on
optimisation and 0.99 on compiler version where CTPH sits at 0.4990, so a
byte-level scheme *can* carry a one-variable signal and ours does not at
function granularity. And it collapses to **0.43** cross-architecture, below
chance, which is the same wall CTPH hits at 0.5000.

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

Catalog1's XA row is 0.000 / 0.000 and so is ours; that is the one place where
a byte hash and a byte hash agree exactly, and it says the failure is the
representation class rather than the implementation.

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
in this harness. When one does:

* On the **in-house corpus**, the row to beat is the Python structural
  fingerprint's **XC-O2 AUC 0.7287 / MRR10 0.2241**, and the row that says
  whether the representation is actually better is **XM AUC 0.5150** — the task
  with both variables free, where every token-level representation in the
  literature falls over.
* On **Dataset-1**, the floor is CTPH's **XA 0.5000 / XB 0.4997** and the
  target is a published one rather than one of ours: FunctionSimSearch's
  graphlets reach **XA AUC 0.69** and Zeek's strands **0.84**. The CFR is a
  CFG-plus-dataflow representation and the graphlet row is the honest bar for
  it. Anything that reports an XA number without also reporting whether it
  covers the MIPS slices is reporting half a result.

Two things a new scheme must do that CTPH did not have to. It must consult
`SampleArch::is_liftable` and **fail** extraction on MIPS rather than return a
degenerate signature — the harness counts and prints extraction failures for
exactly this. And when its numbers move, both `target/identity-eval/ctph.json`
and `target/identity-eval/cisco-ctph.json` are diffable artifacts: a change
that improves one corpus and quietly ruins the other is the case a single-row
summary hides.

## See also

* [`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md)
  — the design, the identity ladder, and the four literature surveys behind it.
* [`docs/development/corpora.md`](corpora.md) — provenance for every
  downloaded corpus: URLs, sizes, SHA-256s, licences, and how to fetch again.
* [`docs/development/decompiler-testing.md`](decompiler-testing.md) — how the
  fixture corpus this harness reads is built.
* `tests/similarity_retrieval.rs` — the earlier, narrower CTPH measurement.
  Its numbers are **not** comparable to the ones here: it scores every named
  text symbol with first-wins tie handling, this harness scores only functions
  of 5 blocks or more with ties counted against the twin.
