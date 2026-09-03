# Measuring programs: a representation and metric for function identity — 2026-09-02

> **Kind:** record · **Date:** 2026-09-02

> **Status: research synthesis.** Four literature surveys were run on 2026-09-02
> (binary similarity, mathematical foundations, signature schemas and indexes,
> program representations); they are filed verbatim under
> [`program-measures-2026-09-02/`](program-measures-2026-09-02/). This page is the
> cross-check and the recommendation. In-tree claims below were verified against
> the working tree at `0de7b12d`; every literature claim traces to one of the four
> reports, which carry the URLs and mark what could not be verified.

## The question

Glaurung wants a fundamental representation of a function over which
"how far apart are these two?" is a computable, deterministic, well-defined
number, invariant to the choices a compiler makes and stable enough to index a
corpus. Four use cases drive it: naming stripped binaries from a library,
ranking the changed functions between two builds, identifying statically
linked libraries, and clustering families.

## The answer in one paragraph

Quotient first, then metrise. Build invariance into the representation rather
than paying for it in the matcher: a typed SSA dataflow graph plus a
degree-labelled CFG, with register names, block order, addresses, NOPs, dead
flags, stack mechanics and large constants projected away. Hash it with
Weisfeiler-Lehman relabelling into a multiset of features. The WL kernel is
positive semi-definite by construction, so its induced distance is a genuine
pseudo-metric, computed deterministically in near-linear time. That is Ghidra
BSim's design restated over Glaurung's LLIR, and it is the deterministic dual
of HermesSim, the current leader in independent evaluations. Everything else
(exact GUIDs, structural invariants, value fingerprints, indexes) hangs off
that object through the `function_identity(scheme, identity)` table that
already exists.

## What the evidence says

Five findings recur across all four reports, and the first two are the ones
that should change how we read our own results.

**1. The signal is in the IR, not the model, and not the bytes.** Three
independent evaluations agree (Marcelli et al. USENIX'22, Kim et al. TSE'22,
Shi et al. 2025). Byte hashes and assembly-token models are one-free-variable
tools: near-perfect when only the compiler version changes, collapsing when
optimisation, compiler and architecture vary together (SAFE Recall@1 0.4,
jTrans 5.8 on cross-bitness). Every current leader is built on decompiler IR
with dataflow edges. HermesSim beats jTrans with 226x fewer parameters. Our
in-tree result that CTPH is near chance at function granularity is not a
defect in the implementation; it is the published behaviour of that
representation class. Our structural fingerprint over disassembly tokens sits
in FunctionSimSearch territory, whose published ceiling is MRR10 0.26.

**2. A model is not required.** vSim (NDSS 2026) is explicitly non-ML and
beats jTrans and CLAP cross-compiler while being four times more stable across
toolchains. BSim is non-ML in the same sense. Maier et al. 2025 found the
advantages of pre-trained assembly embeddings "hardly noticeable" over 1.2M
Debian functions.

**3. Every tool that measures masks the same things and keeps the same
things.** Read from source across BinExport, BSim, WARP, FunctionID, Diaphora
and angr: masked are register names, block layout order, absolute addresses
and relocation targets, NOPs and padding, dead flag computations, stack-frame
mechanics, and large constant values. Kept are CFG shape as relations not
order, an order-insensitive operation multiset, call-graph position, small
constants and stack displacements (they identify locals and fields), operand
position for non-commutative operators, external callee names, and a
prototype keyed by storage location. Nobody stores block order. Nobody folds
constants into the primary identity.

**4. Most similarity measures are not metrics, and one is.** Approximate
graph edit distance (bipartite, Hausdorff, beam) has no triangle inequality
and exact GED is APX-hard; it is fine as DecBench's reporting number and
unusable as an index distance. The Weisfeiler-Lehman subtree kernel is an
explicit feature map, hence PSD, hence a pseudo-metric, deterministic, and
near-linear. Unit-cost tree edit distance is a true metric and applies to the
recovered region tree. Jaccard distance on WL label multisets is a metric.
Gromov-Wasserstein is the principled metric on isomorphism classes, and the
WL-meets-GW result (ICML 2022) is the bridge, but there is no usable Rust
optimal-transport stack, so it stays a research note.

**5. Inlining is the field's unsolved failure.** In the best tools, roughly
82 to 84 percent of failures involve differential inlining. Marcelli disabled
inlining in the benchmark to sidestep it. We should measure it, not assume it
away, and report the diff ratio on failures.

## The representation: Canonical Function Representation (CFR)

Three artifacts, computed together and versioned together, over LLIR after
SSA and copy propagation and before structuring introduces source-level
operators.

**CFR-G, the operator-typed SSA dataflow graph.** Nodes are SSA values and
memory states. A node's label is a tuple, never a name:

```
(op_kind, result_width_class, operand_arity, value_class, const_bucket, callee_class)
value_class  in {const, global_addr, stack_addr, function_input, phi, derived}
const_bucket in {0, 1, -1, small, pow2, pointer_like, large}
callee_class = resolved external name | import name | arity class for internal
```

Edges are positionally labelled operand edges, memory-dependence edges, and
control-dependence edges. Run three WL iterations, mixing commutatively for
commutative operators (`Add`, `Mul`, `And`, `Or`, `Xor`, `Eq`, `Ne`, phi) and
positionally for the rest. Drop shadow nodes: pure copies, and phis whose
inputs are identical. Positional edge labels matter: without them `a - b` and
`b - a` collapse under any permutation-invariant aggregation.

**CFR-C, the block-order-independent CFG labelling.** Seed each block with
`(in_degree << 8) | out_degree`, one WL iteration mixing predecessor labels
with distinct constants for taken and fallthrough edges, edge kinds
`{cond_true, cond_false, unconditional, switch}` with a precomputed back-edge
flag from the existing dominators. Fuse the CFR-G label into the block label
at each root operation (call, indirect call, store, conditional jump, return),
so topology and semantics land in the same feature.

**CFR-I, the typed interface record.** Return type, parameters by ABI
position, locals by frame offset, callee set, effect summary. Keys are storage
locations, never names. This is what DecBench matches on and what rev.ng's raw
function definition encodes.

**Outputs.** A sorted multiset of `(u32 feature_hash, u16 count)` pairs, a
single digest for the `identity` column, and the label multiset for kernel and
Jaccard use. Weight features by TF-IDF from a corpus count table and compare
with BSim's merge-join cosine using `min(cA, cB)^2` in the numerator, plus a
log-likelihood confidence so small functions cannot reach high confidence.
Ship it as `scheme = "glaurung-cfr-v1"` with an explicit `(major, minor,
settings)` triple in `schema_meta`. Any change to the mask list invalidates
every stored vector; BSim versions its strategy in the database for exactly
this reason. Include a `nosize` setting (collapse widths of 4 bytes and up)
from day one; it is the single switch that buys 32-to-64-bit matching.

**Two prerequisites found in the tree.** `VReg::Phys(String)` carries the
architectural register name through the IR and must be projected away in the
canonical form. `VReg::Temp` has no derivable width (`VReg::width()` returns
`None` for it), and the varnode seed requires one; either widen `Temp` to
carry a width or thread widths through the SSA pass. Also note that `BinOp`
mixes levels: `LogicalAnd` and `LogicalOr` are source-level operators sitting
beside bitwise `And` and `Or`, which is one reason to canonicalise before the
structuring pass.

## The identity ladder

All four schemes live in the existing `function_identity` table. Cheapest
first, each answering a different question.

| Rung | Scheme | Question it answers | Cost |
|---|---|---|---|
| L0 | WARP function GUID with constraints | Is this exactly a known build of a known function? | UUIDv5 over masked block bytes; equality lookup |
| L1 | Structural invariants: MD-index (top-down, bottom-up, relaxed), small-primes product over opcodes, block, edge, loop and SCC counts, call degree | Which functions changed between two builds? | Scalars, B-tree indexable |
| L2 | CFR feature vector | Which library function is this, across compilers and optimisation levels? | WL hash plus TF-IDF cosine |
| L3 | vSim-style value fingerprints | Same, with the best measured cross-compiler stability | Bounded LLIR emulation; later |

L1 delivers patch-diff ranking essentially outright. A kernel rebuild has zero
free compilation variables, the regime where even fuzzy hashes score well and
where BinDiff has worked for twenty years. It is the highest return per line
of code in any of the four reports.

Byte-level digests keep one role: file-level near-duplicates. Do not extend
CTPH to functions. TLSH is acceptable as a secondary signal on functions of
50 bytes or more with real entropy, and no further.

## Indexes and storage

The schema proposal with commentary is
[`03-schema.sql`](program-measures-2026-09-02/03-schema.sql). The decisions
that matter:

- **Flat scan until about 1e5 to 1e6 vectors.** Ghidra's own embedded BSim
  backend has no LSH index at all; it is an exact hash plus a linear scan. A
  six-thousand-function kernel diff needs no index. Add banding only when a
  measured corpus says so.
- **Inverted index on rare features** for L2 retrieval at scale, ordered by
  ascending corpus frequency so a prefix is the rarest tokens. Retrieve
  candidates by the query's highest-IDF features, then rescore exactly.
- **AllPairs for exact Jaccard joins.** Mann et al. (VLDB 2016) found the
  plain prefix filter competitive and PPJoin+ "rarely competitive".
- **MinHash over SimHash for binary sets**; hyperplane LSH only where the
  vector is TF-IDF weighted, as BSim does. Fixed seeds as constants, never a
  `RandomState`.
- **A BinaryFuse8 membership gate** per `(scheme, architecture)`: about 1.1
  bytes per key and a 3 ns probe answers "is this in any known library" before
  the index is touched. The `xorf` crate's default features are
  non-deterministic (measured: identical keys gave different bytes); build
  with defaults off.
- **Do not use** `sqlite-vec` (its ANN is compile-gated off and the Rust
  crate's build script enables neither flag), `sqlite-vss` (dead), `faiss-rs`
  (pinned to an old Faiss), or `instant-distance` (measured non-reproducible
  despite a seed; the rayon build loop is the source).
- **Provenance on both sides.** A library is keyed by `(name, version,
  variant, architecture, platform)`, and each match records which level
  resolved it, as BinDiff stores the winning algorithm per match.

## Signature libraries

The current library is a demo, not a mechanism. It holds thirty exact
32-byte prologues taken from this repository's own linked sample binaries, and
a linked binary is the contaminated input: with no relocation table, every
`call rel32` and RIP-relative `lea` is an absolute that changes on the next
link. FLIRT, FunctionID, SigKit and WARP all say the same thing: build from
`.a` archives, where the unlinked objects carry the relocation table that says
exactly which bytes are variant. The `object` crate we already depend on reads
archive members and section relocations. And no exact or masked scheme
crosses an optimisation level, so a corpus spanning gcc and clang across O0 to
O3 is not one library but N libraries sharing a name, keyed by `variant`.
Cross-variant matching is L2's job.

`lancelot-flirt` (Apache-2.0, actively released) parses and matches real
`.pat` and `.sig` files, and open signature sets exist; price that before
writing a masked matcher.

## Measurement protocol

No number from this work is comparable to anything unless it states the pool
size and the set of free compilation variables. The same tool, SAFE, scores
MRR 0.918 and 0.17 in two published papers on different protocols.

- **Corpus:** start on our own sample and fixture matrix, which already has
  matched builds across compilers and optimisation levels with DWARF intact.
  Then BinKit 2.0 (MIT) and the Cisco Talos dataset (MIT) so numbers drop
  into Marcelli's published tables. The BinKit NoInline lane matters most.
- **Tasks:** Marcelli's verbatim taxonomy (XO, XC, XC+XB, XA, XA+XO, XM, and
  XM by size), plus Shi's cross-bitness lane, which is the one that separates
  IR representations from token representations.
- **Ground truth:** DWARF, which we already ingest: same package, source file,
  line range and name. Apply the published filters so denominators match:
  drop functions under five blocks, PLT thunks, intrinsics, and duplicates by
  name and instruction hash.
- **Metrics:** AUC over positive and negative pairs, MRR10 and Recall@1 with
  100 negatives per positive, reported at pool sizes 100, 10k and 100k, with
  Recall@k curves and extraction cost per function.
- **Metric axioms as tests.** A property suite from Briand et al. (1996) and
  the metric axioms: symmetry, identity on the quotient, triangle inequality
  over sampled triples, and invariance assertions such as same source at O0
  versus O2 landing under a threshold. This is the part of the work that is
  literally a measurement theory, and it should ship with the first hash.

## The plan, merged and ranked

The four reports disagree on ordering in two places, resolved below. Effort
figures are the reports' engineering judgment, not measurements.

| # | Work | Effort | Delivers |
|---|---|---|---|
| 1 | Minimal harness on the in-house corpus with the protocol above; retro-score CTPH and the structural fingerprint | ~1 week | The ability to rank anything that follows |
| 2 | L1 structural invariants: MD-index, SPP, counts, rarity weighting; persisted as scalars | ~1 week | Patch-diff ranking at BinDiff quality on data we already compute |
| 3 | Width for `VReg::Temp`, projection of `Phys` names, commutativity table over `BinOp` and `CmpOp` | ~1 week | The two prerequisites for CFR |
| 4 | CFR-G and CFR-C: WL labelling, shadow elimination, sorted feature multiset, digest, `glaurung-cfr-v1`, version triple, `nosize` setting, property-test suite | 3 to 5 weeks | The core object and its metric |
| 5 | TF-IDF corpus table, merge-join cosine and confidence, rare-feature inverted index, flat scan | 1 to 2 weeks | L2 retrieval |
| 6 | Rebuild the signature library from `.a` with relocation masks (price `lancelot-flirt` first) and add WARP GUIDs as a scheme (`uuid` feature `v5`, one line) | 1 to 2 weeks | L0 and exact-toolchain naming; ecosystem interop |
| 7 | BinaryFuse8 gate, `siglib` provenance, `function_match` evidence | 3 days | Corpus-scale gating and auditability |
| 8 | Unsound local peephole normaliser before hashing (VexINE template: copy propagation, folding, CSE, dead-store elimination, opcode collapse), as a separate artifact from the decompiler IR | 1 to 2 weeks | Cross-optimisation invariance; measure the delta with #1 |
| 9 | BinKit and Cisco ingestion for externally comparable numbers | 2 to 3 weeks | Published-table comparability |
| 10 | RevDecode-style call-graph re-rank (Viterbi over a layered candidate graph) | 2 to 3 weeks | Improved rankings for every underlying matcher |
| 11 | Tree edit distance (APTED port) on the region tree | ~1k LOC | A true metric on recovered structure; a second opinion for patch diff |
| 12 | L3 value fingerprints; program-level rollup for clustering | 6 to 10 weeks | Best cross-compiler stability; family clustering |

**Disagreements resolved.** The foundations report ranks e-graph
canonicalisation fourth; the representations report says do not build it yet.
Verified negative: no published system applies equality saturation to lifted
binary IR, and Cranelift measures 1.13 e-nodes per class after rewriting,
which suggests little algebraic variation to recover. Do the cheap peephole
normaliser (#8) first and revisit e-graphs only if measurement shows
`x*2` versus `x<<1` and De Morgan variants are a material source of mismatch.
The similarity report wants the full external harness first; the foundations
report wants the hash first. The in-house corpus makes a one-week harness
possible, so it goes first and the external ingestion moves to #9.

## Do not build

- A GPU embedding model or a pre-trained assembly-token embedding. Keep
  `function_identity` pluggable so an external HermesSim or CLAP vector can
  be imported if someone wants one.
- Approximate GED as an index distance. Keep it for DecBench reporting.
- Spectral CFG distances: label-blind, and cospectral non-isomorphic graphs
  are common.
- CTPH at function granularity, and TLSH below 50 bytes.
- A new IR. Nothing argues for replacing LLIR with p-code, VEX or LLVM. Our
  `Op` set is already p-code-shaped; the leverage is entirely in the
  canonical projection.
- The SQLite vector extensions and the ANN crates named above.

## Sources

The four reports, each with its own bibliography and verification notes:

1. [Binary function similarity literature](program-measures-2026-09-02/01-binary-similarity-literature.md), 39 sources, classical and learned, with the independent evaluations.
2. [Foundations: distances, kernels, canonical forms, quotients](program-measures-2026-09-02/02-program-measures-foundations.md), 108 URLs across eight areas.
3. [Signature schemas and indexes](program-measures-2026-09-02/03-signature-schemas-and-indexes.md) with the [schema DDL](program-measures-2026-09-02/03-schema.sql), read from FLIRT, Lumina, FunctionID, BSim, WARP, SigKit, Diaphora, BinExport, radare2, capa, angr, ghidriff and Nucleus source.
4. [Program representations and per-function fact schemas](program-measures-2026-09-02/04-program-representations-and-schemas.md), 93 URLs, Ghidra, Binary Ninja, angr, BAP, Miasm, RetDec, Reko, rev.ng, Remill, MLIR efforts, SLEIGH and Sail, e-graphs.

## Execution status

Maintained by the orchestrating session; one row per plan item. "Branch" is
the lane's worktree branch until it is merged into `master`.

| # | Item | State | Branch / commit | Notes |
|---|---|---|---|---|
| 0 | Scaffold `src/identity/` | landed on `identity-base` | `b5d777da` | placeholders only |
| 1 | Measurement harness | on `identity-integration` | `bdbf0bcd` | `tests/identity_retrieval/`, `docs/development/identity-measurement.md`; CTPH at chance on every lane; Python fingerprint AUC 0.58 XO, 0.73 XC, 0.52 XM (pool ~380) |
| 2 | L1 structural invariants | merged (integration line) | `ddc9ff00`, scored `cbd7b199` | `src/identity/structural/`, binding, `function_structural` KB table, `glaurung diff` MD-index rematch; 71.8% of 2,131 same-name gcc O0/O2 pairs share an MD-index triple. Harness AUC (debug): in-house XO 0.75, XC-O0 0.94, XC-O2 0.72, XM 0.70; Dataset-1 XO 0.83, XC 0.89, XM 0.80, XB 0.90, XA-arm64 0.95; MIPS lanes noisy. Found: CFG discovery is not bit-reproducible (per-function wall-clock budget) |
| — | CFG discovery non-determinism (found by #2 scoring) | diagnosed; harness fix merged (integration line) | diagnosis `68dc6310`, harness fix `f9411aa8` | `timeout_ms` (100 ms per function, `cfg/budgets.rs`) truncates walks under load: 129 to 260 of 1,126 functions flap per run pair on a loaded box, none on a quiet one. The harness now runs with an unbounded per-function budget (`tests/identity_retrieval/`): scores are bit-reproducible across 3 consecutive runs, and the MIPS lanes are no longer exempted. Production fix (step counts instead of wall clock, ~150 to 300 LOC, moves all four fixture baselines) is a separate follow-up (`docs/design/cfg-discovery-determinism-2026-09-02.md`) |
| 3+4 | CFR core with local width inference | merged (integration line) | `6781c50b` | `src/identity/cfr/` (15 modules), `glaurung.analysis.cfr_signatures_path`, KB scheme `glaurung-cfr-v1`; no `src/ir/` edits. Measured unweighted on a release build: Recall@1 XO 51/341 = 15.0%, XC 148/309 = 47.9%, whole slice 44/594 = 7.4% against CTPH's 0.32%; local width inference leaves 2.21% of SSA values Unknown. TF-IDF weighting (#5) and the peephole normaliser (#8) are still out |
| 5 | TF-IDF, cosine confidence, inverted index | merged (lane) | `LANE_SHA` | `src/identity/cfr/weights.rs` (IDF `ln((N+1)/(df+1))` quantised into BSim's 512 buckets, `weights_id` over the version triple and every bucket), BSim's significance in `similarity.rs` (`calculateSignificance` verbatim from Ghidra source, its five `lshweights_64.xml` constants, self-significance as a theorem rather than a clamp), `python/glaurung/llm/kb/cfr_index.py` (schema section 4: `feature_vector` deduplicated and refcounted, `function_vector`, `feature_weight`, `feature_posting` at K=32 rarest, flat scan at or below 1e5 vectors), and a `CfrScheme` in the shared harness in three configurations. **Measured**, release, held-out half against an unweighted control on the identical population: in-house XO-gcc AUC 0.7800->0.8592 R@1 0.1872->0.4064 (187 queries, pool 200), XO-clang 0.7419->0.8152 R@1 0.1124->0.2809 (178/184), XC-O0 0.9679->0.9938 (241/243), XC-O2 0.8935->0.9461 R@1 0.5116->0.5698 (172/184), XM 0.7625->0.8131 R@1 0.1243->0.3333 (177/184); Dataset-1 XO 0.8880->0.9902 (18/106), XB 0.9642->0.9844 R@1 0.5667->0.8000 (30/127), XA-arm64 0.9185->0.9855 (19/115). The plan's hypothesis holds: **XO gains most on both corpora and on every metric**, and the ranking gains (+0.25 MRR10) far outrun the AUC gains (+0.08) -- a lane judged on AUC alone would have called this modest. Unweighted whole-corpus CFR also lands in the shared protocol for the first time: in-house XC-O0 AUC 0.9663 / MRR10 0.9162, XM 0.7296 (above `structural`'s 0.7026); Dataset-1 XO 0.913, XC 0.964, XM 0.881, XB 0.935, XA-arm64 0.913, beating `structural` on four of five. Both Dataset-1 MIPS rows score **zero** and the test asserts the zero: `src/ir/lift/` has no MIPS lifter, so extraction refuses rather than returning an empty vector. Extraction 1,810 us/function release, 12,004 debug, retrieval numbers bit-identical between them. Deliberately out of scope: refitting BSim's five constants (they were fitted to NSA p-code features, so the calibration is borrowed and the docs say so), LSH banding (`vector_band`, unneeded below 1e5), `nosize` against the XB lane, and a Rust binding for the KB's query loop (Python merge-join over a few hundred candidates is not the bottleneck; extraction is) |
| 6 | Signature library from `.a` + WARP GUIDs | merged (integration line) | `c8865418` | `src/identity/warp.rs` (WARP-compatible UUIDv5 function GUIDs, x86/x86-64, KB scheme `warp-function-guid-v1`) and `src/flirt/{archive,crc16}.rs` (masked-byte signatures built from `.a` relocation tables). 16 relocation-masked signatures from `libmathlib.a` name 16/16 functions across two link layouts, against 0/16 for the unmasked exact-prologue library, with 0 false positives over 3,568 functions. `lancelot-flirt` was priced and declined; the reason is in [`reference/function-signature-libraries.md`](../reference/function-signature-libraries.md). Deliberately out of scope on this lane: AArch64 GUIDs, consuming IDA `.sig`/`.pat`, the `siglib` KB table, and the BinaryFuse8 gate (#7) |
| 7 | BinaryFuse8 gate, provenance, evidence | queued | | after #6 |
| 8 | Peephole normaliser | queued | | after #4 and #1 |
| 9 | Cisco Dataset-1 ingestion | on `identity-integration` | `00df0686` | 17 GB under `~/.cache/glaurung/corpora/`; XA, XB, XA+XB lanes added; CTPH at chance everywhere. Found: discovery disagrees with IDA on 86% of mips32 and 57% of mips64 functions (`docs/development/corpora.md`). BinKit deliberately not fetched |
| 10 | Call-graph re-rank | queued | | after #5 |
| 11 | Tree edit distance on the region tree | blocked | | `structure_v2` under concurrent change |
| 12 | Value fingerprints; clustering rollup | queued | | after #5 |
| — | MIPS big-endian discovery defect (found by #9) | fixed on `identity-integration` | diagnosis `55d5239b`, fix `441f669d` | `parse_exec_regions` read the container endianness; mips32 86% and mips64 57% degenerate CFGs both to 0% on Cisco Dataset-1; `dectest @smoke` unchanged |
