# Binary Function Similarity: Literature Survey for Glaurung

Scope: classical and learned binary code similarity, with emphasis on what is
*deterministically implementable in Rust without a GPU at inference time*, and
on which representations survive **independent** re-evaluation. Every URL below
was fetched or returned by a search during this survey. Where I could not read a
paper's own numbers I write "not verified".

---

## Part 1 - Annotated bibliography

### A. Classical structural / deterministic tools

**1. Dullien & Rolles, "Graph-based Comparison of Executable Objects", SSTIC 2005.**
<https://static.googleusercontent.com/media/zynamics.com/en//downloads/bindiffsstic05-1.pdf>
(also Flake, "Structural Comparison of Executable Objects", DIMVA 2004,
<https://eldorado.tu-dortmund.de/bitstreams/5bd511dd-bb20-47a0-97cc-21d842a7b6c5/download>)
*Representation:* call graph + per-function CFG; instructions abstracted to
mnemonics. *Metric:* iterative fixed-point propagation. Start from a small set of
high-confidence "fixedpoints" produced by structural selectors, then propagate
matches through call-graph and CFG neighbourhoods until no improvement. The
**Small Primes Product (SPP)** signature (verified from the paper text): map each
mnemonic to a distinct small odd prime via `tau`, take the product of primes over
the instructions of a block/function mod 2^64. Equal products imply an
order-independent permutation match; the paper derives the collision bound
explicitly. *Invariances:* instruction reordering, register allocation (mnemonics
only), address changes. Not cross-architecture. *Index:* none needed - SPP is a
64-bit integer, indexable directly. *Numbers:* case study only, not a retrieval
benchmark. *Deterministic, no GPU: yes.*

**2. Dullien, Carrera, Eppler, Porst, "Automated Attacker Correlation for
Malicious Code", 2010** (MD-index). <https://apps.dtic.mil/sti/html/tr/ADA546372/index.html>
Formula verified from BinDiff source, `graph_util.h`
(<https://raw.githubusercontent.com/google/bindiff/main/graph_util.h>, Apache-2.0):
per edge, `md = 1.0 / (sqrt(2)*indeg(src) + sqrt(3)*outdeg(src) + sqrt(5)*indeg(dst)
+ sqrt(7)*outdeg(dst) + sqrt(11)*level(src) + sqrt(13)*level(dst))`, where `level`
is topological order; node MD-index sums its in/out edges, graph MD-index sums all
edges (sorted before summation to control float rounding). Weights `{2,3,5,7,0,0}`
for the level-free variant. *Invariances:* a graph invariant - robust to node
renaming and address change, sensitive to real CFG edits (which is the point for
patch diffing). *Index:* a single REAL column. *Deterministic, no GPU: yes.*

**3. BinDiff (open-sourced Sept 2023), Google, Apache-2.0.**
<https://github.com/google/bindiff>, docs <https://github.com/google/bindiff/blob/main/docs/concepts.md>
*Representation:* call graph + flow graphs + raw bytes + strings. *Matching:* a
ladder of ~15 function heuristics tried in quality order - raw-byte hash, name
hash, flow-graph MD-index, call-graph MD-index, edges-MD-index, SPP prime
signature, edges-proximity MD-index, relaxed MD-index, string references, loop
count, call sequence, address sequence - then basic-block matching (edges prime
product, byte hash with >=4 instruction minimum, prime product, call-reference,
string reference, Lengauer-Tarjan dominator variants, loop entry/exit, propagation).
*Scoring:* function similarity is a weighted blend (approx. 50% flow-graph MD-index
difference, 25% matched edges, 15% matched blocks, 10% matched instructions) times a
sigmoid-squashed confidence; binary similarity blends matched edges/blocks/functions/
instructions plus call-graph MD-index difference. *Invariances:* excellent for
same-compiler patch diffing; weak cross-optimization, none cross-architecture.
*Deterministic, no GPU: yes.* This is the reference design for Glaurung use case (b).

**4. Diaphora, Koret, AGPL-3.0.** <https://github.com/joxeankoret/diaphora>,
heuristics <https://github.com/joxeankoret/diaphora/wiki/Heuristics-and-their-explanation>
51 heuristics executed in a fixed order over a SQLite export, expressed as SQL
joins - Best / Partial / Unreliable tiers. Signals: MD5 of function bytes (RVA+hash,
order+hash, non-relative hash), name equality, node/edge counts, MD-index (weighted
higher when *rare*, i.e. 1-2 occurrences), same constants and constant ordering,
cyclomatic complexity, in/out degree, Tarjan SCC + SPP for functions >10 blocks,
pseudocode fuzzy hash (DeepToad) and AST variants, then recursive caller/callee
propagation from confirmed matches, then brute force. Glaurung's greedy cross-name
rematch at 0.85 is the Diaphora pattern.

**5. Karamitas & Kehagias, "Efficient features for function matching between
binary executables", SANER 2018** (the "KOKA" CFG hash used by Diaphora).
<https://doi.org/10.1109/saner.2018.8330221>; implementation
<https://github.com/joxeankoret/diaphora/blob/master/jkutils/graph_hashes.py>
*Representation:* CG+CFG features reduced to small-primes-products over node
classes. *Numbers:* not verified (paywalled). *Deterministic, no GPU: yes.*

**6. FunctionSimSearch, Dullien / Google Project Zero, Apache-2.0, archived 2026.**
<https://github.com/googleprojectzero/functionsimsearch>, docs
<https://github.com/googleprojectzero/functionsimsearch/blob/master/doc/01-motivation-and-overview.md>
*Representation:* CFG graphlets (small subgraphs), mnemonic n-grams, large
immediates not divisible by 4; operands, struct offsets and strings ignored.
*Metric:* weighted **SimHash to 128 bits**, Hamming distance. *Index:* bit-sampling
LSH via random bit permutations. Feature weights can be *learned* by L-BFGS from
labelled pairs. *Numbers:* the project docs report roughly 40% true-positive rate at
acceptable false-positive levels. *Deterministic, no GPU: yes.* This is the closest
published analogue of Glaurung's current structural fingerprint.

**7. Ghidra BSim, NSA, Apache-2.0.** <https://github.com/NationalSecurityAgency/ghidra>;
tutorial <https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_Intro.html>;
weights doc <https://www.ghidradocs.com/11.0.1_PUBLIC/help/BSim/help/topics/BSim/FeatureWeight.html>;
internals reverse-engineered by Quarkslab
<https://blog.quarkslab.com/bsim-explained-once-and-for-all.html>
**The single most directly transferable design in this survey.**
*Representation:* **high P-code** - the decompiler's normalized SSA data-flow graph
after dead-code elimination and stack abstraction. Features are produced by a
**1-dimensional Weisfeiler-Leman relabelling**: 3 iterations over the data-flow
graph, 1 over the block control-flow graph. Varnode seeds encode byte width,
defining op, constness, global/input flags; shadowed copy varnodes are removed via
dominator analysis; commutative ops (ADD, XOR, MULTIEQUAL) accumulate inputs
order-independently with CRC32-based fuzzy hashing. Block seeds encode in/out
degree; conditional edges mix with distinct constants (0x777 for true,
0x777 xor 0x7abc7abc for false) so a feature records *which path* reached it. At
each root op (CALL, CALLIND, STORE, CBRANCH, RETURN) the block hash is blended with
the output varnode's expression hash. Result: a sorted, run-length-factorised
multiset of 32-bit `(count:hash)` features.
*Metric:* TF-IDF weighting - IDF `log(N/df(f))` quantised through a shipped table of
the 1000 most common hashes into 512 weight buckets; TF `1 + log2(tf)`. Similarity is
a merge-join cosine in O(n+m): `sum over shared f of min(cA,cB)^2` divided by
`sqrt(sum cA^2) * sqrt(sum cB^2)`.
*Index:* LSH over the weighted vectors; backends H2 (embedded), PostgreSQL (with a C
extension), Elasticsearch. *Invariances:* strong cross-optimization and
cross-compiler because P-code normalization erases ISA and register naming; the
Quarkslab analysis flags small functions (sparse vectors), inlining/LTO, and IDF
tables trained on the wrong domain as the failure modes. *Deterministic, no GPU: yes*
- the only "training" is a corpus frequency count. *Numbers:* no published
recall@k on a standard benchmark that I could verify.

**8. WARP, Vector 35, repo license NOASSERTION ("Other").**
<https://github.com/Vector35/warp>, docs <https://docs.binary.ninja/guide/warp.html>,
blog <https://binary.ninja/2025/08/22/warp.html>
*Representation:* exact, relocation-masked bytes. Basic-block GUID = UUIDv5 over the
in-order instruction bytes with namespace `0192a178-7a5f-7936-8653-3cbaa7d6afe7`,
after (a) zeroing every *relocatable* instruction (direct calls/jumps with absolute
targets; constant-pointer computations such as aarch64 `add x1, x1, #0xf10`),
(b) dropping NOPs, (c) dropping architecture-dependent self-assignment NOPs (x86_64
keeps `mov edi, edi` because of implicit zero-extension, x86 drops it). Function GUID
= UUIDv5 over the basic-block GUIDs sorted by descending start address, namespace
`0192a179-61ac-7cef-88ed-012296e9492f`. **Constraints** disambiguate GUID collisions:
tuples of (called / caller / adjacent function GUID, optional byte offset), hashed
under namespace `019701f3-e89c-7afa-9181-371a5e98a576`; constraint matching is
user-configurable. Container: FlatBuffers (`signature.fbs`). *Invariances:* address
and relocation only. It is a *stronger FLIRT*, not a similarity metric.
*Deterministic, no GPU: yes.* Glaurung's `function_identity(scheme, identity)` table
already names this as a target scheme.

**9. Catalog1** (evaluated as a fuzzy-hash baseline by Marcelli et al.): raw-byte
min-hash signatures at sizes 16 and 128. Numbers below.

### B. Classical semantic approaches

**10. Gao, Reiter, Song, "BinHunt", ICICS 2008.**
<https://people.eecs.berkeley.edu/~dawnsong/papers/2008%20binhunt_icics08.pdf>
Symbolic execution + a theorem prover to check basic-block *semantic* equivalence,
feeding a maximum-common-subgraph match over CFGs. Sound but O(expensive);
per-block SMT is not viable at corpus scale. Numbers: not verified.

**11. Luo, Ming, Wu, Liu, Zhu, "CoP", FSE 2014 / TSE 2017.**
<https://faculty.ist.psu.edu/wu/papers/cop-fse2014.pdf>,
<https://faculty.ist.psu.edu/wu/papers/cop-tse-2017.pdf>
Longest-common-subsequence of *semantically equivalent basic blocks*, equivalence
decided by symbolic execution + theorem proving. Explicitly targets obfuscation
resilience for plagiarism detection. Numbers: not verified.

**12. Egele, Woo, Chapman, Brumley, "Blanket Execution" (Blex), USENIX Sec 2014.**
<https://iseclab.org/files/publications/Egele2014Blanket_Execution.pdf>
Execute every function repeatedly from random initial states until all instructions
are covered; the *side effects observed* (values written, syscalls, stack behaviour)
form the feature vector. *Invariance:* strong against syntax; requires a working
executor and is unsuitable for a static SQLite index. Numbers: not verified.

**13. Wang & Wu, "IMF-sim", ASE 2017.**
<https://home.cse.ust.hk/~shuaiw/papers/IMF.pdf>
In-memory fuzzing to drive functions and collect behavioural features; the dynamic
successor to Blex. Numbers: not verified.

**14. Ming, Xu, Jiang, Wu, "BinSim", USENIX Sec 2017.**
<https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-ming.pdf>
Trace-based semantic diffing: slice execution traces by system call, then check
*conditional equivalence* of the slices with an SMT solver. Designed to defeat
obfuscation where block-centric methods fail. Numbers: not verified.

**Assessment of B:** all four are trace- or solver-driven. They establish that
*semantics* is the invariant that matters, but none is implementable as a
SQLite-resident index. Their descendants that *are* implementable are BSim (static
IR features) and vSim (bounded emulation, entry 27).

### C. Learned approaches

**15. Feng et al., "Genius", CCS 2016.** <https://cs.ucr.edu/~heng/pubs/genius-ccs16.pdf>
ACFG (attributed CFG: per-block numeric features) + codebook clustering + LSH.
Introduced the ACFG that everything after it uses. Numbers: not verified.

**16. Xu, Liu, Feng, Yin, Song, Song, "Gemini", CCS 2017.**
<https://www.cs.ucr.edu/~heng/pubs/gemini-ccs17.pdf>
ACFG + Structure2vec GNN + Siamese training. 7 hand-engineered block features.
Own numbers not verified; independently re-measured below.

**17. Ding, Fung, Charland, "Asm2Vec", IEEE S&P 2019.**
<https://www.dmas.lab.mcgill.ca/fung/pub/DFC19sp.pdf>
PV-DM over random walks of the CFG; **single-architecture by construction**.

**18. Massarelli et al., "SAFE", DIMVA 2019.** <https://arxiv.org/abs/1811.05296>,
code <https://github.com/gadiluna/SAFE>. word2vec instruction embeddings + self-attentive
RNN over a flat, length-capped instruction sequence.

**19. Li, Gu, Dullien, Vinyals, Kohli, "Graph Matching Networks" (GNN/GMN), ICML 2019** -
evaluated by Marcelli et al. as `[40]`. Two modes: an embedding GNN (indexable) and a
cross-graph-attention GMN (pairwise only, not indexable).

**20. Pei, Xuan, Yang, Jana, Ray, "Trex", 2020 / TDSC 2023.**
<https://www.cs.columbia.edu/~suman/docs/trex_final.pdf>, code
<https://github.com/CUMLSec/trex> (MIT). Transformer pre-trained on **micro-traces**
(forced execution) then fine-tuned for similarity. Cross-architecture.

**21. Li, Qu, Yin, "PalmTree", CCS 2021.**
<https://gangw.cs.illinois.edu/class/cs562/papers/PalmTree-ccs21.pdf>, code
<https://github.com/palmtreemodel/PalmTree> (MIT). BERT-style assembly instruction
embedding with def-use-aware pre-training objectives. x86 only.

**22. Wang et al., "jTrans", ISSTA 2022.** <https://netsec.ccert.edu.cn/files/papers/issta22-jtrans.pdf>
Transformer with *jump-target-aware* position sharing. Ships **BinaryCorp**, from
ArchLinux packages: BinaryCorp-3M (1,612 train projects / 3,126,367 functions) and
BinaryCorp-26M (7,845 projects / 21,085,338 train functions; 4,791,673 test).
*Verified numbers* (BinaryCorp-3M, poolsize 10000, avg MRR / Recall@1):
Gemini 0.165/0.132, SAFE 0.320/0.246, Asm2Vec 0.366/0.302, GraphEmb 0.219/0.169,
OrderMatters 0.263/0.200, Genius 0.214/0.179, jTrans-Zero 0.414/0.340,
**jTrans 0.623/0.571**. On BinaryCorp-26M poolsize 32 the same table gives SAFE
0.918 MRR - see the protocol warning in the synthesis.

**23. Yang et al., "Asteria" DSN 2021 / "Asteria-Pro" TOSEM 2023.**
<https://ar5iv.labs.arxiv.org/html/2108.06082>, <https://dl.acm.org/doi/10.1145/3604611>
Tree-LSTM over decompiler ASTs. Numbers: not verified.

**24. Yu et al., "CodeCMR"/BinaryAI (Tencent)** - evaluated inside Marcelli et al.;
and Jiang et al., **"BinaryAI", ICSE 2024**, <https://arxiv.org/abs/2401.11161>
(binary-to-source SCA). Numbers below.

**25. Zhu et al., "kTrans", 2023.** <https://ar5iv.labs.arxiv.org/html/2308.12659>,
code <https://github.com/Learner0x5a/kTrans-release> (MIT). Transformer fed explicit
assembly *knowledge* (operand roles, EFLAGS effects) rather than raw tokens.
Numbers: not verified.

**26. Wang, Gao, Zhang et al., "CLAP", ISSTA 2024.**
<https://netsec.ccert.edu.cn/files/papers/issta24-clap.pdf>, code
<https://github.com/hustcw/clap>. Contrastive language-assembly pre-training (CLIP
for binaries), aimed at few/zero-shot transfer. Independently measured below.

**27. Wang, Gao, Zhang et al., "CEBin", ISSTA 2024.**
<https://netsec.ccert.edu.cn/files/papers/issta24-cebin.pdf>, code
<https://github.com/Hustcw/CEBin>. Embedding recall stage + comparison rerank stage -
the retrieve-then-rerank pattern, which is the right architecture for scale.

**28. He, Lin, Weng, Zhao, Gan, Chen, Ji, Wang, Xue, "Code is not Natural Language:
... Semantics-Oriented Graph Representation" (HermesSim), USENIX Sec 2024.**
<https://www.usenix.org/system/files/usenixsecurity24-he-haojie.pdf>, code
<https://github.com/NSSL-SJTU/HermesSim> (license "Other").
**The most important learned result for Glaurung.** *Representation:* the
**Semantics-Oriented Graph (SOG)** built from Ghidra P-code - a sea-of-nodes-style
graph carrying *data* relations (def-use), *control* relations, and, crucially,
**effect relations** (ordering constraints between memory/IO operations that neither
data nor control edges express). No positional identifiers for instructions, because
semantics is position-independent. *Metric:* GNN embedding + cosine. *Numbers*
(verified, Cisco/Marcelli dataset, Recall@1/MRR, pool 100 unless noted):

| | XA | XO | XC | XM(100) | XM(10000) | params |
|---|---|---|---|---|---|---|
| SAFE | 13.4/26.4 | 21.1/27.5 | 20.1/27.6 | 9.9/18.9 | 1.4/2.3 | 8.93M |
| Trex | 31.2/42.1 | 46.8/53.1 | 45.4/52.5 | 24.4/34.4 | 8.6/11.1 | 61.8M |
| GMN | 72.6/81.7 | 50.3/58.1 | 52.3/59.8 | 44.7/53.7 | 10.5/15.9 | 60.5K |
| jTrans (x64 lanes) | - | 66.9/76.0 | 65.0/73.8 | - | - | 87.9M |
| **HermesSim** | **95.5/97.5** | **81.0/85.3** | **78.0/83.2** | **74.5/80.2** | **43.8/50.8** | **388K** |

HermesSim beats jTrans while using **226x fewer parameters**. The win is the
representation, not the model capacity.

**29. VenkataKeerthy et al., "VexIR2Vec", TOSEM 2025.**
<https://arxiv.org/abs/2312.00507v2>, <https://dl.acm.org/doi/10.1145/3721481>,
code <https://github.com/IITH-Compilers/VexIR2Vec> (AGPL-3.0).
*Representation:* VEX-IR normalized by compiler-style peephole transformations, then
"peepholes" (random walks over the CFG) embedded via knowledge-graph entity
embeddings, combined by a small Siamese feed-forward net (VexNet). *Reported:* 2.7M
functions / 15.5K binaries / 7 projects, 12 compilers, x86 and ARM; MAP 0.76 on
search (46% over nearest baseline), 3.1-3.5x faster than closest baselines; CPU
parallel library, no GPU stated for inference. Numbers taken from the paper's
abstract page, not from an internal table (partially verified).

**30. Liu, Tang, Nie, Wu, Zhang, Tang, "KEENHash", ISSTA 2025.**
<https://rroscha.github.io/assets/pdf/keenhash.pdf>, <https://doi.org/10.1145/3728911>
*Verified:* condenses a whole **program** into one fixed-length embedding by
K-Means-clustering LLM-derived function embeddings plus feature hashing.
**>=215x faster** than SoTA function-matching tools; 5.3 billion similarity
evaluations in 395.83 s where SigmaDiff/BinDiffMatch would need 323 and 56 days;
outperforms 4 SoTA methods by >=23.16% on program clone search over 202,305 binaries.
Relevant to Glaurung use case (d), malware family clustering - the *program-level*
rollup is the right shape there, even if the per-function embedder differs.

**31. Ren, Che, Gilman, De Carli, Walls, "RevDecode", USENIX Sec 2025.**
<https://www.usenix.org/system/files/usenixsecurity25-ren.pdf>
*Verified:* not a matcher - a **re-ranking framework**. Represents a binary as a
directed layered graph (layers = unknown functions, nodes = candidate matches),
then runs a Viterbi-style decode to pick the globally most *relevant* assignment
using call-graph and adjacency context. Improves rankings for **56.3% to 98.8%** of
evaluated functions across multiple datasets and multiple underlying matchers. GPU
variants are for speed only; the algorithm is a dynamic program.

### D. Independent evaluations, benchmarks and surveys (the load-bearing evidence)

**32. Marcelli, Graziano, Ugarte-Pedrero, Fratantonio (Cisco Talos), Mansouri,
Balzarotti (EURECOM), "How Machine Learning Is Solving the Binary Function
Similarity Problem", USENIX Sec 2022.**
<https://www.usenix.org/system/files/sec22-marcelli.pdf>, artifacts
<https://github.com/Cisco-Talos/binary_function_similarity> (**MIT**).
*Dataset-1:* 7 projects (ClamAV, Curl, Nmap, OpenSSL, Unrar, Z3, Zlib) -> 24
libraries, GCC and Clang x 4 versions each (2015-2021), x86-64/ARM/MIPS in 32 and 64
bit (6 arch combos), O0/O1/O2/O3/Os, **inlining disabled**; 5,489 binaries,
26.8M functions, 18.2M discarded for having <5 basic blocks, 438,981 unique
functions in the tests. *Tasks:* XO, XC, XC+XB, XA, XA+XO, XM (+ XM-S/M/L by block
count: <20, 20-100, >100). *Protocol:* AUC on 50k positive + 50k negative pairs per
task (700k pairs total); MRR10 and Recall@1 on 1,400 positives with **100 negatives
per positive**; duplicates removed by name and instruction hash.
*Verified headline numbers (Dataset-1):*

| Approach | XC | XA | XM | XM MRR10 | XM R@1 |
|---|---|---|---|---|---|
| Catalog1, bytes, size 128 | 0.73 | 0.43 | 0.55 | 0.12 | 0.09 |
| FSS graphlets (G) | 0.72 | 0.69 | 0.70 | 0.26 | 0.20 |
| FSS G+M+I | 0.73 | 0.58 | 0.65 | 0.15 | 0.09 |
| Zeek (strands, direct) | 0.84 | 0.84 | 0.84 | 0.28 | 0.13 |
| GNN (s2v) + Gemini's 7 manual features | 0.81 | 0.80 | 0.81 | 0.36 | 0.28 |
| GNN (s2v) + BoW of 200 opcodes | 0.81 | 0.78 | 0.81 | 0.36 | 0.26 |
| GNN (s2v) + no node features | 0.69 | 0.69 | 0.70 | 0.12 | 0.07 |
| GNN (Li et al.) + BoW opcodes | 0.86 | 0.86 | 0.87 | 0.52 | 0.44 |
| GMN (Li et al.) + BoW opcodes | 0.85 | 0.86 | 0.86 | 0.53 | 0.45 |
| SAFE (n.asm 250) | 0.82 | 0.82 | 0.83 | 0.22 | 0.09 |
| Asm2Vec | 0.77 | 0.60 | 0.65 | 0.12 | 0.07 |
| CodeCMR/BinaryAI (CFG+IR+ints+strings) | 0.98 | 0.98 | 0.98 | 0.86 | 0.83 |

Also verified: with **one** free variable at a time, byte hashes are already good
(Catalog1 size-128 AUC 0.99 across compiler *version*, 0.92 across optimization) and
graphlets carry cross-architecture (FSS-G 0.81); with several free variables both
collapse. GNN with a **bag-of-words of opcodes** matches Gemini's hand-engineered
features and is 4x faster to featurize (1.66 s vs 7.18 s per 100 functions);
word2vec instruction embeddings did **not** raise AUC over BoW. Swapping BoW of
opcodes for BoW of **IDA microcode (IR)** raised XM MRR10 from 0.58 to 0.62. The
vulnerability task (10 OpenSSL functions, 8 CVEs, into Netgear R7000 ARM32 and
TP-Link Deco-M4 MIPS32 firmware) shows high MRR10 hiding terrible individual ranks.
CodeCMR was evaluated *by its own authors on Marcelli's data*, not reimplemented -
treat its row as promising but not independently replicated.

**33. Kim, Kim, Cha, Son, Kim, "Revisiting Binary Code Similarity Analysis using
Interpretable Feature Engineering and Lessons Learned" (TikNib/BinKit), TSE 2022.**
<https://wsp-lab.github.io/papers/kim-tse22.pdf>, dataset
<https://github.com/SoftSec-KAIST/BinKit> (**MIT**).
*BinKit* (paper version): 243,128 binaries from 51 GNU packages, 36,256,322
functions, 1,352 option combinations; **BinKit 2.0** (repo): 371,928 binaries,
1,904 combinations, 8 architectures (x86_32/64, ARM 32/64 LE, MIPS 32/64 LE+BE),
GCC 4.9.4-11.2.0, Clang 4.0.0-13.0.0, O0/O1/O2/O3/Os/Ofast, plus **Normal, SizeOpt,
PIE, NoInline, LTO and Obfuscation (Obfuscator-LLVM SUB/BCF/FLA and combined)**
sub-datasets. Ground truth: same source file, same line numbers, same package.
Filtering removed ~40% (non-.text, PLT), ~4% (compiler intrinsics), ~54% of the
remainder (duplicates).
*TikNib:* purely numeric **presemantic** features - basic block / CFG edge / natural
loop / SCC counts from the CFG, instruction counts per Capstone-derived semantic
group, and 6 call-graph features (unique callers, callees, ...). Similarity = mean
over features of `1 - |A_f - B_f| / |max(A_f, B_f)|` (relative difference), with
greedy forward feature selection maximizing ROC AUC, 10-fold.
*Verified numbers:* AUC **>0.98** in nearly all one-variable-free tests; 0.95 with
all three Obfuscator-LLVM options on; the deliberately-hard "Bad" cases (ARM32/GCC4/O0
vs MIPS64BE/Clang7/O3) drop to **0.93**, and to **0.91** with obfuscation added.
No-inline lane degrades with optimization: O1 0.995, O2 0.981, O3 0.967.
Against VulSeeker's own datasets: TikNib 0.9724 (ASE1) and 0.9783 (ASE3) versus
VulSeeker's reported 0.99 and 0.8849. Heartbleed case study: average rank 1.19 and
precision@1 0.89 across 552 option pairs. Firmware study: identifying CVE-2015-1791
across 52M functions in 1,124 IoT images, TikNib top-5 5/5 correct vs Gemini 2/5 and
VulSeeker 3/5. Feature extraction: **0.02-1.03 ms per function** (IDA preprocessing
dominates).
*Crucial caveat, and Marcelli et al. say so explicitly:* TikNib varies **one**
variable at a time. Marcelli's Table 1 shows even fuzzy hashes score 0.92-0.99 in
that regime. TikNib's result is "cheap features suffice when the search is narrow",
not "cheap features suffice in general".

**34. Shi, Chen, Xiao, Li, Xu, Qiu, Zhang, Qi, Li, Chen, Zou, Liu, Huo, "A Large
Scale Study of AI-based Binary Function Similarity Detection Techniques for Security
Researchers and Practitioners", arXiv 2511.01180, Nov 2025.**
<https://arxiv.org/pdf/2511.01180>
The newest independent evaluation. **BinAtlas**: 12,453 binaries, >7M functions;
**BinAres**: 12,291 binaries with 54 real 1-day CVEs in IoT firmware. Nine tools.
*Verified numbers (non-inlined BinAtlas, Recall@1):*

| Tool | XO | XC | XB | XBCO | XA | XM | XM-100k |
|---|---|---|---|---|---|---|---|
| Asm2Vec | 0.1 | 0.0 | 0.0 | 0.1 | - | - | - |
| PalmTree | 42.8 | 41.7 | 2.3 | 24.7 | - | - | - |
| jTrans | 56.9 | 56.8 | 5.8 | 34.6 | - | - | - |
| CLAP | 83.8 | 81.6 | 25.4 | 53.8 | - | - | - |
| SAFE | 17.7 | 14.3 | 0.4 | 9.7 | 0.2 | 5.5 | 5.0 |
| Gemini | 42.1 | 48.3 | 30.3 | 30.7 | 4.6 | 15.4 | 12.6 |
| GMN | 64.7 | 75.3 | 76.8 | 59.2 | 61.3 | 45.0 | 32.6 |
| **HermesSim** | **94.6** | **95.9** | **97.7** | **94.0** | **93.6** | **88.5** | **83.0** |
| DeJina (fine-tuned jina code embedder on decompiled code) | 95.8 | 95.8 | 96.1 | 95.0 | 94.4 | 90.0 | 84.4 |

Key verified findings: (i) assembly-token representations **collapse across bitness
and architecture** (SAFE 0.4, jTrans 5.8, PalmTree 2.3 Recall@1 on XB) - "a key
limitation of assembly-based representations"; (ii) **function inlining is the
dominant failure mode** for the good tools: 81.8% (HermesSim) and 83.6% (DeJina) of
failures involve *differential* inlining, with an average instruction Diff. Ratio of
72.9% / 78.4% in failures vs 24.0% over all queries; (iii) growing the pool from 10k
to 100k costs 2.1-15.1 MRR points, unevenly; (iv) on the real 1-day task the best
*individual* tool reaches F1 51.6% at top-25 and a two-tool combination 58.5%; of 500
confirmed homologous functions only 56% were actually vulnerable - similarity is not
vulnerability.

**35. Maier, Weissberg, Rieck, "On the Role of Pre-trained Embeddings in Binary Code
Analysis", arXiv 2502.08682, Feb 2025.** <https://arxiv.org/pdf/2502.08682>
1.2M functions from Debian, five downstream tasks. *Verified from the abstract:*
several assembly embeddings "perform similarly when sufficient labeled data is
available", differences reported in prior work are "hardly noticeable", and
**end-to-end learning without pre-training performs best on average**. A direct
warning against paying for a pre-trained assembly embedding.

**36. Haq & Caballero, "A Survey of Binary Code Similarity", ACM Computing Surveys
54(3), 2021.** <https://dl.acm.org/doi/10.1145/3446371>, <https://arxiv.org/abs/1909.11424>
The standard taxonomy (22 years, ~70 approaches) - syntactic/structural/semantic,
one-to-one / one-to-many / many-to-many. Use it for vocabulary.
See also the curated tracker <https://github.com/SystemSecurityStorm/Awesome-Binary-Similarity>.

### E. 2026 frontier

**37. Wang & Lin, "vSim: Semantics-Aware Value Extraction for Efficient Binary Code
Similarity Analysis", NDSS 2026.**
<https://raw.githubusercontent.com/whj0401/whj0401.github.io/refs/heads/master/files/2026/vSim_NDSS2026.pdf>,
code <https://github.com/OSUSecLab/vSim>, DOI 10.14722/ndss.2026.240213.
**The most directly relevant paper for Glaurung's constraints: an explicitly
non-ML approach that beats transformers.** Built on angr/VEX IR. Pipeline: (1)
capture values computed by register and memory operations (collecting all Load/Store
ops on the lifted IR, both concrete and symbolic); (2) filter semantically
irrelevant values such as global-variable addresses; (3) normalize and concretize
the survivors into a function fingerprint; (4) **propagate callee fingerprints into
callers** and weight values by distinguishability. *Metric:* **weighted Jaccard**
over the value multisets. *Verified numbers:* PEM cross-optimization dataset,
poolsize 10,000 - MRR (O0,O3) jTrans 0.467, CLAP 0.603, PEM-s 0.605, **vSim 0.621**;
Recall@1 (O0,O2) jTrans 0.420, CLAP 0.596, PEM-s 0.629, **vSim 0.642**; retrieval
time 87 s vs PEM-s 1853 s. BinKit cross-compiler Recall@1: jTrans ranges 0.078-0.441
(std dev 0.107), CLAP 0.548-0.601 (0.014), **vSim 0.611-0.711 (0.026)** - vSim is
both better and far more *stable* across toolchains. Ablations: removing filtering
costs 0.09 Recall@1 and 4x the time; removing propagation costs 0.08.

**38. Zhu, Tang, Wan, Yang, Liu, Cavallaro, "BinAligner: Aligning Binary Code for
Cross-Compilation Environment Diffing", NDSS 2026.**
<https://www.ndss-symposium.org/wp-content/uploads/2026-s649-paper.pdf>
Aligns CFG *subgraphs* rather than basic blocks, because compilers re-split blocks;
uses conditional relaxation to enumerate candidate subgraph pairs and
**instruction-independent** block features for subgraph embeddings. Evaluated across
cross-version, cross-compiler, cross-optimization and cross-architecture. Detailed
numbers: not verified (table extraction incomplete).

**39. "LENA: Llama-based Embeddings of Neutralized Assembly ...", TSE 2026**,
<http://doi.org/10.1109/TSE.2026.3705321>; and **Co2FuLL, "Advancing BCSD via
Context-Content Fusion and LLM Verification", ASE 2025**,
<https://gentlecp.github.io/pdfs/Co2FuLL_ASE_2025.pdf>. Both listed for completeness;
numbers not verified. Both require an LLM at inference - out of scope for Glaurung's
stated constraint.

---

## Part 2 - Synthesis

### (1) Which representations have held up

Three independent evaluations now agree, and they agree on something specific.

**Raw bytes and token n-grams are one-variable tools.** Marcelli's Table 1 shows
Catalog1 byte hashes at AUC 0.99 across compiler *version* and 0.92 across
optimization - and 0.43 across architecture. In the all-variables-free XM task,
Catalog1 lands at AUC 0.55 with **MRR10 0.12**. Glaurung's measured "near-chance"
result for CTPH at function granularity is not a bug in the implementation; it is
the published behaviour of that representation class. The same holds for the
transformer-over-assembly-tokens family: Shi et al. 2025 measure SAFE at Recall@1
**0.4** and jTrans at **5.8** on cross-bitness, and their Insight 1 states the
conclusion flatly - assembly-token representations lack robustness to bitness and
architecture changes.

**CFG structure alone is mid-tier; CFG plus a cheap node label is most of the win.**
FunctionSimSearch graphlets hold up better than bytes cross-architecture (AUC 0.69 XA
vs 0.43) but reach only MRR10 0.26. Glaurung's current structural fingerprint
(normalized token multiset Jaccard + CFG edge set) is squarely in FSS territory, so
FSS's numbers are the right prior for it. The most useful negative result in Marcelli
is that Gemini's seven carefully hand-engineered ACFG block features perform **the
same** as a bag-of-words of the 200 most common opcodes, at 4x the extraction cost -
and that word2vec instruction embeddings on top of that add nothing. Elaborate
node featurization is not where the value is.

**IR-level semantic graphs are where the value is.** Every ranking in the last three
years is topped by something built on decompiler IR with data-flow structure:
CodeCMR/BinaryAI (CFG + IR + integers + strings) at AUC 0.98 / MRR10 0.86 in Marcelli;
HermesSim's SOG (P-code data + control + **effect** edges) at Recall@1 95.5 XA and
74.5 XM in its own paper and 94.6/88.5 in Shi et al.'s independent replication, with
388K parameters against jTrans's 87.9M. Marcelli's own smallest controlled experiment
says the same thing: swapping the GNN's node feature from BoW-of-opcodes to
BoW-of-IDA-microcode raised XM MRR10 from 0.58 to 0.62 with no other change.
**The signal is in the IR, not in the model.**

**And the model may not be needed at all.** vSim (NDSS 2026) is explicitly non-ML -
values extracted from VEX IR, filtered, weighted-Jaccard'd, propagated along the call
graph - and it beats jTrans and CLAP on cross-compiler retrieval while being *three
to four times more stable* across toolchains (std dev 0.026 vs 0.107). Ghidra BSim
is non-ML in the same sense: Weisfeiler-Leman hashing over P-code SSA plus a TF-IDF
count table. Maier et al. (2025) close the loop from the other side: across 1.2M
Debian functions and five tasks, end-to-end learning without pre-training beat every
pre-trained assembly embedding, and the differences reported in prior work were
"hardly noticeable".

**A protocol warning that must be internalized before any number is quoted.** SAFE
scores MRR **0.918** on BinaryCorp-26M at poolsize 32 (jTrans paper) and MRR10
**0.17-0.22** on Marcelli's Dataset-1, and Recall@1 **17.7** on Shi's BinAtlas XO.
Same tool. The differences are entirely protocol: how many compilation variables are
free simultaneously, and how big the candidate pool is. Difficulty is roughly
multiplicative in the number of free variables and monotone in pool size (Shi et al.
measure 2.1-15.1 MRR points lost going 10k -> 100k). **Any Glaurung number that does
not state both is not comparable to anything.**

**The failure mode nobody has solved is inlining.** Shi et al.: 81.8-83.6% of the
failures of the *best* tools involve differential inlining, at an average 72.9-78.4%
instruction Diff. Ratio. TikNib's no-inline lane degrades monotonically with
optimization (O1 0.995 -> O3 0.967). Marcelli sidestepped it by disabling inlining in
Dataset-1. This is an open problem and Glaurung should measure it rather than assume it
away.

### (2) What a deterministic, Rust-implementable, no-GPU representation should look like

Glaurung already has the expensive prerequisite that BSim and HermesSim need and that
FSS/Catalog1/CTPH lack: **a lifted LLIR in SSA form with CFGs**. The recommendation is
a four-rung identity ladder, cheapest first, all four persisted in the existing
`function_identity(scheme, identity)` table.

**L0 - exact identity (WARP-compatible).** Per basic block, hash the in-order
instruction bytes after zeroing relocatable operands (direct call/jump targets;
constant-pointer materializations), dropping NOPs and architecture-dependent
self-assignments; UUIDv5 with WARP's published namespaces. Function GUID = UUIDv5 over
block GUIDs sorted by descending start address. Store WARP **constraints** (called /
caller / adjacent function GUID plus byte offset) for collision resolution. This
strictly subsumes the 32-byte prologue "FLIRT-lite": it covers the whole function,
masks relocations properly, and interoperates with Binary Ninja's ecosystem. Solves
use case (c) for exact-toolchain matches at O(1).

**L1 - structural invariants (BinDiff/Diaphora class).** Per function, store: the
MD-index (exact formula in entry 2, both top-down and bottom-up), the relaxed
MD-index, the SPP over normalized mnemonics (mod 2^64), block/edge/loop/SCC counts,
in/out call degree, and a rare-constant and string-reference set. These are integers
and reals - directly B-tree indexable in SQLite, no ANN required. Weight MD-index
matches by *rarity* the way Diaphora does. This delivers use case (b), patch-diff
ranking, essentially outright: a kernel rebuild has zero free compilation variables,
which is the regime where TikNib measures AUC ~1.0 and where BinDiff has worked for
twenty years. **This is the highest return per line of code in the whole survey.**

**L2 - the core investment: a BSim-style WL feature vector over Glaurung's SSA
LLIR.** Run 1-dimensional Weisfeiler-Leman relabelling: 3 iterations over the SSA
def-use graph, 1 over the block CFG. Seed SSA values with (byte width, defining
opcode, is-constant, is-global, is-parameter); eliminate shadowed copies via the
dominator tree; accumulate commutative operands order-independently. Seed blocks with
(in-degree, out-degree) and mix predecessors with distinct constants for true/false
edges so a feature encodes *which path* reached it. At each root operation (call,
indirect call, store, conditional branch, return) blend the block hash with the
output value's expression hash. Emit a sorted, run-length-factorised multiset of
32-bit features. Weight by TF-IDF (`log(N/df)` from a corpus count table shipped as
data, `1 + log2(tf)`), and compare with BSim's merge-join cosine using
`min(cA,cB)^2` in the numerator - O(n+m), no floating-point model, no GPU, and the
"training" is a `GROUP BY` over the corpus.
This is deliberately the *deterministic dual of HermesSim*: HermesSim learns a GNN
over data + control + effect edges; a WL hash over the same graph computes a
comparable fixed-point labelling without gradients. Two additions from HermesSim's
ablation are worth taking: include **effect edges** (memory/IO ordering constraints)
alongside def-use, and do **not** encode instruction position.

**L3 - value fingerprints (vSim class), later.** Bounded concrete + symbolic
evaluation over the LLIR to harvest values produced by register and memory
operations; filter global addresses and other noise; normalize; weighted Jaccard;
propagate callee fingerprints into callers. vSim's ablations say filtering is worth
~0.09 Recall@1 and propagation ~0.08, so both are load-bearing. Highest cost, best
cross-compiler stability.

**Index design, all SQLite-resident.** L0: unique index on the GUID blob. L1: B-tree
on each scalar; MD-index by range. L2: an **inverted index** `feature_hash ->
(function_id, count)` is the right structure and is what BSim uses - retrieve
candidates by the query's highest-IDF (rarest) features, then exact-rescore the
candidate set. Prefer this over SimHash/bit-sampling LSH (FSS's design): the inverted
index concentrates effort on rare features, which is exactly where the discriminative
power lives, and it degrades gracefully rather than silently. A separate inverted
index over rare constants and string references is cheap and, judging by CodeCMR's
margin, unusually productive. Finally, adopt **RevDecode's** re-rank: a Viterbi
decode over a layered candidate graph using call-graph context improved 56.3-98.8% of
rankings for *every* underlying matcher tested; it is a dynamic program, not a model,
and it composes with whatever L0-L3 produce.

**Do not build:** a GPU embedding model, or a pre-trained assembly token embedding.
Keep `function_identity` pluggable so an externally-computed HermesSim or CLAP vector
can be imported later if someone wants it.

### (3) Benchmark and ground-truth protocol Glaurung should adopt

1. **Corpus: BinKit 2.0** (MIT). 371,928 binaries, 8 architectures, GCC 4.9.4-11.2.0,
   Clang 4.0.0-13.0.0, O0-O3/Os/Ofast, plus the **NoInline, PIE, LTO, SizeOpt and
   Obfuscation (SUB/BCF/FLA)** sub-datasets. The NoInline lane matters more than
   anything else in the list, because inlining is the field's unsolved failure mode.
2. **Cross-check corpus: Cisco-Talos/binary_function_similarity** (MIT), so numbers
   drop directly into Marcelli's published Tables 3 and 4 without re-derivation, plus
   its Dataset-Vulnerability ranking task (10 OpenSSL functions, 8 CVEs, into Netgear
   R7000 ARM32 and TP-Link Deco-M4 MIPS32 firmware).
3. **Task taxonomy: Marcelli's verbatim** - XO, XC, XC+XB, XA, XA+XO, XM, plus XM-S
   (<20 blocks), XM-M (20-100), XM-L (>100). Add Shi et al.'s **XB** (cross-bitness)
   lane; it is the one that separates IR representations from token representations.
4. **Metrics:** AUC over 50k positive + 50k negative pairs per task, **and** MRR10 +
   Recall@1 with 100 negatives per positive. Additionally report at pool sizes 10,000
   and 100,000. **Always print the pool size and the free-variable set next to every
   number.** Report Recall@k curves, not just @1 - Marcelli shows models that tie on
   AUC diverge sharply on ranking.
5. **Ground truth from DWARF** (which Glaurung already ingests): same package, same
   source file, same line range, same name. Apply the published filters so the
   denominators match - discard functions with <5 basic blocks, discard non-.text and
   PLT thunks, discard compiler intrinsics, and dedupe by (name, instruction hash).
   Marcelli discards 18.2M of 26.8M functions this way; TikNib discards ~40% + ~4% +
   ~54% of the remainder. A number computed without these filters is not comparable.
6. **Negative sampling discipline:** negatives must obey the same constraint as the
   task (in XO, the negative shares the architecture). Marcelli names this as a
   frequent, silent source of inflated published results.
7. **Report the inlining lane explicitly:** for failures, report Shi et al.'s
   **Diff. Ratio** (fraction of instructions coming from non-shared inlined callees).
   It is the only diagnostic that distinguishes "our representation is weak" from
   "these two functions are genuinely not the same code any more".
8. **Report extraction cost per function.** TikNib is 0.02-1.03 ms; a design that
   cannot hit that order is not usable for a 6,000-function kernel diff.

### (4) Ranked recommendations with effort estimates

| # | Work item | Effort | Why this rank |
|---|---|---|---|
| 1 | **Measurement harness first**: BinKit 2.0 + Cisco Dataset-1/2 ingestion, DWARF ground truth with the published filters, XO/XC/XB/XC+XB/XA/XA+XO/XM tasks, AUC + MRR10 + Recall@1 at pool 100 / 10k / 100k, cost-per-function. | 2-3 weeks | Nothing below can be ranked without it, and it retro-scores the CTPH and structural-fingerprint work already done. Cheapest possible way to stop guessing. |
| 2 | **L1 structural invariants**: MD-index (top-down + bottom-up + relaxed), SPP over normalized mnemonics, block/edge/loop/SCC counts, rarity weighting. | ~1 week | Highest ROI in the survey. Delivers use case (b) at BinDiff quality on data Glaurung already computes. Formula is in hand and verified. |
| 3 | **L0 WARP-compatible GUIDs + constraints**, written into `function_identity`. | 1-2 weeks | Exact, O(1), replaces the 32-byte FLIRT-lite with something strictly better, and buys ecosystem interop. Namespaces and masking rules are published and verified. |
| 4 | **L2 BSim-style WL feature vector over SSA LLIR** + TF-IDF corpus table + inverted index + merge-join cosine. | 4-8 weeks | **The core investment.** Best evidence-to-cost ratio in the literature, and Glaurung is one of very few tools with the SSA IR prerequisite already built. Deterministic, no GPU, no training. Target: beat FSS-class MRR10 0.26 on XM and approach the GNN band (0.52). |
| 5 | **Rare-constant / string / call-target inverted index.** | ~1 week | Nearly free; CodeCMR's margin over plain CFG+opcodes is partly attributable to integers and strings. Also the strongest signal for use case (d). |
| 6 | **RevDecode-style call-graph context re-rank** (Viterbi over a layered candidate graph). | 2-3 weeks | Multiplies whatever 2-5 produce; improved 56.3-98.8% of rankings across every matcher tested. Pure dynamic programming. |
| 7 | **L3 vSim-style value fingerprints** via bounded LLIR emulation + weighted Jaccard + callee-to-caller propagation. | 6-10 weeks | Best cross-compiler stability measured anywhere without a GPU, but only worth it after L2 exists and the harness can prove the delta. |
| 8 | **Program-level rollup for clustering** (KEENHash shape: cluster function vectors, feature-hash into one fixed-length program vector). | 2-3 weeks | Use case (d) only; 215x speedups reported. Do after L2 supplies the function vectors. |
| 9 | **Do not build** a GPU embedding model or a pre-trained assembly-token embedding. Keep `function_identity` open so an external HermesSim/CLAP vector can be imported. | - | Maier et al. found pre-trained assembly embeddings' advantages "hardly noticeable"; Shi et al. found token models collapse cross-bitness; HermesSim's win came from the graph, not the parameters. |
