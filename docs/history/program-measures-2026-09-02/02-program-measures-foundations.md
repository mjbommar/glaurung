# Foundations for Measuring Programs: Distances, Kernels, Canonical Forms, Quotients

> **Kind:** record · **Date:** 2026-09-02

A literature survey for Glaurung. Scope: the mathematical and program-analysis
foundations of "how far apart are two functions", with an eye to what is
implementable in deterministic Rust over Glaurung's SSA LLIR + CFG.

Effort/LOC estimates in the synthesis are engineering judgment, **not verified**.
Every URL below came from a search result or a fetch.

---

## 1. Distances on program structures

### 1.1 Graph edit distance (GED)

**Hardness.** Exact GED is NP-hard and APX-hard; the APX-hardness is attributed to
Lin (1994), "Hardness of approximating graph transformation problem"
(https://www.researchgate.net/publication/221543858_Hardness_of_approximating_graph_transformation_problem),
per the Wikipedia summary (https://en.wikipedia.org/wiki/Graph_edit_distance),
which also notes most practical approximations are cubic time.

**Metric property — the load-bearing caveat.** GED is *not* automatically a metric.
Serratosa, "Graph edit distance: Restrictions to be a metric", *Pattern Recognition*
2019 (https://www.sciencedirect.com/science/article/pii/S0031320319300639) is the
reference statement of the cost-function restrictions required for the triangle
inequality to hold (the full text was 403 to fetch; the conditions themselves are
**not verified** here, but the existence of restrictions is the point). See also
"Graph Edit Distance or Graph Edit Pseudo-Distance?" SSPR 2016
(https://dl.acm.org/doi/10.1007/978-3-319-49055-7_47) — the title is the finding.

**Approximations.**
- *Bipartite GED*: Riesen & Bunke, "Approximate graph edit distance computation by
  means of bipartite graph matching", *Image and Vision Computing* 2009
  (https://www.sciencedirect.com/science/article/abs/pii/S026288560800084X).
  Reduces GED to a linear sum assignment problem over node-neighbourhood costs;
  O(n^3) via Hungarian. It is an **upper bound**, and not a metric.
- *A\*-beam / suboptimal search*: Neuhaus, Riesen & Bunke, "Fast Suboptimal Algorithms
  for the Computation of Graph Edit Distance", SSPR 2006
  (https://doi.org/10.1007/11815921_17). Beam-width-truncated A\*; deterministic
  given a fixed node ordering, still an upper bound.
- *Hausdorff GED*: Fischer, Riesen & Bunke, "Improved quadratic time approximation of
  graph edit distance by combining Hausdorff matching and greedy assignment",
  *Pattern Recognition Letters* 2017
  (https://www.sciencedirect.com/science/article/abs/pii/S0167865516301386);
  earlier "A Hausdorff heuristic for efficient computation of graph edit distance"
  (https://publications.polymtl.ca/12376/). O(n^2); a **lower bound**, useful as a
  cheap filter under a "lower bound then verify" retrieval scheme.
- *Exact ILP formulation*: Justice & Hero, "A Binary Linear Programming Formulation of
  the Graph Edit Distance", *IEEE TPAMI* 2006
  (https://web.eecs.umich.edu/~hero/Preprints/gedPAMI2_final.pdf).

**GED on binaries.** Flake, "Structural Comparison of Executable Objects", DIMVA 2004
(https://dl.gi.de/items/7f573931-cb51-49ef-a12c-0452a9fb0ea4) is the ancestor of
BinDiff: a *heuristic* CFG/call-graph matching, not a distance. BinSlayer (Bourquin,
King & Robbins, PPREW 2013, https://dl.acm.org/doi/10.1145/2430553.2430557) replaces
BinDiff's heuristics with Hungarian bipartite matching on CFGs. funcGNN (Roy et al.,
ESEM 2020, https://arxiv.org/abs/2007.13239) learns to *predict* GED on CFGs.
Broad context: Haq & Caballero, "A Survey of Binary Code Similarity",
*ACM Computing Surveys* 2021 (https://arxiv.org/abs/1909.11424) — the best single map
of this space (~70 systems classified by syntactic/structural/semantic level).

**Relevance to Glaurung.** DecBench scores decompiler output by GED against source
(https://decbench.com/about/). That is an *evaluation* number where a fixed
approximation is fine. It is a bad choice for an *index* distance: no triangle
inequality means no metric-tree pruning, no valid clustering guarantees, and no
kernel.

### 1.2 Tree edit distance (TED) on ASTs

- Zhang & Shasha (1989) is the classical O(n^2 * depth^2)-ish recursive TED. Reference
  implementation: https://github.com/timtadh/zhang-shasha.
- Pawlik & Augsten, "RTED: A Robust Algorithm for the Tree Edit Distance", *PVLDB* 2012
  (https://vldb.org/pvldb/vol5/p334_mateuszpawlik_vldb2012.pdf) and "Efficient
  Computation of the Tree Edit Distance", *ACM TODS* 2015
  (https://dl.acm.org/doi/pdf/10.1145/2699485). RTED runs in O(n^3) time / O(mn) space
  and is *tree-shape independent*: it computes an optimal path-decomposition strategy,
  so it never falls into the shape-dependent worst cases of Zhang-Shasha. APTED is the
  successor implementation (https://github.com/DatabaseGroup/apted).
  Unlike GED, unit-cost TED **is** a metric — the edit operations are unit-cost and
  composable, and the standard cost conditions are easy to satisfy.
- GumTree: Falleri et al., "Fine-grained and accurate source code differencing", ASE
  2014 (https://doi.org/10.1145/2642937.2642982, code:
  https://github.com/GumTreeDiff/gumtree). Not a distance — a *matching heuristic*
  (top-down isomorphic subtree matching, then bottom-up container matching) producing
  an edit script. Fast and readable, but asymmetric and non-metric.

For Glaurung, TED is directly applicable to the `structure_v2` region tree (the
recovered AST), and it is the *only* structure in the current tree where a genuine
metric comes essentially for free.

---

## 2. Graph kernels and canonical forms

### 2.1 Weisfeiler-Lehman

Shervashidze, Schweitzer, van Leeuwen, Mehlhorn & Borgwardt, "Weisfeiler-Lehman Graph
Kernels", *JMLR* 12(77), 2011 (https://jmlr.org/papers/v12/shervashidze11a.html).
Defines a family of kernels from the 1-WL colour-refinement iteration; the subtree
kernel counts matching refined labels at each of h iterations. Runtime scales linearly
in the number of edges and in h (per the paper abstract); for N graphs the multiset
sorting/compression makes the all-pairs computation near-linear in total size rather
than quadratic in nodes.

Mathematically this is the important one. The kernel is an inner product between
explicit feature vectors (counts of WL labels), so it is **positive semi-definite by
construction**, and therefore `d(G,H) = sqrt(k(G,G) + k(H,H) - 2k(G,H))` is a genuine
*pseudo-metric* on graphs (a metric on WL-feature equivalence classes). It satisfies
the triangle inequality exactly, deterministically, in near-linear time. That is a
rare combination in this literature.

**Expressive limits.** 1-WL cannot distinguish all non-isomorphic graphs; Morris et al.,
"Weisfeiler and Leman Go Neural", AAAI 2019 (https://arxiv.org/pdf/1810.02244)
characterises message-passing GNNs as exactly 1-WL-bounded and gives k-WL hierarchies.
For CFGs this matters less than for chemistry graphs: CFGs are sparse, rooted at a
unique entry, and heavily labelled — labels do most of the discrimination.

**WL hashing.** The practical single-value form is the WL graph hash (NetworkX
`weisfeiler_lehman_graph_hash`,
https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.graph_hashing.weisfeiler_lehman_graph_hash.html
and `weisfeiler_lehman_subgraph_hashes`). One-sided: equal graphs give equal hashes;
different hashes prove non-isomorphism; equal hashes do not prove isomorphism.

Related: graph2vec (Narayanan et al., MLG 2017, https://arxiv.org/pdf/1707.05005)
treats rooted WL subgraph labels as "words" and learns a doc2vec embedding — a useful
reminder that the WL label *multiset* is the reusable object, and the learned part is
optional.

Generalisation: Schulz, Horváth, Welke & Wrobel, "A generalized Weisfeiler-Lehman graph
kernel", *Machine Learning* 2022 (https://link.springer.com/article/10.1007/s10994-022-06131-w).

### 2.2 Other kernels

- Gärtner, Flach & Wrobel, "On Graph Kernels: Hardness Results and Efficient
  Alternatives", COLT 2003 (https://researchr.org/publication/GartnerFW03). The
  foundational negative result: any kernel that would let you decide graph isomorphism
  is NP-hard to compute; random-walk kernels are the tractable retreat. Random-walk
  kernels suffer "tottering" and halting-parameter sensitivity, and are typically
  O(n^6) naively (O(n^3) with Sylvester-equation tricks per Vishwanathan et al.).
- Shervashidze et al., "Efficient graphlet kernels for large graph comparison",
  AISTATS 2009 (https://proceedings.mlr.press/v5/shervashidze09a.html). Counts of
  size-k induced subgraphs; PSD; sampling-based estimates are cheap but stochastic
  (a determinism hazard for Glaurung unless the sampler is seeded and pinned).

### 2.3 Canonical labelling

McKay & Piperno, "Practical Graph Isomorphism, II", *J. Symbolic Computation* 2014
(https://www.sciencedirect.com/science/article/pii/S0747717113001193); nauty/Traces
(https://pallini.di.uniroma1.it/, user guide
https://users.cecs.anu.edu.au/~bdm/nauty/nug29.pdf). Produces a *canonical form*: two
graphs are isomorphic iff their canonical labellings are equal. Exponential worst case,
excellent in practice. Babai's quasipolynomial result bounds the theory but is not
implemented. Rust bindings exist: `nauty-pet` 0.15.0 (26,817 downloads,
https://crates.io/crates/nauty-pet, "Canonical graph labelling using nauty/Traces and
petgraph") and `graph-canon` 0.1.4 (https://crates.io/crates/graph-canon). **Licensing
of nauty itself is not verified here and must be checked before vendoring.**

Canonical labelling gives *exact* isomorphism classes — the right tool if the quotient
you want is literally "isomorphic labelled graph". It gives no notion of *near*.

### 2.4 Spectra

Laplacian/adjacency spectra are permutation invariants, computable in O(n^3), and give
a natural distance (sorted-eigenvalue L2). The catastrophic caveat is cospectrality:
"Which graphs are determined by their spectrum?" (van Dam & Haemers,
https://repository.tilburguniversity.edu/bitstreams/a0757d00-8071-4ed5-90dc-8be8ac9dd47b/download)
and enumeration work (https://doi.org/10.1016/j.amc.2021.126348) show large families of
non-isomorphic cospectral graphs. Worse for our purposes: CFGs are small and highly
structured, and spectra discard *all* node labels — exactly the information (opcode,
type, callee) that distinguishes two functions with the same shape. Spectral distance
is a legitimate metric on an over-coarse quotient.

---

## 3. Semantic equivalence and quotients

### 3.1 Rewriting to a canonical form

- Alpern, Wegman & Zadeck, "Detecting equality of variables in programs", POPL 1988
  (https://dl.acm.org/doi/10.1145/73560.73561). Global value numbering: partitions SSA
  values into congruence classes by a Hopcroft-style refinement. This is the original
  "quotient the program by an equivalence" result, and Glaurung already has an
  implementation (`src/ir/value_number.rs`, 2,692 lines).
- Tate, Stepp, Tatlock & Lerner, "Equality Saturation: a New Approach to Optimization",
  POPL 2009 (https://cseweb.ucsd.edu/~lerner/papers/popl09.pdf). The E-PEG represents
  *all* programs equivalent under a rewrite set simultaneously; optimisation becomes
  extraction. Reframed as: the e-graph is a data structure for the *quotient set*.
- Willsey, Nandi, Wang, Flatt, Tatlock & Panchekha, "egg: Fast and Extensible Equality
  Saturation", POPL 2021 (https://arxiv.org/abs/2004.03082, https://doi.org/10.1145/3434304).
  Rust. `egg` 0.11.0 on crates.io, 3.1M downloads
  (https://docs.rs/egg/latest/egg/, https://github.com/egraphs-good/egg). The key
  engineering contribution is *deferred rebuilding* (invariant restoration amortised),
  which is what makes saturation practical.
- Fallin, "ægraphs: Acyclic E-graphs for Efficient Optimization in a Production
  Compiler", EGRAPHS 2023 (https://cfallin.org/blog/2026/04/09/aegraph/,
  RFC: https://github.com/bytecodealliance/rfcs/blob/main/accepted/cranelift-egraph.md).
  Cranelift's variant: a single forward pass over an acyclic e-graph with eager
  rewriting and no separate extraction phase. Directly relevant — it is production
  Rust, it operates on an SSA CLIR very close to Glaurung's LLIR, and it is designed
  for bounded cost rather than saturation.
- Hash-consing: Filliâtre & Conchon, "Type-Safe Modular Hash-Consing", ML Workshop 2006
  (https://usr.lmf.cnrs.fr/~jcf/publis/hash-consing2.pdf). Maximal sharing of a term
  DAG makes structural equality pointer equality — the cheapest possible "semantic
  hash" once the terms are canonical.
- MLIR canonicalization docs (https://mlir.llvm.org/docs/Canonicalization/) are the
  best engineering statement of what a canonicalizer must guarantee (confluence-ish,
  termination, no information loss) even without a formal proof.

Note: no verified literature was found for the term "Sigma-normalization" as a program
canonicalisation technique; searches surfaced only unrelated Rust crates. Treat that
term as **unconfirmed**.

### 3.2 Symbolic / logical equivalence

- Gao, Reiter & Song, "BinHunt: Automatically Finding Semantic Differences in Binary
  Programs", ICICS 2008 (https://people.eecs.berkeley.edu/~dawnsong/papers/2008%20binhunt_icics08.pdf).
  Symbolic execution + theorem proving to establish basic-block equivalence, then
  maximum-common-subgraph isomorphism over the CFGs. Sound-ish, expensive.
- Luo, Ming, Wu, Liu & Zhu, "Semantics-Based Obfuscation-Resilient Binary Code
  Similarity Comparison" (CoP), FSE 2014 (https://faculty.ist.psu.edu/wu/papers/cop-fse2014.pdf;
  extended TSE version https://faculty.ist.psu.edu/wu/papers/cop-tse-2017.pdf).
  Longest common subsequence of *semantically equivalent* basic blocks, where block
  equivalence is decided symbolically. The clearest statement of "quotient the trace
  alphabet, then use a sequence distance".
- Ming, Xu, Wang & Wu, "BinSim: Trace-based Semantic Binary Diffing via System Call
  Sliced Segment Equivalence Checking", USENIX Security 2017
  (https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-ming.pdf).
  Slices traces by system call and checks segment equivalence — anchors the comparison
  on observable effects rather than syntax.
- Churchill, Padon, Sharma & Aiken, "Semantic Program Alignment for Equivalence
  Checking", PLDI 2019 (https://theory.stanford.edu/~aiken/publications/papers/pldi19.pdf,
  https://dl.acm.org/doi/10.1145/3314221.3314596). Constructs a *product program* by
  aligning loops using runtime data, then discharges equivalence with invariant
  inference. This is the state of the art for "same up to aggressive compiler
  transformation" and directly targets unrolled/vectorised loops.
- Lopes, Lee, Hur, Liu & Regehr, "Alive2: Bounded Translation Validation for LLVM",
  PLDI 2021 (https://web.ist.utl.pt/nuno.lopes/pubs/alive2-pldi21.pdf). Refinement, not
  equality: `tgt` refines `src` when it is defined at least as often. The refinement
  *preorder* — not a symmetric relation — is arguably the mathematically correct notion
  for compiler output, and worth remembering when writing "equivalence" in a spec.
- Godlin & Strichman, "Regression verification: proving the equivalence of similar
  programs", *STVR* 2013 (https://ofers.dds.technion.ac.il/publications/stvr12.pdf) and
  Lahiri, Hawblitzel, Kawaguchi & Rebêlo, "SYMDIFF: A Language-Agnostic Semantic Diff
  Tool for Imperative Programs", CAV 2012
  (https://link.springer.com/chapter/10.1007/978-3-642-31424-7_54). Mutual summaries and
  product programs for differential verification.

### 3.3 I/O sampling equivalence

- Egele, Woo, Chapman & Brumley, "Blanket Execution: Dynamic Similarity Testing for
  Program Binaries and Components", USENIX Security 2014
  (https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/egele).
  Executes a function under a controlled random environment repeatedly, records
  side-effect features, and compares feature vectors. Compiler-choice invariant almost
  by construction; requires execution.
- Wang & Wu, "In-Memory Fuzzing for Binary Code Similarity Analysis" (IMF-sim), ASE
  2017 (https://www.cse.ust.hk/~shuaiw/papers/IMF.pdf). Same idea with fuzzing to drive
  coverage.

Glaurung already has the harness shape for this: `tests/decompiler_fixtures/` executes
recompiled output and diffs against the original. An I/O-behaviour digest is a natural
extension of infrastructure that already exists.

---

## 4. Abstract interpretation as a lattice for similarity

- Cousot & Cousot, POPL 1977 (https://www.di.ens.fr/~cousot/COUSOTpapers/POPL77.shtml).
  A Galois connection is precisely a quotient-and-approximation of the concrete
  semantics; every abstract domain therefore *defines* an equivalence ("same abstract
  semantics") and a computable one.
- Giacobazzi, Ranzato & Scozzari, "Making abstract interpretations complete", *JACM*
  2000 (https://www.sci.unich.it/~scozzari/paper/JACM00.pdf). Complete shells/cores are
  canonicalisation *operators on domains*: given a domain and a semantics, there is a
  most abstract refinement that is complete. This is the theory that tells you when
  "equal abstract states" faithfully means "equal behaviour".
- Partush & Yahav, "Abstract Semantic Differencing via Speculative Correlation",
  OOPSLA 2014 (https://csaws.cs.technion.ac.il/~yahave/papers/oopsla14-diff.pdf).
  Analyses a *correlating* program (an interleaving of two versions) with a numerical
  domain to characterise the difference abstractly.
- Delmas & Miné, "Analysis of Software Patches Using Numerical Abstract Interpretation",
  SAS 2019 (https://perso.lip6.fr/Antoine.Mine/publi/article-delmas-mine-sas19.pdf) and
  "Analysis of Program Differences with Numerical Abstract Interpretation", PERR 2019
  (https://perso.lip6.fr/Antoine.Mine/publi/article-delmas-mine-PERR19.pdf). Double
  program semantics + a relational domain over pairs of versions; the industrial
  patch-diff case.
- Lahiri, McMillan, Sharma & Hawblitzel, "Differential Assertion Checking", FSE 2013
  (https://cs.stanford.edu/people/sharmar/pubs/dac.pdf).

**Verdict for Glaurung.** Abstract domains yield *soundly-different / maybe-same*, an
over-approximation. That is a filter (cheap negative evidence: different abstract
return-value intervals prove non-equivalence) and a feature vector, not a distance.

---

## 5. Information-theoretic and compression-based measures

- Cilibrasi & Vitányi, "Clustering by Compression", *IEEE Trans. Information Theory*
  2005 (https://arxiv.org/abs/cs/0312044, https://homepages.cwi.nl/~paulv/papers/clusterit.pdf).
  NCD(x,y) = (C(xy) - min(C(x),C(y))) / max(C(x),C(y)). Under "normal compressor"
  axioms (idempotency, monotonicity, symmetry, distributivity) NCD is proved to be a
  *normalised admissible distance* satisfying metric axioms up to an additive O(log n / C)
  error term, and it approximates the normalised information distance (which is
  universal, minorising every computable normalised distance up to a constant).
  Tooling: CompLearn (https://complearn.org/ncd.html).
- Instruction-stream entropy / opcode n-grams: ITect
  (http://www0.cs.ucl.ac.uk/staff/d.clark/pubs/itect2016.pdf), structural entropy for
  metamorphic malware (http://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic13/dona.pdf),
  "Detecting Malware with Information Complexity"
  (https://pmc.ncbi.nlm.nih.gov/articles/PMC7517096/), and Santos et al., opcode
  sequences as executable representations
  (https://www.sciencedirect.com/science/article/abs/pii/S0020025511004336). All treat
  the instruction stream as a symbol sequence — invariant to nothing in particular.
- CTPH / similarity digests: Kornblum, "Identifying almost identical files using context
  triggered piecewise hashing", DFRWS 2006
  (https://dfrws.org/sites/default/files/session-files/2006_USA_paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf);
  Roussev, "An evaluation of forensic similarity hashes" (sdhash vs ssdeep), DFRWS 2011
  (http://roussev.net/pubs/2011-DFRWS--sdhash-vs-ssdeep.pdf); Oliver, Cheng & Chen,
  "TLSH -- A Locality Sensitive Hash", CTC 2013 (https://doi.org/10.1109/ctc.2013.9,
  whitepaper https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf).
  **Known failure modes at small input size are structural, not incidental**: TLSH
  requires a minimum of 50 bytes and "a sufficient amount of complexity" — a stream of
  identical bytes produces no hash at all (https://github.com/trendmicro/tlsh). ssdeep's
  block size is tied to input length, so digests of very different-length inputs are
  incomparable. See also Breitinger et al. on security aspects and attacks
  (https://webdiis.unizar.es/~ricardo/files/papers/MRB-FSIDI-21.pdf,
  https://documents.trendmicro.com/assets/wp/wp-using-randomization-to-attack-similarity-digests.pdf)
  and "ssdeeper" (https://dfrws.org/wp-content/uploads/2022/07/ssdeeper-Evaluating-and-improving-ssdeep-combined.pdf).

Glaurung already ships a clean-room CTPH in `src/similarity/mod.rs` (336 lines,
BLAKE3-XOF pieces, Jaccard comparison). Typical function bodies are hundreds of bytes,
which is squarely in the regime where these digests degrade. Byte-level digests should
be treated as a *last-resort* signal for functions, and a reasonable signal for whole
sections/files.

---

## 6. Classical software metrics and measurement theory

- McCabe, "A Complexity Measure", *IEEE TSE* 1976 (https://doi.org/10.1109/tse.1976.233837,
  https://ieeexplore.ieee.org/document/1702388/). v(G) = e - n + p. It is a *graph
  invariant of the CFG* — and therefore invariant to block layout and register
  allocation, which is more than most metrics here can claim. It is not invariant to
  inlining, if-conversion, tail duplication, or loop unrolling.
- Halstead's software science (n1, n2, N1, N2 -> volume/difficulty/effort). The
  critical literature is decisive: Hamer & Frewin, "M.H. Halstead's Software Science - a
  critical examination", ICSE 1982 (https://doi.org/10.5555/800254.807762); Shen, Conte
  & Dunsmore, "Software Science Revisited" (https://docs.lib.purdue.edu/cgi/viewcontent.cgi?article=1302&context=cstech);
  NIST TN "Software Science revisited: rationalizing Halstead's system using
  dimensionless units" (https://nvlpubs.nist.gov/nistpubs/TechnicalNotes/NIST.TN.1990.pdf).
- Fenton, "Software measurement: a necessary scientific basis", *IEEE TSE* 1994
  (https://wwwipd.is.ipd.kit.edu/mitarbeiter/padberg/lehre/sqs07/FentonTSE1994.pdf);
  Fenton & Bieman, *Software Metrics: A Rigorous and Practical Approach*, 3rd ed.
  (https://www.eecs.qmul.ac.uk/~norman/metrics_book/book.html). The *representation
  condition*: a measure must be a homomorphism from an empirical relational system into
  a numerical one, and only transformations admissible for the scale type are
  meaningful. Most software "metrics" fail this.
- Briand, Morasca & Basili, "Property-Based Software Engineering Measurement", *IEEE TSE*
  1996 (https://www.cs.umd.edu/~basili/publications/journals/J58.pdf). Axiom sets for
  *size* (non-negativity, null value, module additivity), *length*, *complexity*
  (non-negativity, null value, symmetry, module monotonicity, disjoint-module
  additivity), *cohesion*, *coupling*. A concrete checklist any Glaurung metric can be
  tested against.
- Zuse, *A Framework of Software Measurement* (https://horst-zuse.hier-im-netz.de/horst-zuse-z3-html/012book.pdf).
  Measurement-theoretic scale analysis of ~hundreds of measures.

**Transfer to binary functions.** The axioms transfer; the measures mostly do not. Size
and complexity axioms are stated over module composition, which has a clean analogue in
CFG/callgraph composition. But the empirical relational system for binaries is
different: the thing we want to preserve is *behaviour under compilation*, and neither
Halstead nor cyclomatic complexity is invariant to it. Their honest role is as
low-dimensional *features* in a candidate filter, evaluated against Briand's axioms
before being called measures.

---

## 7. Program embeddings and the representations they define

The value here is the *graph*, not the model.

- Alon, Zilberstein, Levy & Yahav, "code2vec: Learning Distributed Representations of
  Code", POPL 2019 (https://arxiv.org/abs/1803.09473,
  https://github.com/tech-srl/code2vec). Representation: the **bag of AST paths** —
  (terminal, path, terminal) triples. Deterministic, computable without any model, and
  a perfectly good kernel feature set on its own (a bag-of-paths Jaccard/cosine is a
  PSD kernel). Directly applicable to Glaurung's recovered AST.
- Ben-Nun, Jakobovits & Hoefler, "Neural Code Comprehension: A Learnable Representation
  of Code Semantics", NeurIPS 2018 (https://arxiv.org/abs/1806.07336,
  https://github.com/spcl/ncc). Representation: the **contextual flow graph (XFG)** over
  LLVM IR — statements as nodes, data- and control-flow as edges, with identifiers and
  immediates abstracted away. This is the single closest published object to what
  Glaurung should build: XFG's abstraction of register/identifier names is exactly the
  register-allocation invariance we need.
- Cummins, Fisches, Ben-Nun, Hoefler, O'Boyle & Leather, "ProGraML: A Graph-based Program
  Representation for Data Flow Analysis and Compiler Optimizations", ICML 2021
  (https://proceedings.mlr.press/v139/cummins21a.html,
  https://github.com/ChrisCummins/ProGraML). Representation: one graph with **three edge
  types — control, data, call** — nodes for instructions and for data values, and
  *positional edge labels* encoding operand order. That last detail is essential: it is
  what makes `a - b` distinguishable from `b - a` under any permutation-invariant
  aggregation.
- VenkataKeerthy et al., "IR2Vec: LLVM IR Based Scalable Program Embeddings", *ACM TACO*
  2020 (https://dl.acm.org/doi/10.1145/3418463, https://arxiv.org/abs/1909.06228).
  Representation: a hierarchy — instruction / function level, built from a
  flow-aware propagation over use-def and reaching-definition edges on LLVM IR.
- Ferrante, Ottenstein & Warren, "The Program Dependence Graph and Its Use in
  Optimization", *ACM TOPLAS* 1987 (https://doi.org/10.1145/24039.24041). The ancestor
  of all of the above: control-dependence + data-dependence in one graph, which by
  construction discards statement ordering that does not matter.
- Assembly-level: Ding, Fung & Charland, "Kam1n0: MapReduce-based Assembly Clone Search
  for Reverse Engineering", KDD 2016 (https://www.kdd.org/kdd2016/papers/files/adp0461-dingAdoi.pdf,
  https://github.com/McGill-DMaS/Kam1n0-Community) — LSH over subgraph features with an
  adaptive index; and Xu et al., "Neural Network-based Graph Embedding for
  Cross-Platform Binary Code Similarity Detection" (Gemini), CCS 2017
  (https://doi.org/10.1145/3133956.3134018), whose input is an attributed CFG with
  hand-designed per-block features.

---

## 8. Measure-theoretic and optimal-transport distances

- Desharnais, Gupta, Jagadeesan & Panangaden, "Metrics for labelled Markov processes",
  *TCS* 2004 (https://www.cs.mcgill.ca/~prakash/Pubs/fullmetric.pdf; earlier "Metrics
  for Labeled Markov Systems", CONCUR 1999,
  https://link.springer.com/chapter/10.1007/3-540-48320-9_19). The genuine
  measure-theoretic answer to "distance between programs": a *bisimulation metric*
  whose kernel is exactly probabilistic bisimulation, defined via the Kantorovich
  (Wasserstein-1) lift of a metric on states to a metric on distributions over states.
  This is the correct template — quotient by bisimulation, then metrise the quotient —
  even though its natural home is probabilistic transition systems, not x86.
  Tutorial framing: Panangaden, "The Kantorovich metric and cousins"
  (https://www.cs.mcgill.ca/~prakash/Talks/part3handout.pdf).
- Mémoli, "Gromov-Wasserstein Distances and the Metric Approach to Object Matching",
  *FoCM* 2011 (https://www.math.ucdavis.edu/~saito/data/acha.read.w12/memoli-gromov-dist.pdf).
  GW is a **metric on isomorphism classes of metric measure spaces** — literally a
  metric on a quotient by relabelling, which is the mathematical shape the maintainer is
  asking for. Computing it is a non-convex quadratic assignment problem.
- Xu, Luo, Zha & Carin, "Gromov-Wasserstein Learning for Graph Matching and Node
  Embedding", ICML 2019 (https://proceedings.mlr.press/v97/xu19b.html); "Scalable
  Gromov-Wasserstein Learning for Graph Partitioning and Matching", NeurIPS 2019
  (https://proceedings.neurips.cc/paper_files/paper/2019/file/6e62a992c676f611616097dbea8ea030-Paper.pdf);
  Vayer/Titouan et al., "Optimal Transport for structured data with application on
  graphs" (Fused GW), ICML 2019 (https://proceedings.mlr.press/v97/titouan19a.html) —
  FGW interpolates between Wasserstein on node *features* and GW on node *structure*,
  which is exactly the labelled-CFG case.
- Togninalli, Ghisu, Llinares-López, Rieck & Borgwardt, "Wasserstein Weisfeiler-Lehman
  Graph Kernels", NeurIPS 2019
  (https://proceedings.neurips.cc/paper/2019/file/73fed7fd472e502d8908794430511f4d-Paper.pdf).
  Replaces the WL kernel's exact label matching with a Wasserstein distance between WL
  embedding *distributions*; handles continuous node attributes. Note the standard
  caveat: Wasserstein-derived kernels are generally *not* PSD without a Laplacian-kernel
  trick, so the PSD guarantee of plain WL is traded away.
- Chen, Lim, Mémoli, Wan & Wang, "Weisfeiler-Lehman Meets Gromov-Wasserstein", ICML 2022
  (https://proceedings.mlr.press/v162/chen22o.html). Constructs a polynomial-time
  WL-distance that is a *lower bound* on GW and provably a metric on the space of
  graphs modulo WL-indistinguishability — the cleanest bridge between the cheap
  invariant (§2.1) and the principled metric (Mémoli).
- Fang, Huang, Su & Kasai, "Wasserstein graph distance based on L1-approximated tree edit
  distance between Weisfeiler-Lehman subtrees", AAAI 2023
  (https://ojs.aaai.org/index.php/AAAI/article/view/25916).

Rust tooling for OT is immature: `wass` (https://crates.io/crates/wass) exists but is
tiny and unproven. Treat GW as a research direction, not an implementation target.

---

## SYNTHESIS

### (a) What actually gives a computable, deterministic, compiler-choice-invariant distance

Rank the invariance sources by where they come from, because most of the invariance
should be *built into the representation*, not paid for by an expensive matcher:

| Nuisance transformation | Neutralised by |
|---|---|
| Register allocation | SSA value identity + dropping machine register names (Glaurung has SSA; XFG/ProGraML do exactly this) |
| Instruction scheduling within a block | Representing a block as a **data-dependence DAG**, not a list |
| Basic-block layout / address order | Node identity from the graph, never from address; canonical traversal by RPO with edge-kind-ordered successors |
| Strength reduction, `lea` idioms, magic-number division, condition polarity | **E-graph rewriting + deterministic extraction** (egg / ægraph) |
| Inlining, unrolling, tail duplication | Nothing cheap. Needs alignment (PLDI'19) or I/O sampling. Accept as out of scope for v1 |

Given a representation with the first four properties, the distances that are
*well-defined, deterministic, and metric*:

1. **WL-kernel-induced distance** on the labelled dataflow+control graph. PSD by
   construction, triangle inequality exact, near-linear time, no randomness. Best
   effort/benefit ratio in this entire survey.
2. **Jaccard distance on WL label multisets** (equivalently MinHash-estimated). Jaccard
   distance is a metric; MinHash gives sublinear candidate retrieval, which is what an
   index in the SQLite KB needs.
3. **Unit-cost TED** on the `structure_v2` region tree, via RTED/APTED. A true metric,
   O(n^3), shape-independent.
4. **NCD** over a *canonicalised* token stream (not raw bytes). Metric up to a small
   additive term under the normal-compressor axioms.

Explicitly **not** metrics, and therefore unsuitable as index distances: approximate GED
(bipartite upper bound, Hausdorff lower bound), GumTree scripts, cosine similarity of
learned embeddings without a proof, Wasserstein-based kernels without a PSD correction.
Approximate GED remains fine as the DecBench *reporting* number.

### (b) The canonical form to define first

**A typed value-dependence graph (VDG) per function, WL-hashed, over an e-graph-canonicalised body.** Concretely, in two layers so the second is optional:

*Layer 0 — the graph (build this first).* Nodes are SSA values and memory-SSA states.
Node label = `(opcode class, bit width, type class, constant bucket, callee class)`,
where: opcode class collapses architecture-specific mnemonics into a lifted operation
family; constants are bucketed (0, 1, -1, small, power-of-two, pointer-ish, other) so
that offset shifts do not shatter the label; callee class is the resolved symbol name
when known, PLT/import name when imported, and arity-class otherwise. Edges are
*positionally labelled* operand edges (ProGraML's lesson), memory-dependence edges, and
control-dependence edges derived from the region tree. **Addresses, register names,
block indices, and instruction order never appear.** Then run h=3 WL iterations with a
64/128-bit BLAKE3 (already a dependency) as the label compressor, and emit both a single
graph hash and the label multiset.

Why this first: invariance to register allocation, scheduling, and layout is achieved
*by construction* rather than by search; the object is a plain labelled digraph so every
tool in §2 applies to it unchanged; the hash is a KB primary key and the multiset is a
kernel feature vector, from one pass; and it degrades gracefully — a partially-recovered
function still yields a valid (coarser) hash.

*Layer 1 — the canonicalisation (compose later).* Before hashing, run bounded
equality-saturation over each value's defining expression with a rewrite set for
arithmetic identities, shift/multiply equivalences, comparison polarity, address
arithmetic, and division-by-constant sequences, then extract a minimum-cost
representative with a total tie-break order. Cranelift's ægraph shows this can be a
single bounded forward pass rather than saturation-to-fixpoint, which is the version
that stays deterministic and fast.

The pairing matters: WL-hashing *without* canonicalisation is brittle to exactly the
transformations that distinguish -O0 from -O2; canonicalisation *without* a
permutation-invariant hash gives you no distance at all. Together they are a computable
approximation of the quotient "equal up to compiler choices", with a clean one-sided
guarantee (same canonical form ⇒ same WL hash; different WL hash ⇒ genuinely different
under the rewrite theory).

### (c) Cheap in Rust with existing crates

Verified on crates.io during this survey:

- `petgraph` 0.8.3 (490M downloads) — graph types; the substrate for everything.
- `egg` 0.11.0 (3.1M downloads) — e-graphs and equality saturation, by the POPL'21
  authors. Alternative: port the ægraph single-pass design (no crate; the Cranelift
  source is the reference).
- `nauty-pet` 0.15.0 / `graph-canon` 0.1.4 — nauty/Traces canonical labelling over
  petgraph, for exact isomorphism classes. **Check the nauty licence before vendoring
  (not verified).**
- `rustworkx-core` 0.18.1 — general graph algorithms if petgraph's are insufficient.
- `blake3` 1.5.1, `strsim` 0.11, `rayon` 1.10 — already in `Cargo.toml`.
- Already in-tree: `src/ir/ssa.rs` (1,224 lines), `src/ir/value_number.rs` (2,692 lines,
  i.e. GVN already exists), `src/ir/structure_v2/` (region tree), `src/similarity/mod.rs`
  (CTPH). No graph-kernel or WL crate is needed — the WL loop is ~100 lines.
- Not available/mature: optimal transport (`wass` is unproven), graph-kernel libraries,
  TED (APTED would need a port — it is a well-specified ~1,000-line algorithm).

### (d) Ranked recommendations

Effort estimates are judgment, not measured.

1. **VDG + WL hash + WL label multiset** (§b Layer 0). ~1,200-1,800 LOC Rust plus tests.
   Unlocks: retrieval index, library identification, clustering, and a metric.
   Highest value per line in this report.
2. **MinHash sketch over the WL multiset, persisted in the `.glaurung` KB.** ~300 LOC.
   Turns the fingerprint into sublinear candidate retrieval. Jaccard distance is a
   metric, so metric-tree pruning is sound.
3. **A property test suite derived from Briand et al. (1996) and the metric axioms.**
   ~400 LOC of Rust/pytest: symmetry, identity of indiscernibles on the quotient,
   triangle inequality over sampled triples, and invariance assertions ("same source,
   -O0 vs -O2, i386 vs x86_64 ⇒ distance below threshold"). Glaurung's fixture matrix
   already supplies the cross-compiler pairs. Do this *with* item 1, not after.
4. **Bounded e-graph canonicalisation pre-pass** (§b Layer 1) using `egg` or an ægraph
   port. ~2,000-3,000 LOC including the rewrite set. Biggest single improvement to
   cross-optimisation invariance; also the biggest determinism risk — pin the crate
   version, cap iterations and node counts, and make extraction tie-breaks total.
5. **RTED/APTED on the `structure_v2` region tree.** ~1,000 LOC port. Gives a real metric
   on recovered structure and a principled replacement for ad-hoc structural diffing;
   also a second, independent opinion for patch-diff ranking.
6. **Nauty canonical labelling of small CFGs** as an exact-duplicate detector behind the
   WL hash (WL collisions get resolved exactly). ~200 LOC via `nauty-pet`, plus a licence
   review.
7. **Cheap negative-evidence filters**: abstract-domain summaries (§4) — argument/return
   interval and sign facts, syscall/import sets, block-count and cyclomatic-complexity
   bands. ~500 LOC. Not distances; they prune candidate sets before the kernel runs.
8. **I/O-behaviour digest** in the style of Blanket Execution, reusing the existing
   fixture-execution harness. ~2,000+ LOC and inherently non-deterministic without a
   pinned seed and environment. High value for obfuscation resilience, but park it
   until 1-5 land.
9. **Research track (do not implement yet)**: WL-meets-GW (ICML 2022) as a principled
   metric refinement with a proven lower-bound relation to GW; FGW for jointly matching
   CFG structure and node features. No usable Rust OT stack today.

**Do not build**: approximate GED as an index distance (not a metric — keep it only for
DecBench reporting); spectral CFG distances (label-blind, cospectrality); byte-level
CTPH/TLSH at function granularity (below the size floor where those digests are
meaningful); learned embeddings as a first move (the representations in §7 are the
transferable part, and they are all computable without a model).
