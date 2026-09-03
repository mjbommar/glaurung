# The Canonical Function Representation (CFR)

> **Kind:** reference · **Status:** maintained

**Implemented, normalised, weighted, indexed and measured.** Everything below is
in `src/identity/cfr/` and `python/glaurung/llm/kb/cfr_index.py`. Every number
carries the run it came from and the denominator it was measured over.

Two levers landed on separate branches and are now integrated. The opt-in
peephole normaliser ([Normalisation](#normalisation)) changes the
*representation*; the TF-IDF corpus table and the rare-feature inverted index
([Weighting](#weighting-the-corpus-tf-idf-table),
[Confidence](#confidence-bsims-significance),
[the index](#storage-and-retrieval-the-inverted-index)) change the *metric* over
whichever representation they were counted on. Both are off in
`CfrSettings::default()` and in the default `cosine(a, b, None)`, so the numbers
in [Measured numbers](#measured-numbers) are what the representation does with
neither, and [The two levers together](#the-two-levers-together) is the 2x2 over
one population. The research
synthesis this implements is
[`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md)
and its four source reports in
[`program-measures-2026-09-02/`](../history/program-measures-2026-09-02/).

## The question, and the shape of the answer

Glaurung wants a number for "how far apart are these two functions?" that is
computable, deterministic, blind to the choices a compiler makes, and stable
enough to index a corpus. Four use cases drive it: naming stripped binaries from
a library, ranking the changed functions between two builds, identifying
statically linked libraries, and clustering families.

The answer is to **quotient first, then metrise**. Invariance is built into the
representation rather than paid for in the matcher: register names, block order,
addresses, NOPs, dead flags, stack mechanics and large constants are absent by
construction, so two builds of one function land on the same object instead of
being reconciled by an expensive comparison. The object is a
Weisfeiler-Lehman feature multiset over a typed SSA dataflow graph and a
degree-labelled CFG; the number is the distance that multiset induces.

This is Ghidra BSim's design restated over Glaurung's LLIR, and the
deterministic dual of HermesSim: the same graph, a fixed-point relabelling
instead of gradients, no model and no GPU. The literature it comes from is
[`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md).

## Where it sits in the pipeline

```
lift_function_from_image      machine code -> LLIR
abi::annotate_calls           call effects, so a call has defs and uses
[ normalize::normalize_function ]  OPT-IN, on a COPY -- see "Normalisation"
ssa::compute_ssa_for_target   SSA identities
--------------------------------- CFR is computed HERE
value_number, types_recover, structure_v2, ast, render
```

It stops before structuring on purpose, and the reason is concrete:
`structure_v2` introduces `BinOp::LogicalAnd` and `BinOp::LogicalOr`, which are
*source-level, short-circuit, left-to-right* operators sitting in the same enum
as the bitwise `And` and `Or`. A machine-semantics graph must not contain them.
The second reason is stability: type recovery, prototype recovery and region
recovery are all under active development, and an identity that moved whenever
the renderer moved would not be an identity.

The two prerequisites the design named are delivered **inside**
`src/identity/cfr/`, not as changes to `src/ir/`. `VReg::Temp` is not widened;
`VReg::Phys` still carries its architectural name. The projection happens on the
way into a label, once.

## CFR-G: the operator-typed SSA dataflow graph

Nodes are SSA values and memory states. A node's label is a tuple, never a name:

```
(op_kind, width_class, operand_arity, value_class, const_bucket, callee_class)
```

| Field | Domain |
|---|---|
| `op_kind` | the projected operation: `add`, `load`, `phi`, `call`, `mementry`, `intr:cpuid`, ... |
| `width_class` | `w1 w8 w16 w32 w64 w128 w256 w512`, plus `wge4` under `nosize` and `w?` for unresolved |
| `operand_arity` | positional operand count, saturating at 255 |
| `value_class` | `const`, `global`, `stack`, `input`, `phi`, `derived` |
| `const_bucket` | `c0 c1 c-1 csmall cpow2 cptr clarge`, present only on constants |
| `callee_class` | `ext:<name>` for a resolved import, `int:<arity class>` for an internal call, `ind`, or `-` |

Encoded as `|`-separated text and compressed with BLAKE3; `|` cannot occur in a C
or Rust linkage name. `add|w64|2|derived|-|-` is a complete label, and the
absence of a register name from it is the whole design.

**Edges.** Positional operand edges; memory-dependence edges along a per-block
memory chain whose block-entry state merges its predecessors' exit states; and
control-dependence edges from a branch's predicate to the entry state of each
block control-dependent on it, computed from post-dominators this module owns.
Attaching control dependence to the block's memory-entry node rather than to
every node in the block costs one edge per dependence instead of one per node,
and the relabelling propagates it to everything downstream anyway.

**Relabelling.** Three Weisfeiler-Lehman iterations. Commutative nodes sum their
inputs' labels (a multiset sum, not an XOR -- an XOR cancels a repeated input);
positional nodes fold each input with its operand index. Features are every
node's label at every iteration including the seed, which is the WL *subtree*
kernel and is what lets a three-node function contribute anything at all.

**Removed rather than represented.** Unconditional jumps and NOPs get no node.
Pure copies and trivial phis are forwarded to their source. Anything no root
depends on is dropped by reverse reachability -- an x86 `cmp` writes six flags
and a `jne` reads one, and the other five must not become features.

## CFR-C: the block-order-independent CFG labelling

Each block is seeded with `(in_degree << 8) | out_degree`, a function of the
CFG's relations and of nothing else. One WL round mixes in the predecessors'
seeds, commutatively, with a different constant per edge kind:

| Edge kind | Constant | When |
|---|---|---|
| `cond_true` | `0x777` | branch taken |
| `cond_false` | `0x777 ^ 0x7abc7abc` | fallthrough, and the surviving edge of a conditional return |
| `unconditional` | `0x0f1e2d3c` | the predecessor has one way out |
| `switch` | `0x5a5ac3c3` | an arm of a computed transfer |

An edge whose target dominates its source is a back edge, and its constant is
xored with `0xb1cde5ed`. The dominators are `src/identity/cfr/dominators.rs`, a
deliberate second implementation of Cooper-Harvey-Kennedy: `structure_v2`'s
belongs to the decompiler's structuring stage, whose representation is free to
change with the recovery algorithm.

The true/false constants are BSim's verbatim, so a future comparison against
Ghidra's own vectors has one fewer difference to explain.

At each **root** operation -- call, indirect jump, store, conditional jump,
return, BSim's set -- the block's refined label is fused with the CFR-G label of
what that operation computed. Without the fusion, a block of six stores and a
block of six calls with the same degrees are the same feature.

## The mask / keep table

The specification, with the precedent for each row. Rows are from the synthesis
in [`04-program-representations-and-schemas.md`](../history/program-measures-2026-09-02/04-program-representations-and-schemas.md) section 9(b); the
"where" column names the code that implements it.

| Masked | Kept in its place | Precedent | Where |
|---|---|---|---|
| Register names and allocation | operand **width class** | BSim: "names of registers ... are intentionally not incorporated"; Binary Ninja MLIL translates registers to variables | `labels.rs`, `widths.rs` |
| Block layout order | degree seeds, relation-derived edge multiset | WARP sorts block GUIDs; BinDiff's MD index; our own fingerprint already sorts | `blocks.rs` |
| Absolute addresses and relocation targets | the *class* `global_addr`; a call edge to a resolved callee identity | WARP zeroes relocatable instructions; BinExport2's `Expression.is_relocation`; FunctionID excludes address-like constants | `labels.rs` `ConstBucket`, `extract.rs` |
| NOPs and alignment padding | nothing | WARP excludes NOPs | `graph.rs` (`Op::Nop` gets no node) |
| Unconditional jumps | nothing; the edge survives in CFR-C | layout, not computation | `graph.rs` |
| Dead flag computations | the *fused* comparison at the branch | BSim's `normalize`; Binary Ninja LLIL folds flags into conditionals; GDSL/RREIL reports ~50% code reduction from block-scope flag liveness | `prune.rs` (`live_nodes`) |
| Stack-frame mechanics | the `stack_addr` value class, so locals stay keyed by frame position | BSim "abstracting stack mechanics"; MLIL "the stack as a concept is not present" | `stack.rs` |
| Register copies and trivial phis | nothing | BSim drops shadow varnodes via the dominator tree; Braun et al.'s trivial-phi rule | `prune.rs` (`shadow_forwarding`) |
| Exact constant values | a bucketed magnitude class | BSim excludes constant values; FunctionID's full hash excludes them; SAFE masks `\|v\| > 5000`; PalmTree masks >= 5 hex digits; angr's bindiff demotes constant differences to `ConstantChange` | `labels.rs` `ConstBucket` |
| Internal callee identity | a bucketed argument arity | jTrans maps internal call names to `<function>` and keeps external ones: a stable interface survives a version bump, a private name does not | `labels.rs` `CalleeClass` |
| Symbol names and type names | nothing here; they live in the KB payload | WARP separates the GUID from its `Symbol`/`Type` payload; BSim excludes data types | -- |
| Varnode size at >= 4 bytes, *optionally* | `wge4` | BSim's `medium_nosize`, which is what enables 32-to-64-bit matching | `CfrSettings::nosize` |
| **Not masked**: operand position for non-commutative operators | positional mixing in the WL round | ProGraML gives every data edge a `position`; BSim mixes non-commutative inputs positionally | `commutativity.rs`, `wl.rs` |
| **Not masked**: external callee names | the name, verbatim, after linker decoration is stripped | jTrans; every tool in the survey | `extract.rs` `normalize_import_name` |
| **Not masked**: CFG shape as relations | degree seeds, edge kinds, back-edge flags | BinExport2 stores exactly this, computed by Lengauer-Tarjan | `blocks.rs` |

### One deliberate departure

SAFE and PalmTree keep *small* immediates verbatim, on the grounds that they
identify locals, arguments and struct fields. We keep only the bucket. The
reason is that a stack displacement is exactly the thing that moves between
`-O0` and `-O2` as the frame is relaid out, and cross-optimisation matching is
what this rung exists for. BSim masks constants entirely and is stricter still.
`src/identity/cfr/tests.rs::constant_magnitude_classes_are_kept_and_exact_values_are_masked`
asserts the consequence in both directions.

### Constant bucket thresholds

| Bucket | Rule |
|---|---|
| `Zero`, `One`, `MinusOne` | exactly `0`, `1`, `-1`; classed before magnitude is consulted |
| `Small` | `\|v\| <= 5000` -- SAFE's published threshold, the tighter of the two anchors |
| `Pow2` | above the small threshold and an exact power of two: alignment masks, bit fields |
| `PointerLike` | above the small threshold, not a power of two, and within `[0x1000, 0x00007fffffffffff]` -- above the unmapped first page, below the top of the canonical low half |
| `Large` | everything else: hash seeds, float bit patterns, sign masks |

## The commutativity table

`src/identity/cfr/commutativity.rs`, every entry justified in place.

| Operator | Mixing | Why |
|---|---|---|
| `Add`, `Mul` | commutative | commutative in two's complement at every width, wrapping included |
| `And`, `Or`, `Xor` | commutative | commutative bit by bit |
| `Eq`, `Ne` | commutative | symmetric relations; compilers pick the operand order freely |
| phi, block-entry memory merge | commutative | a merge over an unordered predecessor set, and predecessor order *is* block layout order |
| `Sub` | positional | `a - b != b - a`. The canonical case: with commutative mixing the two produce an identical feature multiset, and subtraction is the most common asymmetric operation in compiled code -- every bounds check, every pointer difference, every loop countdown |
| `Div` | positional | dividend and divisor are different roles |
| `Shl`, `Shr`, `Sar` | positional | the operands are not the same kind of thing: one is the value, the other the distance |
| `Ult`, `Ule`, `Slt`, `Sle` | positional | ordered comparisons reverse under a swap |
| `Load` (address vs memory state) | positional | different roles; and a scaled base and index are not interchangeable |
| `Store` (address vs value) | positional | `*p = q` and `*q = p` are different programs |
| `Call` | positional | arguments are in ABI order, which is the callee's contract |
| `Concat`, `Ite` | positional | `hi`/`lo`; `cond`/`then`/`else` |
| `LogicalAnd`, `LogicalOr` | positional | short-circuit and left-to-right, so a swap changes which side effects happen. Also a signal that canonicalisation ran too late -- these should not exist pre-structuring |

Anything else defaults to positional, which is the safe direction: declaring a
commutative operator positional costs recall on operand-swapped twins, while
declaring a non-commutative operator commutative silently merges two different
functions. `BinOp` has no remainder operator, so there is no `Rem` row.

## Width inference

`VReg::width()` answers for a physical register (by ISA name) and for a flag
(one bit) and returns `None` for `VReg::Temp`. The seed needs a width, because
width is the *only* thing a register contributes once its name is masked.
`widths.rs` derives one, in order of authority:

1. the storage location -- a physical register's ISA width, a flag's one bit;
2. the defining operation -- a load's access size, an extension's declared
   target, an `Extract`'s bit span, an `Ite`'s declared width, a comparison's
   single bit, an intrinsic's declared output;
3. the operands, for width-propagating operations -- a move, a bitwise
   operation, a negation, a `Concat` (the sum), a shift (the *value*, never the
   distance).

A phi takes the widest of its incoming values: in well-formed SSA they agree,
and they can disagree only where sub-register merging has put a 32-bit and a
64-bit definition in one location, which is 64 bits wide.

The fixed point is monotone -- absent to known, known only wider -- over a
lattice bounded at 512 bits, so it terminates on its own; `MAX_ROUNDS` is a
backstop against a future IR change breaking monotonicity, not the mechanism.

**`Unknown` is a class, not a guess.** A value the pass cannot resolve keeps a
distinct label. Guessing a machine word would merge it with genuine 64-bit
values and the error would be invisible. `WidthCensus` reports the rate, and it
crosses the Python boundary as `width_unknown` / `width_total`.

## Output, versioning and the metric

```rust
CfrSignature {
    version: CfrVersion { major, minor, settings },
    features: Vec<(u32, u16)>,   // sorted ascending by hash
    digest: [u8; 32],            // BLAKE3 over the version triple then the features
}
```

The sorted `(hash, count)` encoding is BSim's `1:545c6155`, and it is what makes
the comparison an `O(n + m)` merge join.

**Version discipline.** Any change to the mask list changes every feature of
every function, so a vector computed under the old rules is not comparable with
one computed under the new. `major` moves when the mask list moves; `minor` when
features are added without changing the meaning of existing ones; `settings` is
a bit field, currently just `nosize`. Two signatures whose major or settings
differ are **not compared at all**: `cosine` returns `0.0`. That is deliberately
the same answer as "no shared features", because an unanswerable comparison and
a comparison with no evidence are both "no", and a small non-zero number would
read as "distant but related". BSim carries `major`/`minor`/`settings` in its
database for exactly this reason, and adding it after a corpus exists is
painful.

**The kernel.** Each feature gets `c_f = idf(f) * (1 + log2(tf_f))`, and

```
k(A, B) = sum over shared f of min(c_A(f), c_B(f))^2
```

which is BSim's formula. `min(x, y)` is PSD on the non-negative reals (Brownian
covariance); the Schur product theorem makes `min(x, y)^2` PSD; a sum of PSD
kernels is PSD. So

```
d(A, B) = sqrt(k(A,A) + k(B,B) - 2 k(A,B))
```

is induced by an inner product and satisfies symmetry, non-negativity, identity
on the quotient and the triangle inequality **exactly**, not approximately. That
is what makes it indexable. Approximate graph edit distance has none of those
properties and exact GED is APX-hard; it stays a reporting number for DecBench
and is not an index distance.

`d(A, B) = 0` does not say the two functions are the same. It says they have the
same canonical form. 1-WL is one-sided: different features prove a difference,
identical features do not prove identity.

**Weights.** `UniformWeights` (`idf = 1`) is the no-table fallback and is what
every *unweighted* number below was measured under. The corpus table that
replaces it is the next section.

## Weighting: the corpus TF-IDF table

`src/identity/cfr/weights.rs`. Without it a `mov` between two registers weighs
as much as a call to `pthread_mutex_lock`, and the measured cost of that is at
the bottom of this section.

A feature's **document frequency** `df(f)` is the number of functions carrying
it at least once -- not the number of occurrences, which is the term frequency
and is already handled by the `1 + log2(tf)` term inside the kernel. Over a
corpus of `N` functions:

```text
idf(f) = ln((N + 1) / (df(f) + 1))          [nats]
```

The `+1` on both sides is add-one smoothing and it is doing two jobs, neither
cosmetic. It keeps the weight **finite** for a feature the corpus has never seen
(`df = 0`), which is the ordinary case at query time and which plain
`ln(N / df)` sends to infinity. And it keeps the weight **non-negative** for a
feature every function carries (`df = N`), where plain `ln(N / df)` is exactly
zero and one rounding error below it is negative -- and a negative weight makes
the kernel indefinite, which takes the triangle inequality with it and with it
everything the index rests on. `no_weight_is_ever_negative` asserts it directly.

So the range is `[0, ln(N + 1)]`: a universal feature contributes nothing, and a
feature seen once in a million-function corpus contributes about 13.

### Quantisation

BSim stores a `u16` per feature rather than a double
(`LSH_ITEM{uint32 hash; uint16 tf; uint16 idf; double coeff;}`) and covers its
commonest hashes with a fixed number of levels. This table does the same, with
**512 levels evenly spaced over `[0, 16]` nats**:

```text
bucket(f) = round(clamp(idf(f), 0, 16) * 511 / 16)
weight(f) = bucket(f) * 16 / 511
```

Sixteen nats is `ln` of about 8.9 million, so the ceiling binds only on a corpus
larger than any this project indexes; fixing it as a constant rather than
deriving it from `N` is what puts two tables built over differently sized
corpora on the same scale. The step is 0.031 nats, a 3.2% resolution on the
frequency ratio a weight encodes -- finer than the gap between two adjacent
document counts anywhere the weight matters.

Quantising is not only a storage saving. A weight table is part of a score that
gets stored, compared and ratcheted, and a full-precision `f64` recomputed over
a different corpus ordering can differ in its last bits; a bucket index cannot.
Two tables that agree on every bucket produce bit-identical scores.

### `weights_id`, and why a reweight is not an update

Every stored vector's score depends on the table it was scored under. BSim
freezes its weight scheme at database creation and documents that it "cannot be
changed without reingesting". `CorpusWeights::weights_id` makes that explicit:
a BLAKE3 over the scheme name, the full `(major, minor, settings)` triple, the
quantisation parameters, the corpus size and every `(feature, bucket)` pair,
printed as `cfr-1.0-s0-idf512-<16 hex>`. Anything that could change a weight
changes the id, so a reweight is a new id rather than a silent rescoring of
rows that are still sitting in the table.

### What a feature the table has never seen is worth

The corpus maximum, `ln(N + 1)`. That is the honest answer rather than a
conservative one: the table's whole claim is that rarity is evidence, and a
feature it has never seen is as rare as its evidence goes. It only inflates the
norms, because a feature absent from the table can still be *shared* by two
functions -- and then it is shared rarely, which is exactly the case worth
scoring highly.

## Confidence: BSim's significance

`src/identity/cfr/similarity.rs`. The cosine says "how alike". It does not say
"is this a coincidence", and it cannot: two four-feature functions sharing three
features score 0.75 whether those features are in every function on earth or
unique to one library. BSim returns two numbers from one comparison for this
reason, and so does `confidence()`.

**The formula is BSim's, recovered from public source rather than approximated.**
It is `LSHVectorFactory.calculateSignificance` in
`Ghidra/Framework/Generic/src/main/java/generic/lsh/vector/`, whose C twin is
`lsh_compare_internal` in `Ghidra/Features/BSim/src/lshvector/c/weights.c`:

```text
sig = dotproduct
    - numflip * (probflip0 + probflip1 / max)
    - diff    * (probdiff0 + probdiff1 / max)
    + addend
```

with, from `VectorCompare.fillOut()`:

| Term | Definition |
|---|---|
| `acount`, `bcount` | total feature **occurrences** on each side -- BSim's `hashcount` is the sum of the term frequencies, not `numEntries()` |
| `min`, `max` | min and max of those two |
| `intersectcount` | `sum over shared f of min(tf_A, tf_B)` |
| `numflip` | `min - intersectcount` |
| `diff` | `max - min` |

The model behind the two penalties is stated in Ghidra's own doc comment:
*"Assume small vector is produced by flipping and removing hashes from big
vector."* `numflip` counts occurrences the smaller function has that the larger
does not -- the same computation spelled differently -- and `diff` counts the
extra work the larger function does. Both are charged at a rate with a constant
part and a part that decays as `max` grows, because a longer function has more
chances to differ by accident.

The five constants are `lshweights_64.xml`'s, divided through by that file's
`scale`, and the weights are normalised by `Weights::max_idf` so the rarest
feature the table can express again has coefficient 1 -- the normalisation BSim
performs by folding `sqrt(scale)` into every loaded weight.

### What is BSim's here and what is ours

**BSim's, verbatim:** the shape, the definitions of `numflip`/`diff`/`max`
(occurrences with multiplicity, which is easy to get wrong and changes all three
at once), the five fitted constants, the self-significance bound, and therefore
the calibration below.

**Ours:** the features being counted, and the coefficient. BSim's is
`idfweight[bucket] * sqrt(1 + log2(tf))` with `idfweight[0] = 1` for any feature
outside its thousand-entry lookup; this module's is `idf(f) * (1 + log2(tf))`.
The two agree exactly at `tf = 1`, the overwhelming majority of features, and
diverge for repeated ones: BSim's `coeff^2` is linear in `1 + log2(tf)` where
this module's is quadratic. That difference is inherited from the kernel above,
which was measured and published before this function existed.

**The consequence, stated plainly:** the constants were fitted by the NSA to a
feature distribution that is not this one. The score is on BSim's scale by
construction and on BSim's calibration only by assumption. Read the table below
as an order of magnitude for this representation, not as a measured
false-positive rate for it.

### Calibration

Ghidra's `help/topics/BSim/FeatureWeight.html`, verbatim, and the reason
`false_positive_one_in` returns nothing below 10:

| Confidence | False positive rate |
|---|---|
| 10 | 1 in 4,000 |
| 26 | 1 in 100,000 |
| 43 | 1 in 1,000,000 |
| 93 | 1 in 1,000,000,000 |

The page states the rate halves every four to five points, and states that it
holds "for scores of 10.0 and greater" because "a general correspondence between
low confidence scores and false positive rates can be somewhat skewed by
wrappers and other small functions". Below 10 there is no rate to quote and
`false_positive_one_in` answers `None` rather than extrapolating one. Above 93
the last segment's slope continues. `CONFIDENT_SIGNIFICANCE` is 26.

### The bound is a theorem, not a clamp

`min(cA, cB)^2 <= cA^2` termwise and both penalties are non-negative, so

```text
significance(A, B) <= min(self_significance(A), self_significance(B))
```

falls out of the definition with nothing clamping anything.
`self_significance` is `length^2 + addend`, which is the formula above
specialised to a self-comparison where the intersection is everything and both
penalties vanish -- BSim's `getSelfSignificance`, and the quantity its query
paths use as a pre-filter:

```text
// Self significance should be bigger than the significance threshold
// (or its impossible our result can exceed the threshold)
if (len2 < query.signifthresh) { continue; }
```

It grows with the function, so **a small function cannot reach a confident match
however well it matches.** That is the property report 03 names as the thing
BSim's confidence has and a fixed threshold does not, and it is asserted three
times: on constructed vectors
(`a_small_function_cannot_reach_a_confident_match_however_well_it_matches`), on
real functions through the Python boundary (`test_cfr_index.py`), and over the
corpus (`cfr_significance_is_bounded_by_self_significance`).

## Storage and retrieval: the inverted index

`python/glaurung/llm/kb/cfr_index.py`, implementing section 4 of
[`03-schema.sql`](../history/program-measures-2026-09-02/03-schema.sql).

| Table | Holds |
|---|---|
| `cfr_weight_table` | one row per frozen table: `weights_id`, the CFR version triple, the corpus size, `top_k` |
| `feature_weight` | `(weights_id, feature_hash) -> (doc_count, weight)` |
| `feature_vector` | one row per **distinct canonical form**, keyed by the CFR digest, with the packed `(u32 hash, u16 count)` blob, its self-significance under the table, and a refcount |
| `function_vector` | `(binary_id, entry_va) -> vector_id` |
| `feature_posting` | `(feature_hash, vector_id)` for each vector's **32 rarest** features |

Two deliberate departures from the proposal's column list, both stated in the
module docstring: `vector_hash` is the CFR's own 64-hex digest rather than a
second 64-bit integer that could collide, and the proposal's `norm` is
`self_significance`, which is what BSim's own embedded backend stores
(`H2VectorTable`: `VectorStoreEntry(id, vec, count, getSelfSignificance(vec))`)
and what lets a thresholded query skip a stored vector without reading its
features at all.

**Deduplicated and refcounted** is BSim's `vectable.count` / `desctable.id_signature`
split. It is a large saving on a library-heavy corpus and it is also the cheapest
false-positive signal available: a vector with a refcount of two hundred is CRT
boilerplate and a match against it means nothing. `CfrMatch` carries the
refcount for that reason.

**K = 32** postings per vector, so the index is linear in the corpus and
independent of function size -- a full postings list would give a 900-feature
function 900 rows, and the commonest features would contribute the longest and
least useful lists. The reasoning is AllPairs' prefix filter's: a rare feature's
posting list is short and its evidence is high, and two functions that are
genuinely the same overwhelmingly share more than one of their rarest features.
Note what K does *not* affect: nothing is scored from the index. It generates
candidates; every candidate is then rescored exactly against its full stored
vector. So K trades recall for time, never precision.

**Two retrieval paths, chosen by corpus size rather than by a knob.** At or
below **100,000 stored vectors** `query_cfr` scans every vector, which is exact
by construction. Above it, candidates come from the postings of the query's own
highest-IDF features, rarest first, so a truncated candidate set has dropped the
weakest evidence rather than an arbitrary slice of it. The figure is the
research synthesis's -- "Flat scan until about 1e5 to 1e6 vectors. Ghidra's own
embedded BSim backend has no LSH index at all; it is an exact hash plus a linear
scan" -- and below it the cheaper answer is also the better one.
`test_the_index_and_the_scan_agree_on_the_top_hit` runs both on the fixture
corpus and pins that they agree, which is the only thing that stops the index
path silently rotting while the scan carries every real query.

**A rebuild rather than an append**, by default, and the docstring says why: a
feature's IDF is a property of the whole corpus, so adding one binary moves
every stored norm. Pinning a table (`build_cfr_index(..., weights=...,
replace=False)`) lets an index be extended; mixing two `weights_id`s in one
index is refused rather than allowed to produce two incomparable scorings
sharing a column.

```python
from glaurung.llm.kb.cfr_index import build_cfr_index, query_cfr

summary = build_cfr_index(kb, ["libfoo-gcc-O2.so", "libbar-gcc-O2.so"])
matches = query_cfr(kb, unknown_signature, k=10,
                    min_significance=g.analysis.CFR_CONFIDENT_SIGNIFICANCE)
for match in matches:
    print(match.entry_va, match.cosine, match.significance, match.refcount)
```

## Measured numbers

Two harnesses measure this, over two corpora, and they answer different
questions.

`tests/identity_cfr_retrieval.rs` is the CFR's own lane: size-matched pools,
LLIR instruction count as the size, its own filter set stated per lane. Its
numbers are below under [Its own lane](#its-own-lane).

`tests/identity_retrieval/` is the **shared** protocol every identity scheme is
scored under -- Marcelli's task taxonomy, the published filters, 100 negatives
per positive drawn from the task's own pool slice, pessimistic ties. Those
numbers are directly comparable with CTPH and with the L1 structural invariants
and are the ones to quote. The full tables live in
[`docs/development/identity-measurement.md`](../development/identity-measurement.md);
the summary is here.

### Unweighted, the shared protocol

Release build, 2026-09-02, bit-identical in a debug build. Sampled pool 101
throughout, so chance Recall@1 is 0.0099.

| Corpus | Task | Scored | Global pool | AUC | MRR10 | R@1 |
|---|---|---|---|---|---|---|
| in-house | XO-gcc | 389 | 410 | 0.7569 | 0.2543 | 0.1799 |
| in-house | XO-clang | 366 | 377 | 0.7135 | 0.1808 | 0.1120 |
| in-house | **XC-O0** | 487 | 494 | **0.9663** | **0.9162** | **0.8706** |
| in-house | XC-O2 | 357 | 377 | 0.8921 | 0.5688 | 0.5014 |
| in-house | XM | 365 | 377 | 0.7296 | 0.1990 | 0.1342 |
| Dataset-1 | XO | 50 | 229 | 0.9127 | 0.7570 | 0.6800 |
| Dataset-1 | XC | 65 | 348 | 0.9638 | 0.9667 | 0.9385 |
| Dataset-1 | XM | 36 | 262 | 0.8806 | 0.7301 | 0.6667 |
| Dataset-1 | **XB** | 72 | 260 | **0.9353** | 0.6695 | 0.5694 |
| Dataset-1 | **XA-arm64** | 47 | 228 | **0.9131** | 0.8045 | 0.7447 |
| Dataset-1 | XA-mips64 | **0** | -- | -- | -- | -- |
| Dataset-1 | XA+XB-mips32 | **0** | -- | -- | -- | -- |

The two zeroes are the honest cell. `src/ir/lift/` covers x86, x86-64, ARM and
AArch64 and reaches MIPS not at all, so the CFR has no signature to give on
those slices and `CfrScheme::extract` **refuses** rather than returning an empty
vector -- which would score 0.0 against everything and read as a measured
failure instead of a coverage hole. CTPH scored those rows at exactly 0.5000
(chance) and `structural` at 0.574 and 0.552; this scores them not at all, and
the difference between "wrong" and "cannot answer" is the whole point of
`SchemeError`.

### Weighted against unweighted

The delta is measured on the **held-out half** of each corpus, against an
unweighted control over the identical population. The split is SplitMix64 over
the ground-truth label (`scheme::cfr_in_training_half`), so a function is in
training or held out in every slice at once -- its `-O0` build never trains the
table that scores its `-O2` build. That is *stricter* than production: BSim
counts its IDF over the corpus it later searches, as does every TF-IDF retrieval
system, because a document frequency is a property of the collection and not a
fitted parameter. These rows therefore understate what the weighting is worth in
a deployment that indexes what it searches.

In-house corpus, weight table over 910 training-half functions, 39,969 weighted
features:

| Task | Scored | Pool | AUC unw. -> wtd. | MRR10 unw. -> wtd. | R@1 unw. -> wtd. |
|---|---|---|---|---|---|
| **XO-gcc** | 187 | 200 | 0.7800 -> **0.8592** (+0.079) | 0.2549 -> **0.5080** (+0.253) | 0.1872 -> **0.4064** (+0.219) |
| **XO-clang** | 178 | 184 | 0.7419 -> **0.8152** (+0.073) | 0.1829 -> **0.3729** (+0.190) | 0.1124 -> **0.2809** (+0.169) |
| XC-O0 | 241 | 243 | 0.9679 -> 0.9938 (+0.026) | 0.9501 -> 0.9557 (+0.006) | 0.9253 -> 0.9253 (0.000) |
| XC-O2 | 172 | 184 | 0.8935 -> 0.9461 (+0.053) | 0.5681 -> 0.6549 (+0.087) | 0.5116 -> 0.5698 (+0.058) |
| XM | 177 | 184 | 0.7625 -> 0.8131 (+0.051) | 0.1984 -> 0.4232 (+0.225) | 0.1243 -> 0.3333 (+0.209) |
| XM-S | 141 | 184 | 0.7474 -> 0.7963 (+0.049) | 0.1699 -> 0.4128 (+0.243) | 0.0922 -> 0.3191 (+0.227) |
| XM-M | 34 | 184 | 0.8355 -> 0.8797 (+0.044) | 0.2394 -> 0.4303 (+0.191) | 0.1176 -> 0.3235 (+0.206) |

Dataset-1, weight table over 958 training-half functions (the MIPS half of the corpus contributes none), 212,090 weighted features:

| Task | Scored | Pool | AUC unw. -> wtd. | MRR10 unw. -> wtd. | R@1 unw. -> wtd. |
|---|---|---|---|---|---|
| **XO** | 18 | 106 | 0.8880 -> **0.9902** (+0.102) | 0.5718 -> 0.8426 (+0.271) | 0.5000 -> 0.7222 (+0.222) |
| XC | 29 | 171 | 0.9586 -> 0.9972 (+0.039) | 0.9483 -> 0.9425 (-0.006) | 0.8966 -> 0.8966 (0.000) |
| XM | 18 | 125 | 0.8681 -> 0.9291 (+0.061) | 0.5802 -> 0.6543 (+0.074) | 0.5000 -> 0.6111 (+0.111) |
| XB | 30 | 127 | 0.9642 -> 0.9844 (+0.020) | 0.7001 -> 0.8722 (+0.172) | 0.5667 -> 0.8000 (+0.233) |
| XA-arm64 | 19 | 115 | 0.9185 -> 0.9855 (+0.067) | 0.8132 -> 0.8921 (+0.079) | 0.7895 -> 0.8421 (+0.053) |
| XA+XB-arm32 *(n=9)* | 9 | 128 | 0.9667 -> 0.8878 (-0.079) | 0.7778 -> 0.8148 (+0.037) | 0.7778 -> 0.7778 (0.000) |
| XA+XO *(n=9)* | 9 | 115 | 0.8635 -> 0.8983 (+0.035) | 0.4251 -> 0.3529 (-0.072) | 0.2222 -> 0.1111 (-0.111) |

**Three things to read off these.**

**The plan's hypothesis holds, and holds on every metric.** Weighting was
predicted to lift **XO** most, and it does: the largest AUC gain on both corpora
(+0.079 in-house, +0.102 on Dataset-1) and the largest ranking gains anywhere in
either table (+0.253 MRR10, +0.219 Recall@1). The mechanism is visible in the
row that gains least: XC-O0 was already at AUC 0.968 with Recall@1 0.925 and had
almost nothing left to gain, while XO sat at 0.780 -- and what separates a
function from its `-O2` twin's neighbours is exactly the rare structure a
uniform weighting drowns in `mov`-shaped noise.

**Ranking gains far outrun AUC gains.** XM moves +0.05 AUC and +0.225 MRR10.
AUC asks whether a positive pair outscores a random negative pair, which
unweighted CFR already mostly gets right; MRR10 asks whether the twin outranks
one hundred *size-matched* negatives, and that is the question weighting
answers. A scheme evaluated on AUC alone would have reported this lane as a
modest improvement.

**The two negative cells are the two underpowered rows.** `XA+XB-arm32` and
`XA+XO` score nine queries each -- one query is 11 percentage points of
Recall@1 -- and both are flagged and unratcheted for exactly that reason. Read
them as noise, and read the seven powered Dataset-1 and in-house rows as the
result.

### Cost

| Build | us/function | Note |
|---|---|---|
| release | 1,810 | in-house corpus, 1,787 samples |
| debug | 12,004 | the profile `cargo test --features python-ext` uses |
| release | 25,331 | Dataset-1, 2,441 samples, six architectures |

An order of magnitude past TikNib's published 20-1030 us band, and structurally
so: the CFR is the only scheme in the harness that lifts to LLIR and runs SSA,
where CTPH reads bytes (41 us) and `structural` reads a discovered CFG (267 us).
The Dataset-1 figure is higher again because its binaries are larger and the
harness's per-image signature cache turns over more.

**Retrieval scores are bit-identical between the two profiles**, which is worth
recording: the numbers above were read off a release run and reproduced exactly
by the debug ratchet run in the same commit.

### Its own lane

`tests/identity_cfr_retrieval.rs`, unweighted, release, 2026-09-02. A different
filter set and a different negative-sampling rule from the shared protocol
above -- negatives are the 100 candidates nearest the query in **LLIR
instruction count** -- so these are not comparable with the tables above and are
kept because the whole-slice lane is comparable with `tests/similarity_retrieval.rs`'s
CTPH number on the identical task.

Corpus: `tests/decompiler_fixtures/build/`, 206 C sources compiled by gcc and
clang at `-O0` and `-O2` with symbol tables intact, so `(fixture, function
name)` is an exact label. Run 2026-09-02, release build, unweighted. Harness:
`tests/identity_cfr_retrieval.rs`.

Filters. Everywhere: functions with fewer than **5 basic blocks** are dropped,
and names are deduplicated within a binary. In the two size-matched lanes only:
functions whose canonical form is shared with another function in the same slice
are dropped -- `__do_global_dtors_aux` is the same CRT function in all 206
fixtures, and a retrieval question with 206 identical correct answers has no
answer. The whole-slice lane does **not** apply that filter, so it stays
comparable with `tests/similarity_retrieval.rs`, which does not either.

Negatives are the 100 candidates **nearest the query in LLIR instruction
count**, so "whichever is closest in length" is not a winning strategy. A tie
counts as a miss.

| Lane | Free variables | Result | Chance | Pool |
|---|---|---|---|---|
| XO, size-matched | optimisation level | **51/341 = 14.96%** Recall@1 | 0.99% | 1 + 100 |
| XC, size-matched | compiler | **148/309 = 47.90%** Recall@1 | 0.99% | 1 + 100 |
| XO, whole slice | optimisation level | **44/594 = 7.41%** Recall@1 | 0.16% | 610 candidates |
| exact quotient match, XO | optimisation level | **2/341 = 0.59%** | -- | -- |
| width inference unresolved | -- | **8,033/362,980 = 2.21%** | -- | gcc `-O0` slice |

Three things are worth reading off that table.

**The whole-slice lane is the comparable one.** `tests/similarity_retrieval.rs`
pins CTPH at **0.32%** on the same corpus and the same task (924 queries, 1,096
candidates, no duplicate filter). 7.41% is twenty-three times that, which is the
expected ordering -- and still nowhere near a tool you would point at a stripped
binary unassisted. All three of the things that gap was said to be waiting for
-- the peephole normaliser, the TF-IDF weighting and the rare-feature index --
have landed since. The normaliser takes this lane to 8.59% (see
[Normalisation](#normalisation)); the weighting's effect is measured in the
shared-protocol tables above rather than here, because this lane is deliberately
left unweighted so that it stays comparable with the CTPH number it was written
to sit beside.

**Cross-compiler is three times cross-optimisation**, and the contrast is the
entire argument for canonicalising over an IR. gcc and clang at one optimisation
level build the *same program* from the same source and differ in register
allocation, instruction selection and block order -- precisely the list the
projection erases. `-O0` to `-O2` changes the graph itself: unrolling duplicates
a loop body, inlining merges two functions into one, and no mask list reaches
either.

**The exact-match lane fell from 35% to 0.59% when duplicates were dropped.**
Every one of those 206 extra hits was the same piece of CRT boilerplate. It is
the clearest illustration in this work of why a retrieval number without its
filter set and its denominator is not a number.

## Normalisation

Plan item 8: an **unsound, local peephole normaliser**, applied to a copy of the
lifted function before the graph is built. `src/identity/cfr/normalize/`, opt-in
through `CfrSettings::normalize`, off by default.

### This artifact is unsound, and it never feeds the decompiler

Every pass here is allowed to be wrong in ways the decompiler's own passes may
never be: to fold at the wrong width, to forward a load past a store it cannot
prove non-aliasing, to flip a predicate a successor block also reads. That is
the licence VexIR2Vec's authors take for VexINE, the system this is modelled on,
and they state it plainly:

> soundness is not important in this context: the normalizations are designed to
> reduce the differences in IR generated from different architectures and
> compilers.

Three mechanical facts keep that licence contained.

1. **It runs on a clone.** `normalize_function` borrows the caller's
   `LlirFunction` and returns a new one; the input is never mutated
   (`tests::the_input_function_is_not_touched`). The clone is dropped as soon as
   the feature multiset exists.
2. **Nothing in `src/ir/` calls it, and this lane changed no file there.**
   Glaurung already has sound, global versions of most of these transformations
   -- `ir::copy_prop`, `ir::const_fold`, `ir::value_number`, `ir::dce`,
   `ir::dead_stores` -- and they exist to make rendered C correct. These are a
   second, deliberately worse implementation for a different purpose.
3. **It is a bit in the version triple.** A normalised signature and an
   unnormalised one are *not comparable*: `cosine` answers `0.0`, the same
   answer it gives across a `nosize` difference, because they are different
   quotients rather than different precisions.

With the flag off, every signature byte is what it was before the directory
existed. `tests::with_the_flag_off_every_signature_byte_is_what_it_was` pins
three hand-built functions against digests measured on `a5ba7f7c`, the commit
before this work started.

### The peephole

One basic block, straight-line, with VexINE's invariant: **a value used but not
defined in the peephole is a parameter and must survive**. No pass looks outside
its block, so no pass needs liveness, dominance or a call graph. Passes run in a
fixed order for at most `MAX_ROUNDS = 4` rounds per block -- rounds because the
passes feed each other (CSE turns a duplicate into a copy that copy propagation
then forwards), a cap because no pass individually proves the system terminates.
Every container is a `BTreeMap` or a `Vec`, never a `HashMap`: a canonical form
whose features depended on hash iteration order would not be an identity.

### The rules

| Pass | Rule | Precedent | Default? |
|---|---|---|---|
| (a) `opcodes` | intrinsic width suffix stripped (`intr:x86.smul_hi.64` -> `intr:x86.smul_hi`); `Sub x, C` -> `Add x, -C`; `Xor x, x` and `Sub x, x` -> `0`; `And x, x`, `Or x, x` and every algebraic identity (`+0`, `*1`, `&-1`, `<<0`, ...) -> a copy; a width-neutral `ZExt`/`SExt`/`Trunc` -> a copy; `intr:x86.{s,u}div_quot` -> `BinOp::Div` | VexIR2Vec rules 1 and 3, `Add8\|Add16\|Add32 -> Add` and the immediate-sign rule; LLVM `InstCombine`; Cranelift's egraph rules | yes |
| (b) `constants` | block-local constant folding and copy propagation, plus a constant memory base folded into the displacement | VexINE ("copy propagation, constant propagation/folding"); Fraser and Davidson | yes |
| (c) `cse` | local common-subexpression elimination over pure operations, invalidated on any redefinition | VexINE ("CSE"); Cocke 1970; Alpern-Wegman-Zadeck generalises it | yes |
| (d) `redundancy` | load-after-store forwarding, store-store elimination, redundant register-write elimination | VexINE ("redundant-write elimination ... load-store and store-store elimination"); BSim's "abstracting stack mechanics" | yes |
| (e) `polarity` | an inverted consumer's negation pushed back into the `Cmp` that produced the predicate, with the operand swap the ordered relations need (`!Ult(a,b)` is `Ule(b,a)`) | Ghidra's `normalize` folding `BOOL_NEGATE` into its comparison; Binary Ninja LLIL folding flags into conditionals | yes |
| (f) `strength` | `Mul x, 2^k` -> `Shl x, k`; the three provable magic-number division idioms -> `BinOp::Div` | Granlund and Montgomery (PLDI 1994) for the construction; Ghidra `divopt`, Hex-Rays and rev.ng all recognise the shape | **no -- measured negative** |

The direction of (a)'s `Sub`/`Add` rule is the **opposite** of VexIR2Vec's,
which converts `add(-1,t)` to `sub(+1,t)`. This representation buckets constants
by magnitude rather than keeping their values, so `Add x, -C` is the form that
leaves the *operator* -- the part that survives into the label -- the same for
both spellings.

`a < b` versus `b > a` needs no rule at all: the IR has no greater-than
operator, so the lifter has already made that choice once, for every
architecture.

Each module's doc comment states its own rule, precedent, unsoundness and bound.

### Measured

Corpus, filters and protocol are exactly the ones the unnormalised numbers above
were measured under, in the same process, in the same run. Release build,
2026-09-02. Harness: `tests/identity_cfr_retrieval.rs`.

| Lane | Free variables | Unnormalised | Normalised | Delta | Pool |
|---|---|---|---|---|---|
| XO gcc `-O0` -> gcc `-O2`, size-matched | optimisation | 51/341 = **14.96%** | 60/341 = **17.60%** | +2.64 pt, +17.6% rel | 1 + 100 |
| XC gcc `-O2` -> clang `-O2`, size-matched | compiler | 148/309 = **47.90%** | 155/309 = **50.16%** | +2.26 pt | 1 + 100 |
| XO gcc `-O0` -> gcc `-O2`, whole slice | optimisation | 44/594 = **7.41%** | 51/594 = **8.59%** | +1.18 pt, +15.9% rel | 610 candidates |

The whole-slice row is the one comparable with `tests/similarity_retrieval.rs`'s
**0.32%** for CTPH on the same corpus and the same task: the normalised CFR is
twenty-seven times the byte digest where the plain one was twenty-three.

The same representation under the *other* protocol -- Marcelli's task taxonomy,
AUC and MRR10, a seeded negative draw instead of nearest-size, no duplicate
filter. Harness: `tests/identity_retrieval/`, scheme `cfr` and
`cfr-normalized`. The two Recall@1 columns are not comparable with the table
above and the filter set is why.

| Task | Scored | AUC | AUC' | MRR10 | MRR10' | R@1 | R@1' |
|---|---|---|---|---|---|---|---|
| XO-gcc (gcc O0 -> gcc O2) | 389 | 0.7569 | **0.7583** | 0.2543 | **0.2657** | 0.1799 | **0.2031** |
| XO-clang (clang O0 -> clang O2) | 366 | 0.7135 | **0.7175** | 0.1808 | **0.2007** | 0.1120 | **0.1366** |
| XC-O0 (gcc O0 -> clang O0) | 487 | 0.9663 | 0.9663 | 0.9162 | 0.9104 | 0.8706 | 0.8624 |
| XC-O2 (gcc O2 -> clang O2) | 357 | 0.8921 | 0.8856 | 0.5688 | **0.5790** | 0.5014 | **0.5182** |
| XM (gcc O0 -> clang O2) | 365 | 0.7296 | **0.7329** | 0.1990 | **0.2120** | 0.1342 | **0.1425** |
| XM-S (< 20 blocks) | 308 | 0.7030 | **0.7077** | 0.1637 | **0.1801** | 0.1039 | **0.1104** |
| XM-M (20-100 blocks) | 54 | 0.8708 | **0.8727** | 0.3125 | **0.3586** | 0.2037 | **0.2593** |
| XM-L (> 100 blocks) | 3 | \-- | \-- | \-- | \-- | \-- | \-- |

Sampled pool 101 on every row; the global pool is 377 to 494 depending on the
slice. XM-L has three scored queries and is below
`MIN_SCORED_FOR_A_MEASUREMENT`, so its numbers are printed by the harness and
are not quoted here.

**Two rows go the other way and are kept.** `XC-O0` loses 0.8 points of
Recall@1 and `XC-O2` loses 0.0065 of AUC while gaining 1.7 points of Recall@1.
The cross-compiler lanes are where the projection already erases most of the
difference, so a rewriter that merges spellings has less to gain and the same
amount to lose. Quoting only the metric that improved would be choosing the
evidence.

**Cost.** Extraction goes from 2,032 to 2,802 microseconds per function over the
1,787-sample in-house corpus, a 38% increase, all of it the four rounds of
rewriting over every block of every function.

### Cisco Dataset-1: no measurable effect

The same two schemes over Marcelli's Dataset-1 testing split (`ncat`, `nmap`,
`nping`; `tests/identity_retrieval/main.rs::cisco_cfr_xo_xc_xm`, which is
`#[ignore]`d because the CFR's extraction is a whole-image lift and the run
takes five minutes). Slices are x86-64 only for these three tasks; extraction
failures were zero on all of them.

| Task | Scored | Global pool | AUC | AUC' | MRR10 | MRR10' | R@1 | R@1' |
|---|---|---|---|---|---|---|---|---|
| XO (x64 gcc-9 O0 -> O2) | 50 | 229 | 0.9127 | 0.9176 | 0.7570 | 0.7713 | 0.6800 | 0.6800 |
| XC (x64 gcc-9 O0 -> clang-9 O0) | 65 | 348 | 0.9638 | 0.9605 | 0.9667 | 0.9654 | 0.9385 | 0.9385 |
| XM (x64 gcc-9 O0 -> clang-9 O2) | 36 | 262 | 0.8806 | 0.8754 | 0.7301 | 0.7035 | 0.6667 | 0.6389 |

**Read the denominators before reading the numbers.** These are three to ten
times the in-house Recall@1 for the same representation, and none of that is the
representation getting better: Dataset-1's ground truth samples roughly a tenth
of each binary's functions independently per binary, so a pool of 101 candidates
drawn from it holds far fewer near-twins than a pool drawn from 206 small
fixtures that share their CRT. The two corpora answer different questions and
their numbers do not belong in one column.

**The normaliser does nothing here that can be told from noise.** Recall@1 is
identical on XO and XC and one function lower on XM; AUC moves by +0.005,
-0.003 and -0.005. With 36 to 65 scored queries a row moves by 1.5 to 2.8
percentage points when a single function changes rank, so none of these
differences is a measurement. What the lane establishes is that the normaliser
*runs* on real binaries -- zero extraction failures over 2,441 samples -- at
21,533 microseconds per function plain and 31,627 normalised, a 47% increase.

The three tasks are XO, XC and XM. `XB` and the `XA-*` lanes are deliberately
not run: they cost the same again, and a local peephole rewriter has nothing to
say about a change of instruction set that the mask list does not already say.

### Every function has something to normalise

**710/710 = 100.00%** of the gcc `-O0` slice has its feature multiset changed by
the normaliser (`the_normaliser_moves_a_measured_fraction_of_the_corpus`,
comparing feature multisets rather than digests, because the digest carries the
settings word and would differ regardless).

The research synthesis predicted the opposite, from Cranelift's measured **1.13
e-nodes per e-class** after rewriting, and used it to argue against building an
e-graph canonicaliser: "limited algebraic variation to recover". That prediction
does not transfer, and the reason is that the two numbers are not measuring the
same thing. Cranelift's is about *algebraic* variation in an IR a compiler front
end produced. Most of what fires here is lifter and calling-convention
boilerplate: the `lea` expansion's constant seed, the stack round-trip every
`-O0` local performs, the width-suffixed intrinsic name. So a changed-form
fraction of 100% is not the same claim as a large retrieval gain -- the
retrieval tables above are the ones that say what the change is worth, and they
say two to three points.

### Per-pass ablation

XO, gcc `-O0` -> gcc `-O2`, 1 + 100 size-matched candidates, the lane the
normaliser exists for. Each pass alone, then each pass removed from the full
set. Fourteen configurations means fourteen loads of two 206-binary slices, so
the lane is `#[ignore]`d:

```
cargo test --release --features python-ext --test identity_cfr_retrieval \
  -- --ignored --nocapture ablation
```

| One pass alone | Recall@1 | The full set less one | Recall@1 |
|---|---|---|---|
| unnormalised (`none`) | 51/341 = 0.1496 | all six (`all`) | 57/341 = 0.1672 |
| only (a) opcodes | 54/341 = 0.1584 | all but (a) | 52/342 = 0.1520 |
| only (b) constants | 51/341 = 0.1496 | all but (b) | 58/341 = 0.1701 |
| only (c) cse | 51/341 = 0.1496 | all but (c) | 58/341 = 0.1701 |
| only (d) redundancy | 55/342 = 0.1608 | all but (d) | 55/341 = 0.1613 |
| only (e) polarity | 51/341 = 0.1496 | all but (e) | 57/341 = 0.1672 |
| only (f) strength | 48/341 = 0.1408 | all but (f) | **60/341 = 0.1760** |

Denominators move by one between rows because dropping duplicates depends on the
canonical form: a configuration that merges two functions' forms removes both
from the scored set.

Three things to read off it.

**(a) and (d) carry the lane.** Opcode collapse and the memory/register
redundancy rules are the only two passes that move the number on their own, and
they are the two that address what actually differs between `-O0` and `-O2`
code: the spelling of an operator, and whether a local lives in a register or in
the frame.

**(b), (c) and (e) are worth nothing alone and something together.** Each reads
exactly the unnormalised 0.1496 by itself; removing any one of them from the
full set changes the result. They are enablers -- copy propagation is what
exposes the operand identities CSE and the redundancy rules match on, and it has
nothing to propagate until (a) has collapsed the operators.

**(f) costs, in both directions, so it does not ship.** `Passes::DEFAULT` is (a)
through (e), under a rule stated before the measurement: *a pass whose solo
ablation row is below the unnormalised baseline does not ship in the default
set*. Only `strength` fails it. The cost is entirely rule 1, the power-of-two
collapse -- with only the magic-division rule enabled `only strength` returns to
exactly 51/341, which also says that recogniser never fires on this corpus. The
**opposite** direction was measured too (`Shl x, k` -> `Mul x, 2^k`, the other
way to make the two spellings one) and is also a loss: 49/340 = 0.1441 alone and
59/340 = 0.1735 in the full pipeline. Two spellings of a scaled index carry
discrimination this corpus wants kept, in both directions, so the pass stays
implemented, tested and ablated but out of the default set rather than being
tuned until it stops hurting.

Every number above is unweighted. TF-IDF (plan item 5) is expected to change all
of them, including possibly the sign of the `strength` row, which is why the
pass is kept rather than deleted.

### What is deliberately not here

- **No cross-block rewriting.** A peephole is a block. Global value numbering
  over the whole function is `ir::value_number`'s job and would be a different
  artifact with a different failure mode.
- **No remainder rule.** `intr:x86.{s,u}div_rem` has no single IR node to
  collapse onto, and inventing `a - (a / b) * b` for it would manufacture three
  features where the program has one operation. So an `-O0` `%` stays an
  intrinsic while its `-O2` twin is a magic multiply, and they do not match.
- **No unsigned add-back division idiom.** The signed add-back form is
  recognised; the unsigned one (`(h - x) >> 1 + x`, then a shift) is not.
- **No alias analysis.** `may_alias` proves exactly one thing apart: two
  accesses through the same base and index at disjoint displacements. Everything
  else may alias, which costs recall rather than correctness.
- **No architecture but x86.** The rules that name an intrinsic name
  (`x86.smul_hi`, `x86.sdiv_quot`) are x86-only; every other rule is
  architecture-neutral, and none of them has been measured on ARM.

## The two levers together

The normaliser (above) and the TF-IDF weighting
([Weighting](#weighting-the-corpus-tf-idf-table)) landed on separate branches
and are independent by construction: `normalize` rewrites the lifted function
before the graph is built, so it changes the **representation**; a weight table
changes the **metric** over whichever representation it was counted on. Nothing
about either mechanism says how they compose. Normalisation folds local variation
into fewer, commoner features, which is exactly the material a rarity weighting
trades on, so the interaction could plausibly have been sub-additive.

It is not. Measured, not argued.

### The 2x2

`tests/identity_retrieval/main.rs::the_two_cfr_levers_compose`, in-house fixture
corpus, **held-out half** throughout, release build,
`cargo test --release --features python-ext --test identity_retrieval -- --nocapture cfr`.

All four cells are scored on the held-out half -- including the two unweighted
ones, which would not otherwise need a split -- because a four-cell table whose
cells sat on different populations could not be read for the interaction at all.
The `scored` column is identical across the four cells by assertion. Each
weighted cell uses a table counted over the training half **under its own
settings**: `cfr-1.0-s0-idf512-48359a7a35563d79` (910 documents, 39,969 weighted
features) for the unnormalised rows and `cfr-1.0-s2-idf512-03df27b6e0d4283f`
(910 documents, 39,031 features) for the normalised ones. Applying the plain
table across the lever would weight a vocabulary the normalised representation
does not produce.

**AUC**

| Task | Scored | Pool (sampled / global) | plain | normalised | weighted | normalised + weighted |
|---|---|---|---|---|---|---|
| XO-gcc | 187 | 101 / 200 | 0.7800 | 0.7769 | 0.8592 | **0.8717** |
| XO-clang | 178 | 101 / 184 | 0.7419 | 0.7442 | 0.8152 | **0.8342** |
| XC-O0 | 241 | 101 / 243 | 0.9679 | 0.9675 | 0.9938 | **0.9942** |
| XC-O2 | 172 | 101 / 184 | 0.8935 | 0.8848 | 0.9461 | **0.9487** |
| XM | 177 | 101 / 184 | 0.7625 | 0.7679 | 0.8131 | **0.8390** |

**MRR10 and Recall@1**, same four cells:

| Task | MRR10 plain | MRR10 norm | MRR10 wtd | MRR10 norm+wtd | R@1 plain | R@1 norm | R@1 wtd | R@1 norm+wtd |
|---|---|---|---|---|---|---|---|---|
| XO-gcc | 0.2549 | 0.2777 | **0.5080** | 0.4928 | 0.1872 | 0.2086 | **0.4064** | 0.3904 |
| XO-clang | 0.1829 | 0.1963 | 0.3729 | **0.3919** | 0.1124 | 0.1292 | 0.2809 | **0.2921** |
| XC-O0 | 0.9501 | 0.9445 | 0.9557 | **0.9581** | 0.9253 | 0.9129 | 0.9253 | **0.9336** |
| XC-O2 | 0.5681 | 0.5823 | 0.6549 | **0.6723** | 0.5116 | 0.5233 | 0.5698 | **0.5930** |
| XM | 0.1984 | 0.2035 | 0.4232 | **0.4405** | 0.1243 | 0.1186 | 0.3333 | **0.3503** |

### Reading it

**The weighting is the larger lever, by a wide margin.** On XO-gcc it is worth
+0.079 AUC and +0.253 MRR10 on its own; the normaliser on the same cell is worth
-0.003 AUC and +0.023 MRR10. Anyone choosing one lever should choose the
weighting.

**They compose on AUC, on all five tasks, and super-additively.** XO-gcc: the
weighting alone is +0.0792, the normaliser alone is -0.0031, and together they
are +0.0917 -- more than the sum of the parts by 0.0156. XM is the same shape
(+0.0506, +0.0054, together +0.0765). The mechanism is the one each section
already gives separately: the normaliser folds lifter boilerplate into fewer,
commoner features, and an IDF table is precisely the thing that stops common
features from costing anything. Each lever removes some of the noise the other
one has to survive, so the normaliser is worth more in the presence of the
weighting than alone.

**One cell does not compose, and it is the headline cell.** On XO-gcc the
combined row's *ranking* metrics are slightly worse than the weighting alone --
MRR10 0.5080 -> 0.4928, Recall@1 0.4064 -> 0.3904, which is three fewer
functions retrieved at rank 1 out of 187 -- while its AUC is better. That is the
same divergence the normaliser lane already recorded on XC-O2 unweighted, in the
other direction, and it reads the same way: AUC is whole-distribution separation
and Recall@1 is the top of the ranking, and a rewrite that pulls the bulk of the
negatives further away can still reshuffle the first few candidates. Four of the
five tasks improve on every metric. This one does not, on a difference of three
functions, and a summary that quoted only AUC would be choosing its evidence.

**The extraction cost is the normaliser's, unchanged by the weighting.** 1,514
us/function unnormalised against 2,113 normalised, release, over 1,787 samples
-- the +39% the [Normalisation](#normalisation) section already reports. A
weight table costs nothing at extraction time and a bounded merge-join at query
time; it is the cheaper lever as well as the larger one.

### What is deliberately not here

- **No Dataset-1 row for the combination.** Both levers have Dataset-1 rows of
  their own, from lanes that cost minutes each and are `#[ignore]`d
  (`cisco_cfr_retrieval_ratchets` for the weighting,
  `cisco_cfr_xo_xc_xm` for the normaliser). The 2x2 there is four more of those
  runs and has not been made.
- **No claim that the interaction generalises.** Five tasks on one 1,787-sample
  in-house corpus, whose compiler and optimisation axes are the only ones free.
  The super-additivity is consistent across all five, which is more than one
  observation, and it is still one corpus.

## Known gaps

- **Inlining.** The field's unsolved failure: roughly 82 to 84 percent of the
  best tools' failures involve differential inlining, and Marcelli's benchmark
  disables inlining to sidestep it. Nothing here addresses it, and the
  cross-optimisation number above is what that costs.
- **Both levers are off by default, and neither closes the gap.**
  [Normalisation](#normalisation) is worth two to three points on every lane and
  the [weighting](#weighting-confidence-and-the-index) is worth considerably
  more, but 8.59% quotient-match on a whole slice is still not a tool you would
  point at a stripped binary unassisted. What the normaliser reaches is also
  local: `~(a | b)` against `~a & ~b` is a De Morgan rewrite no pass here
  performs, and the research synthesis's advice on that stands -- revisit an
  e-graph only if measurement says algebraic variation is material, and this
  lane's measurement says the material variation is lifter boilerplate rather
  than algebra.
- **The confidence's constants are borrowed, not fitted.** The five numbers in
  BSim's causal model were fitted by the NSA to their p-code features over their
  corpus. The formula is theirs verbatim and the features are ours, so the score
  is on their scale by construction and on their published calibration only by
  assumption. Refitting needs a labelled corpus of the size BSim was fitted on.
- **CFR-I is not built.** The typed interface record -- return type, parameters
  by ABI position, locals by frame offset, callee set, effect summary -- is
  specified in the research and not implemented here.
- **`nosize` is still unmeasured.** Cross-architecture coverage is not: the
  Dataset-1 lane above scores x86, x86-64, ARM32 and AArch64, and refuses MIPS.
  But the setting that exists specifically for 32-to-64-bit matching has never
  been run against the XB lane it was built for -- every number on this page is
  `nosize = false`.
- **Memory dependence is block-granular.** One chain per block, merged at block
  entries, with no aliasing analysis: two stores to provably distinct objects
  are still ordered. That is conservative rather than wrong, and it makes a
  reordered pair of independent stores two different graphs.
- **Multi-output intrinsics do not distinguish their outputs.** Each output of
  an `Op::Intrinsic` gets a node with the same label, separated only by width.
- **Internal callee arity is weak evidence.** `abi::annotate_calls` reports the
  convention's conservative may-use set unless a callee contract is known, so
  the arity class is usually the ABI's register count rather than the callee's.
- **PE and Mach-O external names are resolved but unmeasured.** ELF PLT
  resolution is exercised by the corpus; the PE import-thunk and Mach-O stub
  paths are wired and untested.
- **A trampoline block still changes CFR-C.** `Op::Jump` gets no CFR-G node
  because it is layout, but the block that contains it keeps its degree seed and
  its two edges. A compiler that routes a branch through an extra empty block
  therefore produces a different control-flow feature set for the same program.
  Collapsing such blocks is a normalisation this does not do.
- **A truncated discovery is not reported through the signature.** The block and
  instruction ceilings in `Budgets` still apply, and a function above them gets a
  partial graph. `analysis::cfg::FunctionDiscoveryStats` knows this happened;
  `FunctionCfr` does not carry it, so a caller cannot tell a small function from
  a large one that was cut off. The wall-clock ceiling was removed for exactly
  this reason and these two remain.

## Using it

```python
import glaurung as g

left = g.analysis.cfr_signatures_path("libfoo-gcc-O0.so")
right = g.analysis.cfr_signatures_path("libfoo-gcc-O2.so")
score = g.analysis.cfr_similarity(left[0], right[0])   # cosine, [0, 1]
gap = g.analysis.cfr_distance(left[0], right[0])       # the metric distance

# ...and the same three under a corpus TF-IDF table, which is what the
# measured numbers below were produced with.
weights = g.analysis.cfr_build_weights(left + right)
score = g.analysis.cfr_similarity(left[0], right[0], weights)
verdict = g.analysis.cfr_confidence(left[0], right[0], weights)
verdict["significance"]             # BSim's "Confidence"; >= 26 is ~1 in 1e5
verdict["false_positive_one_in"]    # None below BSim's lowest published anchor

# 32-to-64-bit matching. A different setting is a different quotient: a
# nosize signature compared with a plain one answers 0.0, not a low score.
collapsed = g.analysis.cfr_signatures_path("libfoo.so", nosize=True)

# The unsound local peephole normaliser. Two to three points on every lane,
# 38% more extraction time, and the same "different quotient" rule: a
# normalised signature answers 0.0 against an unnormalised one.
canonical = g.analysis.cfr_signatures_path("libfoo.so", normalize=True)
```

Into a `.glaurung` project:

```python
from glaurung.llm.kb.function_identity import CFR_V1, index_cfr_identities

stored = index_cfr_identities(kb, "libfoo.so")
```

`function_identity`'s key is `(binary_id, entry_va, scheme)`, so this is new
rows beside `glaurung-structural-v1`, not a migration. Pick one settings value
per project -- `nosize` and `normalize` both -- because the scheme name is the
same whichever way they are set, so a table that mixes two settings holds rows
that silently disagree.

## Where the code is

| File | What |
|---|---|
| `src/identity/cfr/labels.rs` | the label tuple and its encoding; width classes, value classes, constant buckets, callee classes |
| `src/identity/cfr/commutativity.rs` | the operator table |
| `src/identity/cfr/operands.rs` | one positional operand model, with the test that pins its order to `for_each_use`'s |
| `src/identity/cfr/widths.rs` | width inference and the census |
| `src/identity/cfr/stack.rs` | frame-derived value marking |
| `src/identity/cfr/dominators.rs` | local Cooper-Harvey-Kennedy |
| `src/identity/cfr/graph.rs` | CFR-G construction |
| `src/identity/cfr/prune.rs` | shadow elimination and dead-code removal |
| `src/identity/cfr/wl.rs` | Weisfeiler-Lehman relabelling |
| `src/identity/cfr/blocks.rs` | CFR-C |
| `src/identity/cfr/signature.rs` | the versioned artifact |
| `src/identity/cfr/similarity.rs` | the kernel, the cosine, the distance, the `Weights` trait, and BSim's significance |
| `src/identity/cfr/weights.rs` | the corpus IDF table, its quantisation and its `weights_id` |
| `src/identity/cfr/extract.rs` | path to signatures |
| `src/identity/cfr/tests.rs` | the invariance specification |
| `src/identity/cfr/normalize/mod.rs` | the normaliser's driver, pass bit field and round cap |
| `src/identity/cfr/normalize/common.rs` | the peephole model: mutable use walk, purity, the alias rule |
| `src/identity/cfr/normalize/opcodes.rs` | (a) same-semantics opcode collapse |
| `src/identity/cfr/normalize/constants.rs` | (b) constant folding and copy propagation |
| `src/identity/cfr/normalize/cse.rs` | (c) local common-subexpression elimination |
| `src/identity/cfr/normalize/redundancy.rs` | (d) dead-store and redundant-write elimination |
| `src/identity/cfr/normalize/polarity.rs` | (e) comparison-polarity canonicalisation |
| `src/identity/cfr/normalize/strength.rs` | (f) strength-reduction canonical forms -- measured negative, not in the default set |
| `src/identity/cfr/normalize/tests.rs` | one test per rule, the round cap, determinism, and the off-flag byte identity |
| `tests/identity_cfr_retrieval.rs` | the measurement: Recall@1, the normalised lanes, the ablation |
| `tests/identity_retrieval/scheme.rs` | `CfrScheme`, plain and normalised, for the AUC/MRR10 protocol |
| `src/python_bindings/identity.rs` | the Python surface |
| `python/tests/test_cfr_identity.py` | the boundary and the KB writer |
| `python/glaurung/llm/kb/cfr_index.py` | the stored vectors, the weight table and the inverted index |
| `python/tests/test_cfr_index.py` | the weighting, the confidence and the index, through Python |
| `tests/identity_retrieval/scheme.rs` | `CfrScheme`, the shared-protocol lane |
