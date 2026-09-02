# The Canonical Function Representation (CFR)

> **Status: implemented, measured, and not yet weighted.** Everything below is
> in `src/identity/cfr/`. Every number carries the run it came from and the
> denominator it was measured over. The TF-IDF corpus table, the rare-feature
> inverted index and the peephole normaliser are separate, later lanes; the
> numbers here are what the representation does without any of them.

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
[`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md).

## Where it sits in the pipeline

```
lift_function_from_image      machine code -> LLIR
abi::annotate_calls           call effects, so a call has defs and uses
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
in [`04-program-representations-and-schemas.md`](../research/program-measures-2026-09-02/04-program-representations-and-schemas.md) section 9(b); the
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

**Weights.** The `Weights` trait is defined now so call sites do not move when
the TF-IDF corpus table lands. `UniformWeights` (`idf = 1`) is what every number
below was measured under.

## Measured numbers

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
binary unassisted. That gap is what the TF-IDF weighting, the rare-feature
inverted index and the peephole normaliser are for.

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

## Known gaps

- **Inlining.** The field's unsolved failure: roughly 82 to 84 percent of the
  best tools' failures involve differential inlining, and Marcelli's benchmark
  disables inlining to sidestep it. Nothing here addresses it, and the
  cross-optimisation number above is what that costs.
- **No peephole normaliser.** `x * 2` and `x << 1`, `~(a | b)` and `~a & ~b`,
  and the rest of the local algebraic variation are different features today.
  Plan item 8 is an unsound local normaliser (VexINE's template) run before
  hashing; its delta is measurable against the numbers above.
- **No TF-IDF weighting.** Every feature counts the same, so a `mov` between two
  registers weighs as much as a call to `pthread_mutex_lock`. This is the single
  largest expected improvement and it is plan item 5.
- **CFR-I is not built.** The typed interface record -- return type, parameters
  by ABI position, locals by frame offset, callee set, effect summary -- is
  specified in the research and not implemented here.
- **ARM and cross-architecture coverage is unmeasured.** Every number above is
  x86-64. `stack_registers_for` covers AArch64 and both ARM32 conventions, and
  the lifters exist, but the fixture matrix lane was not run. The `nosize`
  setting exists for the 32-to-64-bit case and its benefit is likewise
  unmeasured.
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

## Using it

```python
import glaurung as g

left = g.analysis.cfr_signatures_path("libfoo-gcc-O0.so")
right = g.analysis.cfr_signatures_path("libfoo-gcc-O2.so")
score = g.analysis.cfr_similarity(left[0], right[0])   # weighted cosine, [0, 1]
gap = g.analysis.cfr_distance(left[0], right[0])       # the metric distance

# 32-to-64-bit matching. A different setting is a different quotient: a
# nosize signature compared with a plain one answers 0.0, not a low score.
collapsed = g.analysis.cfr_signatures_path("libfoo.so", nosize=True)
```

Into a `.glaurung` project:

```python
from glaurung.llm.kb.function_identity import CFR_V1, index_cfr_identities

stored = index_cfr_identities(kb, "libfoo.so")
```

`function_identity`'s key is `(binary_id, entry_va, scheme)`, so this is new
rows beside `glaurung-structural-v1`, not a migration. Pick one `nosize` setting
per project: the scheme name is the same either way, so a table that mixes the
two holds rows that silently disagree.

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
| `src/identity/cfr/similarity.rs` | the kernel, the cosine, the distance, the `Weights` trait |
| `src/identity/cfr/extract.rs` | path to signatures |
| `src/identity/cfr/tests.rs` | the invariance specification |
| `tests/identity_cfr_retrieval.rs` | the measurement |
| `src/python_bindings/identity.rs` | the Python surface |
| `python/tests/test_cfr_identity.py` | the boundary and the KB writer |
