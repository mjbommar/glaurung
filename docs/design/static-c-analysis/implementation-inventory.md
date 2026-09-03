# Implementing the DecBench metrics natively: component inventory

> **Kind:** plan · **Status:** proposed

Every piece of mathematics and every data structure needed to compute DecBench's
three metrics — `ged`, `type_match`, `byte_match` — inside Glaurung, plus the
lowering and equivalence-checking components the later stages add, with the
build order, the acceptance test for each piece, and the three places where an
obvious "improvement" would break parity.

This is the component-level companion to the rest of the set:
[`roadmap.md`](roadmap.md) is the programme, [`architecture.md`](architecture.md)
says where the code lives, [`joern-behavior.md`](joern-behavior.md) says what the
reference implementation does, [`requirements.md`](requirements.md) states the
contract, and [`parity-plan.md`](parity-plan.md) gives the gates for the parity
stage. This document says what to actually write, in what order.

Scope note: `parity-plan.md` covers only the `ged` front end, because that is
the piece with a large offline oracle. This inventory covers all three metrics
plus §7.5's later components, so that a decision to stop at GED is a deliberate
one rather than an accident of what was written down.

## 1. How to read the tables

* **ID** — stable handle. `K` shared kernel, `F` C front end, `G` GED distance,
  `T` type_match, `B` byte_match, `S` scoring, `L` the lowering and equivalence
  components of [`roadmap.md`](roadmap.md) stages S4 and S5 (§7.5).
* **Size** — order-of-magnitude estimate of new Rust, not a measurement:
  `XS` < 100 lines, `S` 100–300, `M` 300–800, `L` 800–2,000, `XL` > 2,000.
* **Test** — the acceptance check that says the component is done. A component
  with no cheap acceptance check is a component that will be wrong.
* Reference-implementation citations are paths inside the DecBench checkout
  (`$DECBENCH_DIR`) or its virtualenv, quoted as inline code because they are
  outside this repository.

## 2. Shared kernel

Needed by all three metrics. Write these first: they are small, pure, and every
later component's test depends on them behaving deterministically.

| ID | Component | Mathematics / algorithm | Data structure | Size | Test |
|---|---|---|---|---|---|
| K-1 | Content-addressed cache key | SHA-256 over canonical JSON — sorted keys, separators `(",", ":")`, `ensure_ascii=False`, per-part domain tags `\x00j` (JSON) and `\x00b` (bytes). `decbench/caching.py:84` | streaming hasher; a canonical-JSON encoder with sorted keys, tight separators, `set` → sorted, `bytes` → hex, `Path` → string | S | byte-identical digest to `decbench.caching.stable_hash` on a fixture of nested maps, sets, floats and bytes |
| K-2 | Measurement tri-state | non-finite means *unmeasurable for everyone*, and is checked **before** the cache so stale values under old semantics are never served | `Measured(f64) \| Abstain(reason) \| Failed(reason)` — never `Option<f64>`, because `0.0` and "not measurable" must not collapse | XS | a metric returning `Abstain` leaves the denominator; one returning `Measured(0.0)` does not |
| K-3 | Aggregation primitives | total, mean, median (sorted, even length averaged), `perfect_count` by exact `==` against the metric's `perfect_value` (`0.0` for GED, `1.0` for the other two) | `Vec<f64>` per metric per binary | XS | reproduce `MetricResult.compute_aggregates` on a stored `evaluated/*.toml` |
| K-4 | Ordered-output discipline | not an algorithm — a rule. Any map whose iteration reaches output is ordered | `BTreeMap` / `IndexMap` throughout; `HashMap` only for lookup-and-discard | XS | run twice, diff bytes (REQ-OUT-3) |

## 3. The C front end (F) — the bulk of the work

This is the component that replaces Joern. Everything in this group is new code;
nothing in the crate parses C today.

F-4 through F-8 are **C-specific code sitting on the language-neutral substrate**
enumerated as `SB-1..SB-9` in
[`../source-front-ends/substrate.md`](../source-front-ends/substrate.md): the
token buffer, arena, interner, diagnostics, event stream, recovery primitives
and the control-flow-event CFG builder are shared, and only the token kinds,
node tags, grammar and `Flow`-event emission are C's. The sizes below are for
the C half; the substrate adds roughly `S`/`M` per component and is charged once
across every language.

| ID | Component | Mathematics / algorithm | Data structure | Size | Test |
|---|---|---|---|---|---|
| F-1 | System-header filter | two-state machine over gcc's `# <line> "<file>"` markers, **starting in the system state** so text before the first marker is dropped. Predicate: non-empty, not `<`-prefixed, not `/usr/`-prefixed, no `/usr/lib/gcc`, not `stdc-predef.h` | streaming line scan, no allocation per line | XS | byte-equal to `strip_system_headers` on a real `.i` |
| F-2 | Literal-aware control-byte escaping | four-state scanner: outside / in-string / in-char / pending-backslash. Escapes `< 0x20` and `0x7F` except tab and newline | same | XS | byte-equal to `escape_literal_control_bytes`, including the `"\\"` case that must not open a literal |
| F-3 | Decompiler-quirk sanitizer | four ordered rewrites: line-anchored aggregate return, register annotation strip, `__int128` widening, then F-2. Must be impossible to apply to a `.i` input | compiled regexes | XS | byte-equal to `sanitize_decompiled_c` on one artifact from each decompiler column |
| F-4 | Lexer | maximal munch; GNU tokens (`__attribute__`, `__extension__`, `asm`/`__asm__`, `__typeof__`, `__restrict`, `&&label`); comments and line splices | `Vec<Token>` of `(kind, span)`; string interner for identifiers | M | round-trip token count on the 1,606 stored decompiled `.c` files without panicking |
| F-5 | Expression parser | Pratt / precedence climbing over the C precedence ladder; right associativity for assignment and `?:`; postfix chains for call, index, member, increment | arena AST — `Vec<Node>` indexed by `NodeId(u32)`, never `Box`, because the tree is walked repeatedly | M | parse-and-print equivalence on a hand-written precedence torture fixture |
| F-6 | Statement parser | recursive descent with **panic-mode recovery**: on an unparseable construct, skip to the next `;` or matching `}` and emit an opaque straight-line item (REQ-IN-4, REQ-CFG-11) | explicit depth counter to bound recursion (REQ-ROB-3) | L | no input in the stored corpus yields zero functions where Joern yielded some |
| F-7 | Declaration handling | the usual declaration-versus-expression ambiguity normally forces a typedef table. **Here it is mostly moot**: both readings of `A * b;` are one straight-line item contributing the same degree. Parse declarations well enough to skip them and to find initializers | optional `Vec<HashSet<Symbol>>` typedef scope stack | S | a fixture where `A * b;` is a declaration in one TU and an expression in another produces the same CFG either way |
| F-8 | CFG construction | syntax-directed translation in evaluation order with a **control context stack** (break target, continue target, the current switch's case list) and **backpatching** for `goto`: a `label → NodeId` map plus a deferred-fixup list resolved in a second pass, exactly as an assembler resolves forward references | `Vec<CfgNode>`; edges accumulated as `Vec<(NodeId, NodeId)>` then compiled to CSR (`offsets: Vec<u32>`, `targets: Vec<NodeId>`) for O(1) degree queries | L | REQ-CFG-4/5/7 fixtures: `if`/`else`, `switch` with and without `default`, fall-through, `while`, `for`, `do`, `break`, `continue`, `goto` |
| F-9 | Short-circuit lowering | the classic inherited-attribute scheme (`B.true` / `B.false` targets) for `&&`, `\|\|` and `?:` — **plus Joern's twist that the operator node is materialized**, so `a && b` costs three nodes and four edges and the operator node has in-degree 2, out-degree 2 | the same control context stack | M | the `xmalloc` shape in [`joern-behavior.md`](joern-behavior.md) §4 reproduces exactly |
| F-10 | Basic-block coalescing | contract `src → dst` when `outdeg(src) == 1 ∧ indeg(dst) == 1`, to fixpoint, excluding self-edges. The reference loop is O(V·E); the correct implementation is one pass over **maximal chains** — compute degrees, find chain heads (nodes that cannot be a `dst`), walk each chain. O(V+E), and the partition is unique regardless of visit order | in/out degree arrays plus a chain-head bitset; disjoint-set union with path compression if you prefer | S | identical partition to `to_supergraph` on 1,000 random small digraphs |
| F-11 | Entry/exit flag derivation | entry ⟺ the block holds `Nop(FUNC_START)`, exit ⟺ it holds `Nop(FUNC_END)`; position-sensitive before merging (first / last statement), membership after; merging ORs them | two bits per block | XS | the published corpus's invariants: zero functions with no entry flag, none with more than one exit flag |
| F-12 | Singleton-funcend removal | guarded deletion — **exactly one** block with `outdeg == 0`, exactly one statement, and that statement `Nop(FUNC_END)`. Deleting it drops its in-edges with it | — | XS | both regimes tested explicitly; this rule alone decides 49.0% of exit flags (§3 of [`joern-behavior.md`](joern-behavior.md)) |
| F-13 | Degeneracy predicate | `n == 0`, or `n == 1` with every statement a `Nop` | — | XS | a one-block function with real statements is **not** degenerate |
| F-14 | Stable relabeling | nodes to `0..n-1` in a deterministic order — first source line, then occurrence index | sort key `(u32, u32)` | XS | rerun determinism (K-4) |
| F-15 | Name filtering and dedup | prefix blacklist `<`, `+`, `*`, `(`, `>`, `JUMPOUT`, `__builtin_unreachable`; for a repeated `(name, file)` keep the CFG with more nodes | prefix set; `BTreeMap` with max-by-node-count merge | XS | reproduce `Function.from_many` on a file defining the same name twice |
| F-16 | Per-TU resolution | lexicographic max on the rank `(is_non_degenerate, node_count)`; the binary's own TU wins, cross-TU best-by-name is the fallback | `BTreeMap<TuStem, BTreeMap<FnName, Cfg>>` | S | reproduce `resolved_source_for_binary` on a project with a colliding `main` |
| F-17 | DecBench serialization | the `nodes` / `edges` / `labels` / `entry` / `exit` / `degenerate` shape (REQ-OUT-1) | serde | XS | a written file is accepted by DecBench's `--source-cfgs` flow unmodified |

## 4. The GED distance (G)

Small, self-contained, and fully specified. Write it early — it turns the front
end's output into a number you can compare against 85,645 stored values.

| ID | Component | Mathematics / algorithm | Data structure | Size | Test |
|---|---|---|---|---|---|
| G-1 | Cost matrix | block form `[[C, D], [I, 0]]`, size `(n+m)²`. Substitution `C[i][j] = \|in_i − in_j\| + \|out_i − out_j\|` — the reference's `c_i + c_j − 2·common` over lists of identical tokens reduces to exactly this — plus `100000` on the **first** entry/exit mismatch. It is an `if/elif` chain, so the penalty is never applied twice even when both flags disagree. `D` and `I` are diagonal with `1 + in + out` and off-diagonal infeasible | dense `Vec<i64>`; mean n is 12, so allocation is irrelevant in the common case | S | cell-by-cell equality with `CFGSimED.__ED`'s matrix on published CFG pairs |
| G-2 | Assignment solver | rectangular LSAP — the Riesen–Bunke bipartite formulation of graph edit distance — solved by Hungarian / Munkres in O(k³), k = n+m | the standard O(n³) column-reduction variant with potentials `u[]`, `v[]`, augmenting path `way[]`, and `match[]` | S | brute-force permutation check for n ≤ 8; then exact agreement with `vj_ged` over published CFG pairs |
| G-3 | Degree-class compression | an optimization the reference does not have. Cost depends only on `(in, out, entry, exit)`, so nodes of the same class are interchangeable and the LSAP collapses to a **transportation problem** over class multiplicities — min-cost flow with `k_a x k_b` arcs. `O(k³)` in *distinct classes* rather than nodes, which matters only for the 3.1% of functions above the node cap | `BTreeMap<(u32, u32, bool, bool), u32>` of class counts | M | identical value to G-2 on every published CFG pair; strictly faster above 30 nodes |
| G-4 | Large-graph fallback | above `GED_MAX_NODES` (default 60, `DECBENCH_GED_MAX_NODES`): return `\|Δnodes\| + \|Δedges\|` and tag it `approximated` | — | XS | the tag is present, and the value is not mistaken for an exact 0 |

## 5. type_match (T)

Independent of the front end; depends on DWARF, which the crate already reads.

| ID | Component | Mathematics / algorithm | Data structure | Size | Test |
|---|---|---|---|---|---|
| T-1 | DWARF ground truth | DIE walk for `DW_TAG_subprogram` → `DW_TAG_formal_parameter` / `DW_TAG_variable`; `DW_AT_name`, `DW_AT_type` chain resolution, `DW_AT_location`. Stack offsets come from `DW_OP_fbreg` in **either** an inline exprloc **or a location list**. Every variable with any location is kept — only fully optimized-out ones are dropped, which is what makes the metric work at `-O2` | `gimli`, already a dependency; `BTreeMap<FnName, Vec<GtVar>>` with `rbp_offset: Vec<i64>` deduplicated | M | variable counts and offsets equal to the reference on a fixture built at `-O0` and `-O2` |
| T-2 | Type normalization | a type string maps to a **set of equivalent spellings**; two types match iff the sets intersect. 37 aliases (`undefined8` → `long long`, `_QWORD`, LP64 `long`, SLEIGH `int4`…), 7 qualifiers stripped, `long long int` → `long long` and friends, whitespace collapse, `*` tightening, then a re-alias pass over the results | static perfect-hash alias map; per-variable `SmallVec<[Symbol; 4]>` of interned forms — intersection over ≤4 elements is a nested loop, not a hash set | S | set-equality with `normalize_type` over every distinct type string in the corpus |
| T-3 | Width-only matching | uncommitted types (`undefined4`, `_DWORD`, `int4`) match a ground-truth **scalar** of the same width, and nothing else — pointers and aggregates stay misses | `width → &'static [Symbol]` table | XS | `undefined8` matches `long`, does not match `char *` |
| T-4 | Per-function offset calibration | **maximum-overlap one-dimensional translation.** A shift `k` can only align a slot when `k = g − d`, so the candidate set is exactly the difference set plus zero — adaptive and uncapped, which is what handles IDA's frame-bottom-relative offsets. Score `k` by `\|{d+k} ∩ G\|`; ties resolve to smallest `\|k\|`; a nonzero winner with ≥2 decompiled offsets must align ≥2, else fall back to `k = 0`. The naive form is O(\|G\|·\|D\|²); the **mode of the difference multiset** does it in O(\|G\|·\|D\|) | `HashMap<i64, u32>` shift → count, `HashSet<i64>` for the ground-truth offsets | S | identical shift to `_calibrate_shift` on every function of a fixture binary |
| T-5 | Binary-wide calibration | the same overlap problem across functions, but candidates restricted to ±32 so a coincidental large shift cannot win the vote, and each function votes `max(0, matches − 1)` so a lone alignment contributes nothing. Falls back to plain counting when no shift earns a discounted vote | `Vec<(Vec<i64>, Vec<i64>)>` per-function offset pairs | S | identical to `_calibrate_shift_multi` |
| T-6 | Three-pass greedy matching | order is load-bearing: (1) arguments by ABI position, (2) stack variables by shifted offset, (3) the rest by exact name. Each decompiled variable is claimed at most once; within a bucket prefer a type-matching candidate, otherwise consume the first and score a false positive. This is **greedy bipartite matching, not optimal** | `HashMap<u32, usize>` by arg index, `HashMap<i64, Vec<usize>>` by shifted offset, `HashMap<Symbol, Vec<usize>>` by name, `FixedBitSet` of claimed indices, parallel `decided` / `verdicts` vectors | M | per-function `(tp, fp, fn)` equality with the reference on a fixture binary |
| T-7 | Score | `tp / (tp + fp + fn)` — a Jaccard over variables, so spurious extra variables cost you | — | XS | — |
| T-8 | Signature-text fallback | with no structured variables, parse the emitted C signature into ABI-positioned arguments plus declared locals. This is the scoring path for stored artifacts and LLM backends, and it is how the materialized run scored type match on 86,612 functions | a small declarator matcher | M | reproduce `parse_c_variables` on stored `.c` artifacts |

## 6. byte_match (B)

The most machine-dependent of the three, and the only one with a component that
cannot be made exactly reproducible (see §9, landmine 1).

| ID | Component | Mathematics / algorithm | Data structure | Size | Test |
|---|---|---|---|---|---|
| B-1 | Format and architecture detection | ELF/PE magic → `(format, arch, bits)` → recompiler choice (PE → MinGW, ARM → arm-none-eabi, x86 → gcc) and the capstone `(arch, mode)` pair | already covered by `src/formats/` | XS | agreement with `binfmt.detect` on every binary in the tree |
| B-2 | Producer-flag recovery | parse `DW_AT_producer` for `-O*`, `-m*` and codegen `-f*` flags. Dropping the `-f` flags made whole projects unwinnable, so they are part of the contract | token scan | XS | flag list equality with `binfmt.producer_flags` |
| B-3 | Function byte extraction | symbol table or DWARF `low_pc`/`high_pc`; **ARM Thumb detection from `STT_FUNC` symbol bit 0** — defaulting to ARM mode made capstone emit confident nonsense on both sides of the comparison | `object` / `goblin`, already dependencies | S | byte-equality with `binfmt.function_bytes` |
| B-4 | Compilability fixup | a **fixpoint repair loop driven by compiler diagnostics**, capped at 12 iterations. It injects only what gcc reports missing — implicit-function prototypes (preferring the decompiler's own sibling signatures), unknown-type typedefs, synthesized structs, width-typed globals — from static tables of 207 known prototypes and 177 helper macros. It **backtracks**: a declaration that produces a conflict is withdrawn and retried, and a diagnostic pointing into the injected header withdraws the offending line | `BTreeMap<Symbol, String>` declarations, `BTreeMap<Symbol, Vec<String>>` structs, a positional-edit list of `(line, col, edit)`, and a header emitted in sorted order so diagnostic line numbers map back deterministically | XL | same `compilable` verdict as the reference on stored artifacts; the 207+177 tables ported verbatim, not paraphrased |
| B-5 | Disassembly | capstone with detail enabled; `nop` skipped as alignment padding | `capstone`, already a dependency | XS | listing equality on extracted bytes |
| B-6 | Operand normalization | blank branch and call targets — mnemonic in a 50-element set **and** no `[` in the operand string; rewrite pc-relative memory `[rip±d]` → `[rip+X]` **including the unlinked object's bare `[rip]`**; blank `adrp`/`adr` immediates; then a **two-instruction peephole** dropping x86-64 `xor eax, eax` / `mov eax, 0` immediately before a `call` | a perfect-hash mnemonic set; compiled regexes | S | line-for-line equality with `_disassemble_bytes` on stored function bytes |
| B-7 | Line diff | line → `u32` interning, then **Myers O(ND)** with the middle-snake bisect and `checklines=False`, then map back to lines | `Vec<u32>` per side; the Myers `v1` / `v2` k-line arrays | M | see landmine 1 — this is the component that cannot be certified exactly |
| B-8 | Score | from the diff operations: `shared / (a_only + shared + b_only)`, plus `changed = a_only + b_only` for the distance view | — | XS | — |

## 7. Scoring and denominators (S)

| ID | Component | Mathematics | Size | Test |
|---|---|---|---|---|
| S-1 | Measurable universe | a metric is measurable for a function iff *some* column has a finite value for it. Requires two passes over all columns before any denominator is computed | S | reproduce the shared universe of a stored `function_results.json` |
| S-2 | Shared denominator | measurable-but-failed is a not-perfect miss **inside** the denominator; unmeasurable-for-everyone leaves it uniformly | XS | column totals equal across decompilers per metric |
| S-3 | Union column | perfect on at least one measurable metric, over functions with at least one measurable metric | XS | reproduce the published Union count |
| S-4 | Compiles rate | per-decompiler `[recompiled, byte_match measured]`, so abstentions never enter the denominator | XS | reproduce the published rate |

## 7.5 Beyond the metrics — the components later stages add (L)

The 45 components above compute the three DecBench metrics. They are not the
whole front end: [`roadmap.md`](roadmap.md) stages S4 and S5 add a lowering and
an equivalence checker, and those are where the front end stops being a metric
adapter. They are listed here so the inventory is the whole picture, and marked
so nobody mistakes them for part of the GED milestone.

| ID | Component | Mathematics / algorithm | Data structure | Size | Test |
|---|---|---|---|---|---|
| L-1 | AST → LLIR lowering | syntax-directed translation from the S1 AST to `LlirFunction`: expressions to `Op` sequences over virtual registers, C's integer promotions and usual arithmetic conversions to explicit widths, lvalues to loads and stores, calls to `CallTarget`. Not a compiler — no linking, no register allocation, no ABI lowering beyond what `ir::abi` already models | reuses `LlirFunction`, `LlirBlock`, `Op`, `VReg`, `Width` from `src/ir/types.rs` | L | a lowered fixture function and the same function lifted from its compiled binary agree observably under `exec` |
| L-2 | Storage model | C locals to LLIR stack slots or virtual registers; address-taken locals must be memory. Requires an escape analysis no harder than "is `&x` taken anywhere in the function" | a per-function `HashSet<Symbol>` of escaped locals | S | a fixture that takes the address of a local round-trips through memory, not a register |
| L-3 | Bounded symbolic runner | drive `exec::interp` over `symbolic::Symbolic` for a lowered function with an unrolling depth and a memory bound. **No new engine code** — this is configuration of the existing `Domain` and `Budget` | `Budget`, `ExprPool` from `src/symbolic/expr.rs` | S | a fixture with a known symbolic output produces the expected `Expr` |
| L-4 | Equivalence query construction | given two symbolic executions with a shared input model, build the QF_BV query `inputs equal ∧ outputs differ` and hand it to the `Solver` trait. `unsat` is equivalence within the bound; `sat` yields a counterexample; `unknown` is a first-class outcome and is **not** evidence of equivalence | the existing `Solver` trait (`src/symbolic/solver/mod.rs`); `solver-axeyum` is the pure-Rust backend and the query shape is exactly its minimal QF_BV consumer profile | M | the separation gate of [`roadmap.md`](roadmap.md) §7: `unsat` on known-good pairs, `sat` with a witness on known-bad ones |
| L-5 | Input model | what "equal inputs" means for a function with pointer parameters: a bounded symbolic heap, aliasing assumptions, and the explicit statement of what the model does not cover | reuses `src/exec/memory.rs` and `src/symbolic/concretization.rs` | M | a fixture whose equivalence depends on an aliasing assumption reports that assumption rather than silently adopting it |
| L-6 | Source function extraction | given a name, return its exact source text and span from the AST | spans from REQ-GEN-2 | XS | replaces `tools/roundtrip_review.py:source_of` and agrees with it on the 196 fixture sources |

L-1 and L-2 are the whole of S4. L-3 through L-5 are S5, and none of them is a
new engine: the interpreter, the symbolic domain and the solvers already exist
(§3 of [`architecture.md`](architecture.md)). L-6 is a byproduct of REQ-GEN-2
that pays for itself immediately.

## 7.6 Dependency tiers — what forces a linked dependency

Of the 45 metric components, exactly one group was ever a build-it-versus-link-it
decision.

| tier | components | situation |
|---|---|---|
| **Free** — pure Rust, zero new dependencies | K-1..4, G-1..4, T-1..8, S-1..4 — **20 of 45** | `gimli`, `object`/`goblin`/`pelite`, `sha2`, `serde_json` are all present and pure Rust. **All of `type_match` and all of scoring need nothing new.** The LSAP is ~200 lines written rather than a `pathfinding`/`lapjv` dependency |
| **The one real choice** | F-1..17 — **17 of 45** | hand-written is pure Rust with no `unsafe`; `tree-sitter-c` brings a generated C `parser.c` through `cc`. Settled, with the evidence, in [`architecture.md`](architecture.md) §4 |
| **Impossible regardless** | B-1..8 — **8 of 45** | B-4 shells out to gcc / MinGW / arm-none-eabi. That is an external toolchain, not a linked library: no amount of building things ourselves removes it |

The L components above stay inside the line: L-1 and L-2 target LLIR, which is
already in the crate, and L-3 through L-5 use the existing `Solver` trait whose
pure-Rust backend is a feature-gated optional dependency. Nothing in this
inventory adds a linked dependency to the default build.

For what the crate links *today* — capstone unconditionally and load-bearing for
every non-x86 architecture, plus mimalloc as the global allocator, and no wasm
target anywhere — see [`architecture.md`](architecture.md) §5.1.

## 8. Build order

Six waves, mapped onto the stages of [`roadmap.md`](roadmap.md). Each wave is
useful on its own, and each ends at a gate that can be run without the next wave
existing.

| wave | components | roadmap stage |
|---|---|---|
| 0 | K-1..4 | S0 |
| 1 | G-1, G-2, G-4 | S3 (scoring half, done early on purpose) |
| 2 | F-1, F-2, F-3, F-13, F-15 | S1 (normalization) |
| 3 | F-4..F-12, F-14, F-16, F-17, G-3 | S1, S2, S3 |
| 4 | L-1, L-2, L-6 | S4 |
| 5 | L-3, L-4, L-5 · T-1..8 · B-1..8 | S5 · S6 · not a stage |

**Wave 0 — kernel.** K-1..K-4. Half a day, no dependencies, and every later
test leans on K-4.

**Wave 1 — the distance before the front end.** G-1, G-2, G-4. Feed them
`rebuild_cfg` output from the 800 published source CFGs on both sides and check
`vj_ged(x, x) == 0` and pairwise agreement with the reference. This makes the
scoring half certain before the hard half starts, and it is the piece most
likely to be reusable elsewhere in the crate.

**Wave 2 — normalization.** F-1, F-2, F-3, F-13, F-15. All pure, all
byte-checkable against the Python originals, all XS. This is gate L0 of
[`parity-plan.md`](parity-plan.md).

**Wave 3 — the front end.** F-4 → F-12, F-14, F-16, F-17, in that order. F-8
and F-9 are where the risk is; F-9 is the highest-value single component,
because short-circuit operators are both common and structurally expensive.
Ends at gates L1, L2 and L3 — including the 85,645-cell oracle. G-3's
degree-class compression lands here too, once there is something to profile.

**Wave 4 — lowering.** L-1, L-2, L-6. This is where the front end stops being a
metric adapter: reaching `LlirFunction` inherits the interpreter, the symbolic
domain and every solver behind the `Solver` trait without writing any of them
(§3 of [`architecture.md`](architecture.md)). L-6 falls out of REQ-GEN-2 and
retires `tools/roundtrip_review.py`'s brace-matching regular expression on the
way past.

**Wave 5 — oracles and the remaining metrics.** L-3, L-4, L-5 build the bounded
equivalence checker, which is the only oracle in this whole set that is not a
proxy. T-1..T-8 is native `type_match`, independent of everything else and
achievable with zero new dependencies. B-1..B-8 is `byte_match`.

Within wave 5, order by value: **the equivalence checker first**, because it
answers the question the metrics only approximate; then `type_match`, which is
`M`-sized throughout, depends on DWARF the crate already reads, and has a cheap
equality test per component; then `byte_match`, which is dominated by B-4 — `XL`,
384 lines of static table to transcribe exactly, and an external compiler
regardless. `type_match` and `byte_match` together account for 27 of our 82
published Union points against GED's 69, so neither is on the critical path.

## 9. Landmines

Three places where writing the better algorithm produces the wrong answer.

**1. `byte_match` is wall-clock dependent, and cannot be made exactly
reproducible.** `diff_match_patch` defaults to `Diff_Timeout = 1.0` seconds and
`diff_bisect` **bails on that deadline**, returning the degenerate
`[(DELETE, everything), (INSERT, everything)]` — which scores `0.0`. So for any
function whose diff exceeded one second on the recording machine, the stored
value is a property of that machine's speed, not of the code. A `byte_match`
parity gate must carve this out explicitly; a stored `0.0` cannot be
distinguished from a genuine total mismatch without re-running.

**2. `type_match`'s matching is greedy, and must stay greedy.** T-6's three
passes, and the within-bucket "prefer a type match, otherwise consume the first
and score a false positive" rule, are load-bearing. Replacing them with an
optimal assignment — which is the obvious improvement, and which G-2 will
already be sitting there implementing — produces different `(tp, fp, fn)` triples
and therefore different scores.

**3. The infeasible cells in the GED cost matrix.** G-1's off-diagonal deletion
and insertion blocks are infinite in the reference. Munkres implementations
differ in how they handle infeasibility: a sentinel that is too small silently
permits a forbidden assignment, and one that is too large makes the `100000`
entry/exit penalty numerically irrelevant or overflows. Pin it as
`M = 1 + Σ(all finite costs)` and test both boundaries.

A fourth, which is not a landmine so much as a standing temptation: **a more
accurate CFG that scores differently is a regression against this component's
purpose.** §8 of [`requirements.md`](requirements.md) lists the things this
component deliberately does not do; Joern folds no constants, terminates no
block at a `noreturn` call, and prunes no unreachable code, and neither may we.

## 10. What exists and what is new

Already in the crate, and reusable as-is: `gimli` (T-1, B-2), `capstone` and
`iced-x86` (B-5), `object` / `goblin` / `pelite` (B-1, B-3), `sha2` and `blake3`
(K-1), `serde_json`, `regex`, `aho-corasick`, `rayon`, and the
`ControlFlowGraph` / `BasicBlock` pair in `src/core/`.

The later stages reuse more, not less: L-1 and L-2 target `LlirFunction`,
`LlirBlock` and `Op` from `src/ir/types.rs`, and L-3 through L-5 use
`exec::interp`, `symbolic::Symbolic`, `symbolic::ExprPool` and the `Solver`
trait — all shipping today. **Nothing in this inventory adds a linked dependency
to the default build** (§7.6).

Genuinely new, in descending order of risk:

1. **The C front end** (F-4 … F-9). The only `L`/`XL` cluster in the GED path,
   and the only component where the difficulty is matching Eclipse CDT's *error
   recovery* rather than parsing C.
2. **AST → LLIR lowering** (L-1, L-2). `L`-sized, and the gate is semantic
   rather than structural, which makes it slower to converge than anything in
   the GED path — but it is the component every later capability depends on.
3. **The compilability fixup loop** (B-4). `XL`, and mostly transcription.
4. **The equivalence query and its input model** (L-4, L-5). The engine exists;
   what is new is deciding what "equal inputs" means for pointer parameters, and
   saying so out loud wherever a result is quoted.
5. **Myers diff with `diff_match_patch`'s exact behaviour** (B-7). See landmine 1.
6. **Hungarian / Munkres LSAP** (G-2). `S`, well-specified, and brute-force
   checkable for small `n` — the easiest new component in the whole inventory.
7. **A canonical-JSON hasher** (K-1). Needed only if cache interoperability with
   the reference matters.

## 11. Precedent in the sibling crate (`axeyum`)

Glaurung already depends on `axeyum` — pinned at rev `c38a9515`, optional,
behind the `solver-axeyum` feature — so its conventions are a sibling's, not a
stranger's. Nothing there is directly reusable for these metrics: **there is no
assignment solver, no min-cost flow, no diff, no graph edit distance and no C
parsing in the workspace**, so G-2, G-3 and B-7 are genuinely new code. The only
union-find lives inside the e-graph (`crates/axeyum-egraph/src/lib.rs:867`) and
is not extractable.

What it does supply is five patterns that have already been paid for once, three
of them by a recorded incident. Take the patterns, not the code.

| Pattern | Where | Applies to |
|---|---|---|
| **Hash-consed arena, dense deterministic IDs.** Structurally equal terms intern to one id; ids are assigned densely in insertion order, so identical construction sequences yield identical ids. Handles are lifetime-free `Copy` ids, and `BTreeMap` is used specifically "because consumers iterate it and output order is a public promise" | `crates/axeyum-ir/src/arena.rs` | F-5's AST arena, F-14's stable relabeling, K-4 |
| **Iterative, explicit-stack traversal as a hard rule.** `sexpr.rs` opens: "Both passes are loop-based with explicit stacks, so adversarially deep benchmark files cannot overflow the call stack (hard rule)." It is there because a recursive scan overflowed the stack and **aborted the process**, so no first-class result could be reported and the harness read the exit as a crash (fixed in `fcc8760d`) | `crates/axeyum-smtlib/src/sexpr.rs` | F-5, F-6, REQ-ROB-3 — and this is the most transferable item in the table. Decompiler C is adversarial in exactly this way: nested casts, parenthesized spines, and long `\|\|` chains are all attacker-controlled depth. A parser that aborts the process cannot report a per-function failure, which is precisely the whole-file voiding mode we are trying to remove (§5 of [`joern-behavior.md`](joern-behavior.md)) |
| **A non-answer is a first-class value, never an error.** "`unknown` is a first-class solver result, never an error" | `CLAUDE.md`, Hard Rules | K-2. The abstention tri-state is the same shape: an unmeasurable metric is a *value*, not a failure, and collapsing it into `0.0` or an `Err` is how a denominator silently rots |
| **Determinism as a public API promise.** "Stable iteration order, explicit seeds, explicit resource limits. No hash-map iteration order in output" | `CLAUDE.md`, Hard Rules | K-4, REQ-OUT-3 |
| **A fuzz seed-class per underspecified case.** A wrong-`unsat` shipped (`a946f925`) because division by a *constant* zero was folded to a fixed convention and the differential fuzz that "passed" structurally could not generate that argument. The rule: every underspecified operator must have a generator that deliberately emits the degenerate case, because "a corpus sweep + a fuzz that avoids the corner is not a soundness gate" | `CLAUDE.md`, Hard Rules | the whole test plan. Our degenerate cases are computed `goto`, an unparseable construct inside an otherwise parseable function, an empty `then` branch, a multi-entry function, a function whose funcend is *not* a singleton, and a diff that hits the one-second deadline. The 88,963-cell oracle is a corpus sweep; on its own it is not a gate for any of these |

One further data point rather than a pattern: the sibling workspace holds
"the default build must compile with **no C/C++ dependency**; native solver
backends are feature-gated leaf dependencies only." That is a stance, not a law
this repository has adopted — Glaurung already links C through `capstone` — but
it is evidence for the hand-rolled side of the parser-strategy question
(open question 1 in [`requirements.md`](requirements.md)), since `tree-sitter-c`
would add a C runtime to the default build rather than to a feature-gated leaf.

## 12. Where the numbers come from

Counts of static tables and constants in this document are read from the
reference implementation at DecBench `efc5d5a`:

```bash
"$DECBENCH_DIR/.venv/bin/python" - <<'COUNTS'
import sys, os
sys.path.insert(0, os.environ["DECBENCH_DIR"])
from decbench.metrics.byte_match import _BRANCH_MNEMONICS, _PC_REL_MNEMONICS
from decbench.metrics.type_match import TYPE_MAP, QUALIFIERS
from decbench.metrics.fixup import _known_protos, _helper_macros, _MAX_REPAIR_ITERS
print("branch mnemonics", len(_BRANCH_MNEMONICS), "pc-rel", len(_PC_REL_MNEMONICS))
print("type aliases", len(TYPE_MAP), "qualifiers", len(QUALIFIERS))
print("known protos", len(_known_protos()), "helper macros", len(_helper_macros()))
print("max repair iters", _MAX_REPAIR_ITERS)
COUNTS
```

At `efc5d5a` that prints 50 and 2, 37 and 7, 207 and 177, and 12 — the values
quoted in §5, §6 and §8. Corpus-level figures (mean 12.03 nodes, 49.0% without
an exit flag, 3.1% above the node cap, 88,963 stored GED cells of which 85,645
are reproducible) come from
`uv run python tools/source_cfg_census.py ~/.cache/glaurung/decbench-full/tree`,
run at `935b7db1`; the full output is in §3 of
[`joern-behavior.md`](joern-behavior.md).
