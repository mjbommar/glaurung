# Structural function identity (L1)

The L1 rung of the identity ladder in
[`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md):
a small set of **control-flow invariants** per function, stored as scalars,
answering one question well --

> Which functions changed between two builds, and by how much?

It is not a similarity model, it does not cross an optimisation level, and it
needs no corpus, no training and no index structure. Everything here is
computed from what `glaurung.analysis` discovery already produces plus one
re-decode of each function's blocks.

| | |
|---|---|
| Rust | `src/identity/structural/` (`graph`, `mdindex`, `spp`, `code`) |
| Python binding | `glaurung.analysis.structural_signatures_path(path, **budgets)` |
| Scheme name | `glaurung-structural-l1-v1` (`glaurung.analysis.STRUCTURAL_SCHEME`) |
| KB table | `function_structural`, keyed `(binary_id, entry_va)` -- `python/glaurung/llm/kb/function_structural.py` |
| Consumer | `glaurung diff` -- `python/glaurung/llm/kb/binary_diff.py` |
| Tests | `tests/identity_structural.rs`, `python/tests/test_structural_signature.py`, `python/tests/test_binary_diff_structural.py`, `python/tests/test_structural_md_index_measurement.py` |

---

## The invariants

### MD-index (three variants)

Dullien, Carrera, Eppler and Porst, *Automated Attacker Correlation for
Malicious Code* (2010). The formula below is verified against
`google/bindiff`'s [`graph_util.h`](https://raw.githubusercontent.com/google/bindiff/main/graph_util.h)
(Apache-2.0), function `CalculateMdIndexInternal`.

For each control-flow edge `(s, t)`:

```
term(s, t) = 1 / (  sqrt(2)  * indeg(s)
                  + sqrt(3)  * outdeg(s)
                  + sqrt(5)  * indeg(t)
                  + sqrt(7)  * outdeg(t)
                  + sqrt(11) * level(s)
                  + sqrt(13) * level(t) )

MD-index    = sum of term(s, t) over every edge
```

Two details are load-bearing:

* **The reciprocal is of the sum, not of its square root.** Diaphora's
  `md_index` column uses `1/sqrt(embedding)` over the same five-term
  embedding, so Diaphora's numbers and ours are *not* interchangeable. Ours
  follow BinDiff.
* **The terms are sorted before they are summed.** BinDiff's own comment:
  *"Sorting the summands before adding them together is important because of
  rounding errors."* Floating-point addition is not associative, so an
  unsorted sum makes the index depend on edge enumeration order and two runs
  over the same function can disagree in the last few bits. We sort with
  `f64::total_cmp`, which is a total order and therefore reproducible.

`level` is a BFS numbering, exactly as in BinDiff's `BreadthFirstSearch`:
every vertex starts at 0, every vertex with in-degree 0 is a root and keeps
level 0, and a vertex first reached from level `l` gets `l + 1`. Vertices in a
cycle no root reaches keep 0.

| variant | weights | `level` from |
|---|---|---|
| `md_index_top_down` | `{2,3,5,7,11,13}` | BFS from the entry (`bfs_top_down_`) |
| `md_index_bottom_up` | `{2,3,5,7,11,13}` | BFS from the exits (`bfs_bottom_up_`) |
| `md_index_relaxed` | `{2,3,5,7,0,0}` | dropped -- `sqrt(0) == 0` |

Degrees do **not** swap between top-down and bottom-up; only the level
numbering changes. BinDiff runs the relaxed variant as a separate,
lower-confidence pass (0.7 against 1.0 in `bindiff.json`): it survives an edit
that moves a block's depth without changing local degrees.

**One documented deviation from BinDiff.** When *no* vertex has in-degree 0 --
a function whose entry block is also a loop header -- BinDiff's queue starts
empty and every level stays 0, collapsing the top-down index onto the relaxed
one. We seed the entry block in that case, so "top-down" means "from the
entry". For any CFG where BinDiff's rule is well defined the two agree
exactly, because a vertex of in-degree 0 is the target of no edge. The
bottom-up direction has no analogous principled fallback and is left as
BinDiff leaves it: no exit blocks means every level is 0.

### Small Primes Product (SPP)

Dullien and Rolles, *Graph-based Comparison of Executable Objects* (SSTIC
2005), section 3; Diaphora ships it as the `mnemonics_spp` column. Map each
normalized mnemonic to a distinct small **odd** prime and take the product
over the function's instructions, modulo `2^64`.

What it buys is an **order-independent multiset identity**: multiplication
commutes, so an instruction scheduler that reorders a block without changing
its contents leaves the SPP alone, while adding or removing one instruction
changes it. A non-empty function's SPP is always odd; an empty one is 1, the
empty product.

BinDiff's own `prime signature matching` pass uses the weaker *sum* of Goedel
numbers, which fits a machine word but loses the multiplicative structure.

**Normalized mnemonic** (`spp::normalize_mnemonic`) -- three rules, in order:

1. **Lowercase and trim.**
2. **Truncate at the first `.`.** Capstone puts a NEON/VFP data-type suffix
   there (`vneg.f64`, `add.4s`); the lane arrangement is carried by the
   operands, not the operation.
3. **Strip one trailing ARM condition suffix, but only onto a known stem.**
   Capstone renders a predicated A32 instruction as `addne`, `bleq`, `movmi`.
   Stripping unconditionally would mangle x86's `cmovle` into `cmov` and
   `setle` into `set`, so the strip is gated twice: the whole name is looked
   up first and returned as-is when it is listed, and only then is a suffix
   removed, and only onto a stem that is itself listed.

The `s` flag-setting suffix (`adds`, `subs`) is **not** stripped: writing the
condition flags is a real semantic difference.

The mnemonic vocabulary differs per architecture because the decoder does:
`iced` for x86 and x86-64, `capstone` for ARM, AArch64, MIPS, PowerPC and
RISC-V (`crate::disasm::registry`).

**The prime table's order is the scheme.** `spp::KNOWN_MNEMONICS` entry `i`
maps to the `i`-th odd prime, so inserting a name in the middle renumbers
everything after it and invalidates every stored SPP. Append only, and treat
an append as a scheme version bump. A mnemonic not in the table maps into a
fixed overflow window of 1,024 further primes, indexed by an FNV-1a hash of
the normalized text, so two unlisted mnemonics can collide onto one prime.
That is deliberate: the alternative is an unbounded table that changes shape
whenever a decoder learns an opcode, which would be a *silent* scheme change.
The consequence is bounded -- a collision can make two different functions
look alike, never make one function look different from itself.

### Counts

| field | definition |
|---|---|
| `basic_blocks` | distinct block start addresses |
| `edges` | distinct `(from, to)` pairs; edges to a block discovery never walked are dropped rather than inventing a node |
| `back_edges` | edges `(u, v)` where `v` dominates `u` (Cooper-Harvey-Kennedy iterative dominators) |
| `loops` | distinct back-edge targets, i.e. natural-loop headers |
| `strongly_connected_components` | Tarjan, trivial components included; an acyclic function of `n` blocks has `n` |
| `cyclomatic_complexity` | `E - N + 2`, clamped at 1 |
| `instructions` | decoded across the function's blocks |
| `calls_out_direct` / `calls_out_indirect` | a call with an immediate target / through a register or memory |
| `callers_in` | distinct callers per the call graph; **0 also means "no call graph was supplied"** |
| `string_refs` | distinct referenced addresses holding a NUL-terminated printable run of >= 4 bytes |
| `rare_constants` | large non-address immediates, ascending, with multiplicity |

`back_edges` is a *loop* count, not a *cycle* count: an irreducible cycle (two
entries into one loop body) has no back edge and contributes 0 there while
still merging blocks in the SCC count. That is why a signature carries both,
and why `cyclic_blocks = basic_blocks - strongly_connected_components` is the
more discriminative derived quantity.

### Rare constants and string references

Two masks, both because the masked thing moves on a relink:

* **Branch and call targets** are skipped entirely. A direct `call` to a
  function one byte further along is the same call.
* **Anything that resolves to an address in this image** is excluded from the
  constant multiset even when it is large -- it is a pointer, not a value.
  Those same operands are exactly where a string reference is looked for.

A constant qualifies as "rare" at `|v| >= 0x1000` (`code::RARE_CONSTANT_MIN`).
Below that sit loop bounds, structure offsets and every small arithmetic
constant, all of which repeat across thousands of functions. The multiset is
sorted and then capped at 64 entries (`code::RARE_CONSTANT_CAP`), so the cut
is deterministic rather than decode-order dependent.

---

## Determinism

Every field is computed from a canonicalised `CfgShape` -- blocks sorted by
address, edges deduplicated and sorted. The MD-index sorts its per-edge terms
before summing. The rare-constant multiset is sorted before truncation. The
SPP is a commutative product over a table with no hashing randomness (FNV-1a,
seedless, never `RandomState`). Two runs over the same bytes produce
bit-identical signatures; `tests/identity_structural.rs::signatures_are_bit_identical_across_two_runs`
and `python/tests/test_structural_signature.py::test_two_runs_agree_exactly`
assert exactly that, field by field.

**JSON is a diagnostic format for a signature, not a storage format.**
`serde_json`'s default float parser is accurate to one unit in the last place,
not bit-exact, so an MD-index that goes out through JSON and comes back may
differ in the last bit. Persist through SQLite `REAL`, which stores an
IEEE-754 double verbatim.

---

## Ranking similarity

`glaurung.analysis.structural_ranking_similarity(a, b) -> float` in `[0, 1]`:

```
counts   = 0.55*ratio(edges) + 0.30*ratio(blocks) + 0.15*ratio(instructions)
md       = mean( agree(top_down), agree(bottom_up), agree(relaxed) )
           where agree(a, b) = 1 - |a-b| / (1 + a + b)
spp      = 1 when the two products are equal, else 0
consts   = Jaccard over the rare-constant multisets (1 when both are empty)

similarity = 0.45*counts + 0.35*md + 0.12*spp + 0.08*consts
```

`ratio(a, b)` is `min/max`, and 1.0 when both are zero.

**Why these weights.** The inner `counts` blend is BinDiff's own
function-similarity formula verbatim -- `0.55*edge_ratio + 0.30*bb_ratio +
0.15*insn_ratio`. BinDiff then averages that against a single MD-index
agreement, i.e. 50/50. We keep the shape and move twenty points onto two
signals BinDiff's *score* omits even though its *matcher* trusts them:
`prime signature matching` runs at confidence 0.9 and `string references` at
0.7 in `bindiff.json`, so both are near-decisive evidence of identity while
contributing nothing to the number that ranks the result. The MD-index share
stays the largest single term because it is the only one of the four that
moves smoothly with the size of a control-flow edit -- SPP is a step function
and the count ratios saturate. The constant term is small on purpose: a
function with no large constants is common, and giving "both empty" a full
0.08 would inflate every small function's score.

**It is not a metric.** Symmetric and 1.0 on identity, but nothing here
establishes a triangle inequality. Do not use it as an index distance. That
restriction is the same one the research synthesis places on approximate
graph edit distance, and for the same reason.

---

## The mask, restated

| kept | masked |
|---|---|
| CFG shape as relations (degrees, levels, dominance) | absolute addresses and the link base |
| an order-insensitive mnemonic multiset | instruction order within a block |
| block, edge, loop, SCC and call counts | block layout order |
| large non-address constants | branch and call targets |
| string-reference count | small constants (folded in via the mnemonic only) |
| | register names (mnemonics only) |

This is the mask/keep list the research synthesis found common to BinExport,
BSim, WARP, FunctionID, Diaphora and angr, restricted to what an L1 scalar can
carry.

---

## Storage

`function_structural`, keyed `(binary_id, entry_va)`. One row per function;
one scheme per build. **No `set_by` and no manual precedence** -- a structural
signature is a measurement of the bytes, not an assertion about them, so there
is no analyst opinion to outrank and recomputing must overwrite
unconditionally. `function_identity` makes the same choice for the same
reason.

Indexes are on `(md_index_top_down, md_index_bottom_up)`, on `mnemonic_spp`
and on `binary_id`. That is the whole index design: at 6,000 functions a flat
scan is faster than anything clever, and Ghidra's own embedded BSim backend
has no ANN index either.

SQLite's `INTEGER` is signed and the SPP is not, so values at or above `2**63`
are stored as their two's-complement negative and mapped back on read
(`_spp_to_db` / `_spp_from_db` are the only two places that know this).

```python
from glaurung.llm.kb import function_structural as fs
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

kb = PersistentKnowledgeBase.open("proj.glaurung", binary_path="a.out")
n = fs.index_function_structural(kb, "a.out")     # idempotent
rows = fs.list_function_structural(kb)
rare = fs.rare_by_md_index(rows)                  # Diaphora's gate
```

---

## How `glaurung diff` uses it

Two things, both after the existing name-match and Jaccard cross-name passes,
and both skipped entirely when those passes left nothing changed, added or
removed -- so a self-diff pays nothing.

### 1. Ranking

Every two-sided row gets `structural_delta = 1 - ranking_similarity`, plus
each side's top-down MD-index. `render_diff_markdown` orders the changed
table by that delta, descending, falling back to the old ascending-Jaccard
order for rows the L1 pass could not measure. The delta ranks a control-flow
edit above a same-shape instruction swap, which the token-Jaccard score cannot
tell apart.

### 2. Rarity-weighted MD-index rematch

The Jaccard pass pairs functions whose *token multisets* still overlap. It
cannot pair a function whose body the compiler rewrote while leaving its
control flow alone -- and a shape that survived unchanged is strong evidence
of the same function.

The MD-index pairs them. What makes that safe is **Diaphora's rule: a feature
is usable as an identity only when it is globally rare.**

* `count(*) <= 2` on **both** sides (`RARE_MAX_OCCURRENCES`), counted over the
  **whole binary** -- a three-block thunk shape occurring 400 times is not
  made rare by 398 of those having matched by name already;
* the function has at least 6 blocks (`RARE_MIN_BLOCKS`, Diaphora's
  `nodes > 5`);
* and exactly one residual candidate remains on each side. Two survivors
  sharing one rare key is a genuine ambiguity; picking one would be a guess
  dressed as a match, so both stay `added` / `removed` and stay visible.

A merged row carries `md_index_matched=True` and `similarity=None` -- the
Jaccard score is genuinely unknown for that pair, and inventing one would make
`relocation_only` fire on a guess.

The MD-indices are quantised to 12 decimal places before being used as a key
(`MD_INDEX_KEY_PLACES`). All three variants participate: two functions can
agree on the relaxed index while differing in where their exits sit.

### Interface

```
glaurung diff A B                            # structural pass on by default
glaurung diff A B --no-structural-rematch    # v3 behaviour
```

JSON output is **schema 4**: top-level `md_index_matched` and
`structural_rematch_ran`; per row `structural_delta`, `md_index_pre`,
`md_index_post`, `md_index_matched`. Every schema-3 field is unchanged, and a
reader that ignores unknown keys parses a schema-4 payload.

---

## What was measured

**MD-index stability across an optimisation level.** Corpus:
`tests/decompiler_fixtures/build/`, every fixture with both a
`<fixture>-gcc-O0.so` and a `<fixture>-gcc-O2.so` -- **206 fixture pairs**.
Functions whose discovered name is a `sub_`/`loc_`/`fn_`/`func_` placeholder
are excluded (those names encode the address they were generated at, so
pairing on them would pair by address). Pairs are same-name only. Measured
2026-09-02 in the main checkout, `maturin develop` (debug) build.

| | count | share |
|---|---:|---:|
| same-name function pairs compared | 2,131 | 100% |
| identical MD-index triple (top-down, bottom-up, relaxed) | 1,531 | 71.8% |
| differing MD-index triple | 600 | 28.2% |
| identical `(blocks, edges, back_edges)` | 1,539 | 72.2% |
| identical counts **but** a differing MD-index | 8 | 0.4% |
| identical MD-index **but** differing counts (a collision) | 0 | 0% |

Read it in two directions. First: on this corpus roughly **seven in ten**
functions keep their exact control-flow shape from `-O0` to `-O2`, which is
why the rarity-gated rematch is worth running even across an optimisation
level -- though this corpus is small decompiler fixtures, where many functions
are leaf helpers the optimiser barely touches, and the share on a large
application would be lower. Second: the MD-index separated **8 pairs** that
`(blocks, edges, back_edges)` could not, and never once claimed a match that
the counts contradicted. Those 8 are the discrimination the MD-index adds over
the three integers angr's `bindiff` uses, on this corpus, at this size.

Reproduce with `uv run pytest
python/tests/test_structural_md_index_measurement.py -q -s -m slow`. It skips
with a printed reason when the gitignored corpus is absent.

**Where the MD-index rematch actually fires.** On
`switchy-c-gcc-O2` against `switchy-c-gcc-O2-stripped`
(`--include-anonymous`), the Jaccard cross-name pass takes 7 pairs and the
MD-index pass then finds **0** -- none of the 3 residual rows was both rare
and unique. With the Jaccard pass disabled the MD-index pass finds **1** of
those 7 on its own. That is the expected division of labour and worth stating
plainly: on a *relink* the token multisets survive, so the cheaper pass wins
and the MD-index pass contributes nothing. It earns its place on the case the
Jaccard pass structurally cannot reach -- a body the compiler rewrote around
an unchanged control-flow shape -- which this sample pair does not contain.

Measured 2026-09-02, debug build.

**Not measured**, and therefore not claimed anywhere: retrieval quality
(Recall@1, MRR10) at any pool size, cross-architecture behaviour, and
behaviour under differential inlining. Those need the measurement harness and
the protocol in the research synthesis -- pool size and free-variable set next
to every number -- and belong to that lane, not this one.

---

## What this cannot do

* **It does not cross an optimisation level reliably**, and it does not cross
  an architecture at all. The SPP is a multiset over one ISA's mnemonics; the
  MD-index moves whenever the optimiser changes the edge set, which is most of
  what an optimiser does. The 71.8% above is a property of that corpus, not a
  guarantee. Cross-toolchain matching is L2's job (`crate::identity::cfr`).
* **It is not an identity on its own.** Small functions collide heavily, which
  is precisely why the rarity gate exists and why it is not optional.
* **A truncated CFG produces a signature for a smaller function than the one
  on disk.** The Python entry point widens `max_blocks`, `max_instructions`
  and `timeout_ms` above discovery's defaults for that reason; a caller that
  overrides them should read `FunctionFlags::CFG_INCOMPLETE` too.

## See also

* [`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md) -- the identity ladder and the ranked plan.
* [`docs/triage/similarity.md`](../triage/similarity.md) -- CTPH, which is a *file*-level near-duplicate tool and is deliberately not extended to functions.
