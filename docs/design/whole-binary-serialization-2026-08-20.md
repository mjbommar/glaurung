# Whole-binary analysis: what to adopt, what to design

Two questions, answered together because the answer to one constrains the other:
what should Glaurung *emit* so other tools can consume it, and what should it
*store* so an analysis survives the process that produced it.

Findings below are separated into **verified** (I read the primary source, or
measured it here) and **reported** (a survey claim I have not independently
checked). The distinction matters: a format recommendation is load-bearing, and
this document is meant to be actionable without re-doing the research.

---

## 1. Where we actually are

**There is no surface that serializes a whole-binary analysis in one artifact.**
Three artifacts carry disjoint slices, in three unrelated schemas, with three
independent version namespaces:

| artifact | carries | drops |
| --- | --- | --- |
| `export --output-format json` | 7 of 34 KB tables — names, comments, types, prototypes, stack vars, labels, evidence | **all xrefs, all 7 CFG tables, the call graph, every Windows fact table.** No code structure whatsoever |
| `decompile --all --format json` | pseudocode text | everything else; never persisted |
| `triage --format json` | file-level metadata | no functions, no CFG, no IR |

The `ida` / `binja` / `ghidra` formats are **script emitters**, not data formats:
they generate a `.py`/`.java` to run inside another tool, at three different and
undocumented fidelities from one flag (IDA carries prototypes and stack vars,
Binja neither, Ghidra neither plus no types).

Underneath sits the enabling defect: **`src/analysis/`, `src/program/` and
`src/ir/` have zero serde derives.** `LlirFunction`, the C AST, `ProgramSession`
and the analysis CFG cannot be serialized at all. The SQLite KB is a
hand-maintained shadow of a fraction of the program model, written in SQL from
Python, and the export is a fraction of that fraction.

Concretely, the thing a user cannot get out of Glaurung today: **one file
containing this binary's functions with their boundaries, their decompiled
bodies, their recovered types, and their cross-references.** All four exist
inside the system. No artifact carries more than two.

### The second-order defect: identity

Everything is keyed by `(binary_id, absolute entry VA)`, where `binary_id` is
anchored to the SHA-256 of the whole file. There is no `functions` table, no RVA
column, and the `binaries` table does not record an image base — so a stored VA
cannot even be renormalised after the fact.

- **Recompile** → new sha256 → a new `binaries` row is silently inserted and
  every query returns zero rows. The old annotations sit orphaned in the file.
- **Rebase** with identical bytes → `binary_id` unchanged, every stored VA now
  wrong, and nothing detects it.

The Rust core says so itself at `src/program/call_graph.rs:51`: *"Not stable
across a re-link, and it does not pretend to be."*

**A stable identifier already exists and is thrown away.**
`python/glaurung/llm/kb/structural_fingerprint.py` (492 lines) computes a
BinDiff-style per-function digest that masks call targets, IAT displacements,
register identity and stack displacements. Its only consumer is `binary_diff.py`,
which recomputes it on every run and discards it. **Zero hash columns exist
across all 34 tables.**

---

## 2. WARP changes the build-vs-adopt line

*Verified: I read the LICENSE, README and `warp.fbs` directly.*

[`Vector35/warp`](https://github.com/Vector35/warp) — **Apache-2.0, "Copyright
2020-2025 Vector 35 Inc."** — is *"a common format for transferring and applying
function information across binary analysis tools."*

**It solves function identity, and publishes the algorithm.** Verbatim from the
README: the function GUID is *"the UUIDv5 of the basic block GUIDs (sorted
highest to lowest start address)"* under namespace
`0192a179-61ac-7cef-88ed-012296e9492f`; the basic-block GUID is *"the UUIDv5 of
the byte sequence of the instructions (sorted in execution order)"* under
namespace `0192a178-7a5f-7936-8653-3cbaa7d6afe7`, after three transformations:

1. *"Zero out all relocatable instructions"*
2. *"Exclude all NOP instructions"*
3. *"Exclude all instructions that set a register to itself if they are
   effectively NOPs"*

That is precisely the rebase- and relink-invariant identity our KB lacks — the
same instinct as `structural_fingerprint.py`, but specified, reproducible, and
namespaced so values are comparable *across tools* rather than only against
ourselves.

**It has random access.** `warp.fbs` declares `file_identifier "WARP"`, a `File`
root of `FileHeader{version}` plus `[Chunk]`, and a `ChunkHeader` carrying
version, `ChunkType ∈ {Signatures, Types}`, `CompressionType ∈ {None, Zstd}`, a
`target`, and a `size:uint` whose comment reads *"provided so that readers can
allocate the size of the chunk before reading."* FlatBuffers is zero-copy, and
versioning exists at both file and chunk level.

**What WARP does not carry** *(reported)*: `Function` and `Symbol` have no
confidence and no provenance — only `Type` does. No decompiler output, no CFG,
no evidence. It is a function-identity and type-transfer format, and should be
adopted for exactly that, not mistaken for a whole-program container.

---

## 3. Provenance: we are less differentiated than we claim

`IDA_GHIDRA_PARITY.md:157` advertises `set_by` precedence as a headline
differentiator over IDA and Ghidra. That is **not accurate**, and two of the
three incumbents model it more finely than we do.

*Reported, not independently verified:*

- **IDA names are four-state**, not boolean: dummy (`sub_401000`), *auto but
  meaningful*, user, and none. That middle state is exactly the distinction our
  flat `set_by` collapses. IDA types are five-valued and, importantly, separate
  the **decompiler** from the disassembler — `AFL_HR_GUESSED_FUNC` /
  `AFL_HR_GUESSED_DATA` / `AFL_HR_DETERMINED` vs `AFL_IDA_GUESSED`. Since
  Glaurung recovers types *through* a decompiler, that distinction is one we
  should be making and are not.
- **Ghidra upstream now has five `SourceType` members including `AI`**, at equal
  priority to `ANALYSIS`. The largest open RE tool treats "a model asserted
  this" as a first-class provenance class at analysis-level trust — not user
  level. Our vocabulary already writes `llm`; it should be `llm:<model>` and
  must never outrank `manual`.
- **Binary Ninja's confidence is numeric and composes**: `BN_FULL_CONFIDENCE
  255`, `BN_DEFAULT_CONFIDENCE 96`, `BN_HEURISTIC_CONFIDENCE 192`,
  `BN_DEBUGINFO_CONFIDENCE 200`, 0 meaning unknown, combined multiplicatively
  with a floor clamp so a chain never silently collapses.

Meanwhile our own enforcement is weaker than advertised. **"Manual always wins"
is enforced in 3 of 5 setters**: `xref_db.py:1285` (data labels), `:1451`
(prototypes) and `:3094` (stack vars) have the guard;
**`set_function_name` (`:1055`) and `set_comment` (`:1205`) have none** — both do
an unconditional `INSERT OR REPLACE`. And `set_by` is a free `TEXT` column with
no CHECK constraint and 13 distinct values written in practice.

The cautionary tale is Ghidra's own IDA bridge: `idaxml.py` defines a
`SOURCE_TYPE` constant and **never writes it**. Provenance existed at the source,
had a slot in the target schema, and was dropped in transit anyway. Any format
we design has to make that failure mode impossible rather than merely
discouraged.

---

## 4. Recommendation

### Adopt
1. **WARP for function identity and type transfer.** Emit `.warp`; use its
   function GUID as our content-addressed entity id instead of inventing one.
   Buys Binary Ninja interop for free and replaces about half of what would
   otherwise be ours to design.
2. **BinExport2** as a writer — the de-facto whole-binary interchange, and the
   entry ticket to BinDiff, capa and VxSig.

### Adapt
3. **SARIF 2.1.0** for L1–L5 findings, which is what it is actually for.
   *(Reported: Ghidra's SARIF path has 20 round-trip test classes against real
   binaries where its XML exporter has none, and bitfields and packing survive
   SARIF but not XML.)*
4. **Borrow, don't invent**: WARP's `ancestors` type-version lineage so stale
   references can migrate forward; Binja's multiplicative confidence
   composition; IDA's auto-but-meaningful name state.

### Design ourselves
What is genuinely unoccupied after all of the above is narrower than it first
looked, and therefore worth doing properly:

5. **Evidence citation** — per-fact `set_by` + `confidence` + `set_at` +
   `cites[] → evidence_log`. No surveyed format carries *why* a fact is believed,
   only how much.
6. **The verification record** — we recompile decompiled output and diff its
   execution against the original. Nothing else surveyed has anywhere to put
   "this body was proven equivalent to the original at these inputs," and it is
   the strongest claim we can make about any function.
7. **Decompiled code with statement-level anchors back to addresses** — the
   thing Glaurung exists to produce, currently persisted nowhere.

### Prerequisite for all of it
8. **Serde on `src/program/` and `src/ir/`.** Until the program model can leave
   the process, every export is a hand-written shadow of it. This is the item
   that unblocks the rest, and it is invisible from the outside.

---

## 5. Not verified

- WARP's absence of `Function`/`Symbol` provenance — read from a survey, not
  from `signature.fbs` and `symbol.fbs` directly.
- Every IDA, Ghidra-upstream, Binary Ninja and BinDiff claim in §3, and the
  SARIF round-trip claim in §4. Primary sources were cited by the survey but I
  read only the WARP ones myself.
- Whether `reference/ghidra` in this repo is stale: reported as a graft at
  `7a4100d5` (2025-08-27, `application.version=12.0`) against an upstream
  12.1.3. **If true, no conclusion about current Ghidra should be drawn from
  that tree without an upstream check** — worth confirming before it misleads
  someone.
- A reported live defect: `export.py`'s IDA emitter calls `int.__iadd__`, which
  does not exist, and would raise `AttributeError` for every non-default-named
  stack var. Read, not executed — no IDA here.
