# What analysts expect, ranked — Glaurung against IDA Pro, Ghidra, and angr

> **Method.** Every competitor claim below is traced to a primary source: the Ghidra
> source tree at `master@9f377f1cbd79`, the angr / angr-management trees at
> `master@72c3b454` / `aab96b51`, and Hex-Rays' own documentation at
> `docs.hex-rays.com` / `cpp.docs.hex-rays.com`. Where docs and source disagreed
> the source won and the disagreement is noted. The **Glaurung** column was
> *measured* on 2026-08-28 by probing the shipped CLI against a real binary, not
> recalled from memory — including the two places where probing contradicted what
> this repository's own docs claimed.
>
> Empirical grounding for "what analysts actually do" is Votipka et al., *An
> Observational Investigation of Reverse Engineers' Processes*, USENIX Security
> 2020 (16 professionals observed) and Mattei et al., *A Qualitative Evaluation of
> Reverse Engineering Tool Usability*, ACSAC 2022 (288 tools evaluated).

## 0. The two numbers that set the bar

From the ACSAC 2022 heuristic evaluation of 288 RE tools:

- **48% do not report results in the context of code.** Of *standalone* tools only
  **22%** (11/50) meet that guideline, versus **58%** (139/238) of plugins.
- Only **26%** list a function's cross-references at all.

Glaurung is a standalone tool. The 22% figure is the one to design against, and it
is why §2's ranking puts addressability above everything except renaming.

From USENIX 2020, the behaviours actually observed (N of 16): determining relevant
output 16, **renaming variables 14**, **taking notes / annotating 14**,
reconstructing data structures 8. And the sentence that should govern a CLI-first
tool: analysts list strings and API calls in a disassembler (N=15) *"as opposed to
using the command-line `strings` command (**N=0**)"* — not because `strings` is
bad, but because its output is not anchored to code.

## 1. Scorecard

Legend: **●** full · **◐** partial · **○** absent. Glaurung entries marked
*(2026-08-28)* landed in this work.

| # | Capability | IDA Pro | Ghidra | angr | **Glaurung** |
|---|---|:--:|:--:|:--:|:--:|
| 1 | Rename function, reaching every call site | ● | ● | ● | **●** *(2026-08-28)* |
| 2 | Rename / retype a local, reaching the body | ● | ● | ● | **◐** *(2026-08-28 — needs a type; see §3.2)* |
| 3 | Function prototype drives the rendered signature | ● | ● | ● | **●** *(2026-08-28)* |
| 4 | Comments on the decompiled function | ● | ● | ◐ | **◐** *(2026-08-28 — anchored, not placed)* |
| 5 | **Line → address map** | ● | ● | ● | **○** |
| 5b | Per-variable machine addresses | ● | ● | ● | **●** *(2026-08-29)* |
| 6 | Cross-references queryable from pseudocode | ● | ● | ◐ | ◐ |
| 7 | Apply a struct to a variable (`base->field`) | ● | ● | ◐ | ○ |
| 8 | Split / merge a variable | ● | ◐ | ○ | ○ |
| 9 | Per-call-site prototype override | ● | ● | ○ | ○ |
| 10 | Code labels (named jump targets) | ● | ● | ● | ○ |
| 11 | Numeric format / equates | ● | ● | ◐ | ○ |
| 12 | **Ranked provenance, enforced** | ○ | ◐ | ○ | **●** |
| 13 | **Undo across every annotation type** | ◐ | ◐ | ○ | **●** |
| 14 | Analyst state readable without decompiling | ● | ◐ | ● | ● |
| 15 | Store openable with standard tooling | ○ | ○ | ● | ● |
| 16 | Non-interactive edit surface | ● | ● | ● | **●** *(2026-08-28)* |
| 17 | Staged / resumable pipeline | ○ | ○ | ● | ○ |
| 18 | Concurrency safety on the project | ◐ | ● | ○ | ○ |

## 2. The ranking, and why

Ordered by *cost to an analyst of not having it*, which is not the same as
implementation difficulty.

### Tier 1 — the tool is a report generator without these

**1. Rename, reaching every use.** The single most common action (14/16). Ours now
reaches the definition, the extern declaration, and every call site, following
`@plt` aliases — verified byte-for-byte identical to the un-renamed output apart
from the name. **Done.**

**2. Line → address mapping.** The enabling primitive for everything else, and the
one capability all three competitors have and we do not.

- *Ghidra* derives it rather than tabulating: `ClangOpToken.getMinAddress()` is
  `op.getSeqnum().getTarget()`, recomputed per call. It is candid that this is
  lossy — `DecompilerPanel.setLocation` says *"multiple tokens can share an
  address, we woudln't know which token is best"* and *"not all fields have an
  address value"* — and falls back through `getClosestAddress` →
  `findAddressBefore` → **the function entry point**.
- *IDA* stores `treeloc_t{ea_t ea; item_preciser_t itp}`.
- *angr* keeps bidirectional `map_pos_to_addr` / `map_addr_to_pos` on the codegen.

Ours dies at `lower_block`, which calls `lower_op(&ins.op, ..)` and drops
`ins.va`. `ast::Function` carries only `entry_va`; the sole in-body anchors are
`Stmt::Label(u64)` for goto targets, which a well-structured function does not
emit. **This is the #1 gap and the top of the work queue.** §4 has the design.

**A correction, 2026-08-29.** This section originally treated that as blocking
per-variable `addresses` too. It does not, and the conflation cost us the
capability for months. A line map needs AST-node-to-instruction lineage; a
variable-to-address map joins on the frame COORDINATE, which `stack_locals`
publishes and the LLIR still carries alongside the machine `va` — no node
identity required. dewolf and Reko ship exactly that shape (direct addresses, no
line map) and DecBench's ingest counts it as a first-class case. Row 5b is now
`●`; row 5 is still `○`, and the two are genuinely different problems.

**3. Prototype drives the signature.** Hex-Rays: setting the callee's type *"will
cause changes to all places where `off_5C6E4` is called"*. Ours now does —
measured `int validate(char*, int)` → `unsigned int validate(const unsigned char*,
short)`. **Done**, with a caveat in §3.3.

**4. Retype a local, reaching the body.** Ours does, and the retype genuinely
propagates: `return (unsigned int)(local_c)` becomes `return running_total`, the
cast gone because the declared type now matches. **Partial** — see §3.2.

**5. Comments.** 14/16 annotate. Both incumbents have instructive failures here;
§3.1 is why our design is deliberately different rather than behind.

### Tier 2 — the difference between usable and pleasant

**6. Apply a struct to a variable.** All three have it; we store `c_type` as a
string and resolve it against nothing. `type_field_uses` exists in our schema with
no production reader or writer.

**7. Split / merge a variable** — undoing the decompiler's speculative merging.
Ghidra's own issue **#975 is the most-reacted open issue in its tracker (54
reactions, open since 2019)**; #2573 (stack vars) has 47. IDA has both directions
and is explicit that it does not verify them: *"the decompiler does not verify the
mapping. A wrong mapping may render the decompiler output incorrect."* Ghidra has
split as an action but **merge has no action, no keybinding, and no documentation**
— it is a `name$1`/`name$2` string convention in `LocalSymbolMap`, whose own
inline comment mis-states the delimiter as `@`.

**8. Per-call-site prototype override.** IDA has three distinct mechanisms
(`hx:SetCallType`, `hx:ForceCallType`, `hx:UserDefinedCall`); Ghidra has
`OverridePrototypeAction`, storing a `FunctionDefinitionDataType` in a namespace
literally named `"override"`.

**9. Code labels.** Our `data_labels` is globals-only. Note IDA retrofitted a
*second, more stable* anchoring strategy for labels specifically —
`save_user_labels(..., const cfunc_t*)` is documented as saving *"using a more
stable method that preserves them even when the decompiler output drastically
changes"* — and did **not** do the same for comments.

### Tier 3 — force multipliers we can defer

Numeric formats/equates, a staged pipeline, cross-decompiler artifact interchange.

## 3. Where we are already ahead, and why it is not an accident

These are the entries where the incumbents' documented behaviour is worse than
ours. Stating them precisely matters as much as stating the gaps.

### 3.1 Comment anchoring — we chose the design both failures point at

*IDA* anchors line and block comments to `(ea, item_preciser_t)` and has said so
in shipped documentation since 2008, unchanged:

> "Some output lines will not have a coordinate in this system. You cannot edit
> comments for these lines. Also, some lines have the same coordinate… **We will
> try to overcome this limitation in the future but it might take some time and
> currently we do not have a clear idea how to improve the existing coordinate
> system.**"

Orphaned comments are dumped at the end of the function, and `hx:DelOrphanCmts`
exists to garbage-collect them — an action whose own doc page contains a title and
nothing else. Igor's tip #43 states the split plainly: line and block comments
*"can move around or even end up as orphan comments"*, while **the function
comment is attached to the function itself** and never orphans.

*Ghidra* is worse in one specific case. `CommentSorter::findPosition` returns
`false` — `// Basic block containing comment has been excised` — and the comment is
**silently and unrecoverably dropped**, with no warning naming it. The escape hatch
that would re-home it (`setDisplayUnplaced`, printing *"Comments that could not be
placed in the function body:"*) has **zero callers in the entire repository**;
`option_unplaced` is `false` at initialisation and never assigned.

We anchor the function comment to the function — the one kind IDA reports as
stable — and *list* interior comments with their addresses instead of guessing a
line. That is a smaller feature than either incumbent's and a **more honest** one:
a plausible wrong placement reads as fact and mis-attributes the analyst's note to
unrelated code. When §4 lands a line map, interior placement becomes available
without changing the anchoring model.

### 3.2 Provenance — ours is enforced; Ghidra's is advisory and IDA's is one bit

**Ghidra.** `SourceType` is a real 5-constant priority lattice
(`DEFAULT 1 < ANALYSIS 2 = AI 2 < IMPORTED 3 < USER_DEFINED 4`) — but
`SymbolDB.doSetNameAndNamespace` **never compares the incoming SourceType against
the existing one.** It reads `getSource()` only to pass along to external-location
bookkeeping. The only gate is DEFAULT/non-DEFAULT. Enforcement lives in
**19 scattered caller sites**; a plugin calling
`symbol.setName(x, SourceType.ANALYSIS)` overwrites a `USER_DEFINED` name without
complaint. And **comments carry no provenance at all** —
`CodeUnit.setComment(CommentType, String)` takes no `SourceType`.

**IDA** is two-valued: user vs auto, surfaced as blue vs gray type text and a flags
bit behind `has_user_name()` / `has_auto_name()`. It cannot tell you whether a
stored name came from DWARF, a FLIRT signature, a PDB, or propagation. Lumina's
push filter uses that same single bit as a quality gate — skip anything still
`sub_XXXX` or under 32 bytes.

**angr** has no general model: one enum for prototypes (`prototype_source`), and
`SimVariable.renamed` is polluted — of its seven writers, four are automatic
(symbol import, semantic naming), so it means *"has a non-default name"*, not
*"a human set this"*.

**Ours** is a 7-value ranked ladder enforced inside every setter, so no caller can
bypass it. Ghidra shipped the value-equality version for years and had to retrofit
priority comparison (commit `a3bd708160cf`, GP-6008); we skipped that retrofit. We
also repeated — and caught — their exact mistake in miniature: Ghidra added a
`Speculative` rung *below* analysis on 2025-09-18 and reverted it on 2025-09-19;
we ranked `borrowed` below the heuristics, which silently disabled
`borrow_symbols`, and moved it to parity for the same reason.

**Still missing, and named:** Ghidra needs *both* `SourceType` **and** separate
`namelock`/`typelock` bits because they answer different questions — *who asserted
this* versus *may the solver re-infer it*. We conflate them. Worth knowing before
copying: Ghidra's locks are **not stored**; they are recomputed on every decompile,
and for parameters partly by string prefix (`!name.startsWith("local_") &&
!name.startsWith("param_")`), so an analyst who names a parameter `param_count`
silently loses its namelock.

### 3.3 Undo

**angr has no undo or redo anywhere** — `QCCodeEdit` explicitly calls
`remove_action(self.action_undo)`, and there is no edit log in either repo. IDA's
equivalent is *"Reset decompiler information"*, a per-category destructive reset,
not an undo. Ours snapshots every analyst write into `undo_log` across five tables,
reversible by a single `glaurung undo` regardless of which surface produced it —
including deletions, as of this work.

## 4. What to do next, in order

1. **The line map.** Not free: `Expr`/`Stmt` derive `PartialEq, Eq` and have no
   node identity, and `prepare.rs` terminates a fixpoint on `if owned == before`.
   The cheap shape is a marker **variant** (`Stmt::Origin(u64)`), not a field —
   a variant costs 182 exhaustive-match sites that the compiler finds, whereas a
   field on `Stmt::Assign` alone costs 1,472 construction sites. The hazard is
   passes that *skip over* marker statements (`return_folds.rs` already does this
   for `Comment | Nop`); missing one is a silent behaviour change, so each site
   needs reading rather than a sweep. Ghidra's precedent says the result may be
   approximate and should say so.
2. **Apply a struct to a variable.** `type_field_uses` already exists unused.
3. **Split / merge a variable.** Highest *demand* signal of anything here.
4. **Per-call-site prototype override.** Our `call_spec` on `Stmt::Call` is the
   natural home.
5. **Code labels**, borrowing IDA's lesson that labels deserve the stable anchor.
6. **Lock bits**, separated from provenance rank — and stored, not re-derived.

## 5. Two corrections this exercise forced

- `docs/cli/analyst-ergonomics.md` claimed `disasm --db` symbol-resolved call
  targets. It did not, until 2026-08-28.
- An audit script reported that we have lock bits. The grep had matched our own
  docstring *describing Ghidra's*. Measured again: we do not. The parity doc was
  right and the probe was wrong — recorded because a self-audit that flatters is
  worse than none.
