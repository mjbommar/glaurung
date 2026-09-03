# Source-CFG front end: lifted requirements

> **Kind:** design · **Status:** proposed

Requirements for the Glaurung C front end: a component that turns C source text
into per-function control-flow graphs, one of whose outputs must score
identically to Joern's under DecBench's GED metric. Requirements about Joern's
behaviour are lifted from [`joern-behavior.md`](joern-behavior.md); the
programme is [`roadmap.md`](roadmap.md), the code layout is
[`architecture.md`](architecture.md), and the gates for the parity milestone are
[`parity-plan.md`](parity-plan.md).

Nothing here is built. Requirements are stated so that each one names the
observation it comes from and the check that would falsify it.

## 0. The parity bar, stated once

`cfgutils.similarity.vj_ged` reads only two things from a CFG: the multiset of
per-node `(in_degree, out_degree)` pairs, and each node's `is_entrypoint` /
`is_exitpoint` flags (§2 of [`joern-behavior.md`](joern-behavior.md)). Node
identity, labels, statements, addresses and the actual wiring are invisible.

That gives a hard bar and a soft one:

* **Hard (what DecBench can see).** For every scored function, our CFG's
  multiset of `(in_degree, out_degree, is_entrypoint, is_exitpoint)` tuples
  equals Joern's. Meeting this reproduces every GED value exactly.
* **Soft (what we should still build).** A CFG that is *actually* right —
  correct successors, not merely correct degrees — because the artifact is
  worth more to Glaurung than the score is, and because a future metric change
  could start reading topology.

Requirements below are written against the soft bar. The hard bar is what the
gates measure, because it is what is externally checkable.

## 0.0 Two layers, and which requirements belong to which

This contract covers two things that must not be confused, and which
[`architecture.md`](architecture.md) §1 keeps in separate modules:

* **The general front end** — a tokenizer, an AST, a parser and a *correct*
  control-flow graph. It outlives the metric, it is what
  [`roadmap.md`](roadmap.md) stages S4 onward build on, and it is judged on
  coverage and on invariants that hold for any well-formed C.
* **The parity layer** — the part that reproduces Joern's artifacts, faithfully
  and deliberately, so a GED value comes out identical. It is judged on one
  number and nothing else.

| requirement group | layer |
|---|---|
| REQ-IN-*, REQ-NORM-*, REQ-GEN-* | general |
| REQ-CFG-1, 3, 4, 5, 6, 7, 11 | general (the parity layer adds granularity and coalescing on top) |
| REQ-CFG-2, 8, 9, 10, REQ-SEL-*, REQ-OUT-1 | parity only |
| REQ-API-*, REQ-ROB-*, REQ-PERF-*, REQ-OUT-2, 3, 4 | both |

A requirement marked parity-only is permitted to be strange. A requirement
marked general is not: it is the thing that gets reused, and a Joern quirk
smuggled into it is a defect with a long tail.

## 0.1 General-layer requirements

These have no counterpart in Joern's behaviour; they exist because the front end
is a Glaurung component, not a metric adapter.

**REQ-GEN-1 — The CFG is correct, not merely scored.** Every node is reachable
from the entry; every path reaches the function end or a diverging construct;
back edges correspond to source loops; `break` and `continue` target the
enclosing construct; a `switch` fall-through is an edge. These invariants hold
for the general CFG. They do **not** all hold for the parity layer's output —
which is the reason the two are separate.

**REQ-GEN-2 — Source positions survive.** Every AST node and every CFG node
carries a byte span into the original text, so a finding can be pointed at a
line and a function can be extracted exactly. This is what replaces
`tools/roundtrip_review.py`'s brace-matching regular expression, whose own
docstring records the IOU: "A real parser would be more robust and is not what
makes this useful."

**REQ-GEN-3 — No linked dependency and no `unsafe`.** `src/csource/` adds
neither. See [`architecture.md`](architecture.md) §5 for why this line is worth
holding in a crate that already links capstone and mimalloc.

**REQ-GEN-4 — Explicit-stack traversal.** The lexer and parser use explicit
stacks, never native recursion, so adversarial nesting depth cannot overflow the
stack. A process that aborts cannot report a per-function failure, which is the
whole-file voiding mode this programme exists to remove.

**REQ-GEN-5 — The AST is lowerable.** The AST retains enough structure —
declarations, initializers, types as written, storage classes, and the
distinction between an expression statement and a declaration — that
[`roadmap.md`](roadmap.md) stage S4 can lower it to `LlirFunction` without
re-parsing. The parity layer needs none of this; the general layer must not drop
it just because the first consumer does not read it.

## 1. Inputs

**REQ-IN-1 — Two input dialects, one parser.** The component accepts (a) gcc
preprocessed output (`.i`), and (b) decompiler-emitted C from any backend. It
must not require the two to be separately configured beyond the normalization
switch of REQ-NORM-2.

**REQ-IN-2 — Already-preprocessed input only.** No `#include` resolution, no
macro expansion, no `#if` evaluation. gcc has already done all three for `.i`,
and decompiler output has no preprocessor directives. A `#`-prefixed line is
either a gcc line marker (REQ-NORM-1) or is skipped.

**REQ-IN-3 — GNU C surface.** The parser accepts the constructs gcc leaves in
`.i` output: `__attribute__((...))`, `__extension__`, `__restrict`, `__inline`,
`asm`/`__asm__` (including basic and extended forms), `__typeof__`, statement
expressions `({ ... })`, designated initializers, `_Bool`, `_Static_assert`,
`__int128`, computed `goto` with `&&label`, and anonymous struct/union members.

**REQ-IN-4 — Ill-formed input must not abort the file.** Decompiler C contains
tokens that are not C at all (`undefined4`, `GLIBC_2.2.5::stderr`,
`__usercall`, `@ rax` before sanitization). A construct the parser cannot model
degrades to an opaque straight-line item; it never terminates the parse of the
enclosing function, and never terminates the file.

*Falsified by:* any input in the 1,606 stored decompiled `.c` artifacts of the
materialized tree for which the component yields zero functions where Joern
yielded some.

## 2. Text normalization

These are ports of pure functions in `decbench/utils/cfg.py` and must be
byte-exact, because a divergence changes what is parsed and therefore every
downstream number.

**REQ-NORM-1 — `strip_system_headers`.** Given `.i` text, keep only lines whose
governing `# <line> "<file>"` marker names a file that is not empty, does not
start with `<`, does not start with `/usr/`, does not contain `/usr/lib/gcc`,
and does not end with `stdc-predef.h`. Markers themselves are dropped. The
result is joined with `\n` and gets one trailing newline. State starts as
*inside a system header*, so text before the first marker is dropped.

**REQ-NORM-2 — `sanitize_decompiled_c`, decompiled side only.** Apply, in order:
the line-anchored aggregate-return rewrite `^([A-Za-z_][\w ]*?)\s*\[\d+\]\s+([A-Za-z_]\w*\s*\()` →
`\1 \2`; register-annotation strip `\s*@\s*[a-z]\w+\b`; `unsigned __int128` →
`unsigned long long` then `__int128` → `long long`; and literal control-byte
escaping. It must be impossible to apply this pass to a `.i` input.

**REQ-NORM-3 — `escape_literal_control_bytes`.** Inside string and char literals
only, every byte `< 0x20` or `== 0x7F` other than tab and newline becomes
`\xNN`. Backslash escapes are honoured so `"\\"` does not open a literal. This
is a correctness requirement, not cosmetic: it is what stops one binary's
`.rodata` from voiding a whole file's CFGs.

**REQ-NORM-4 — Encoding tolerance.** Input is read with replacement on invalid
UTF-8, matching `read_text(errors="replace")`.

## 3. CFG construction

**REQ-CFG-1 — One node per CFG-relevant construct, in evaluation order.** Build
at Joern's granularity first and coalesce second (REQ-CFG-8), rather than
emitting basic blocks directly. Two reasons: an empty region between two forks
is a node in Joern and would be elided by direct block emission; and
node-granular output can be diffed against the `labels` field of the published
CFGs, which is the only statement-level oracle available.

**REQ-CFG-2 — Function boundaries.** One CFG per function *definition*. A
declaration without a body yields nothing. The graph carries a
`Nop(FUNC_START)` node before the body and a single shared `Nop(FUNC_END)` node
that every `return` and the fall-off path targets.

**REQ-CFG-3 — Straight-line statements.** Declarations with initializers,
expression statements, and assignments are single-successor nodes chained in
source order. Declarations without initializers contribute nothing.

**REQ-CFG-4 — Selection.** `if` forks on its condition node: successor 0 the
then-arm entry, successor 1 the else-arm entry or the join. `switch` produces
one selector node whose successors are the distinct jump targets — one per
`case`/`default` label group, plus the fall-out target when no `default` exists.
Fall-through between cases is an ordinary edge.

**REQ-CFG-5 — Iteration.** `while` and `for` place the condition as a node with
two successors (body entry, loop exit) and a back edge from the body tail;
`for`'s init precedes the condition and its update precedes the back edge.
`do`/`while` places the condition after the body. `break` and `continue` are
unconditional edges to the enclosing loop's exit and continue targets.

**REQ-CFG-6 — Short-circuit and conditional operators.** `&&`, `||` and `?:` are
control flow, not expressions. For `a && b`: node `a` forks to node `b` and to
the `&&` operator node; node `b` flows to the `&&` node; the `&&` node carries
the branch. `||` is the mirror. `?:` forks on its condition to the two arms,
which join at the conditional node. This is the requirement most likely to be
got wrong by an expression-oriented front end, and it costs three nodes and four
edges per operator.

**REQ-CFG-7 — `goto` and labels.** A `goto` is an unconditional edge to its
label's node; a label with no reaching fall-through still gets a node. Computed
`goto` (`goto *p`) has an unknown target set: it must not silently produce an
edge-free node, since that changes the degree sequence. Record the divergence
explicitly rather than guessing.

**REQ-CFG-8 — Coalescing.** Merge `src → dst` whenever `src` has exactly one
successor and `dst` exactly one predecessor, to fixpoint, excluding self-edges.
Merged blocks concatenate statement lists in order and OR the entry/exit flags.

**REQ-CFG-9 — Entry and exit flags are derived.** A block is an entry point iff
it contains a `Nop(FUNC_START)`; an exit point iff it contains a
`Nop(FUNC_END)`. For unmerged blocks the check is position-sensitive (first
statement for entry, last for exit); for merged blocks it is membership. The
published corpus shows 0 functions with no entry flag and 1,334 with more than
one, so multi-entry is legal output and must not be normalized away.

**REQ-CFG-10 — Singleton funcend removal.** After coalescing, if there is
**exactly one** block with `out_degree == 0`, exactly one statement, and that
statement a `Nop(FUNC_END)`, delete it — and with it, its in-edges. Otherwise
keep it. This rule alone decides whether 49.0% of functions have an exit-flagged
node, and getting its guard conditions wrong changes both the node count and the
in-degrees of every `return` block.

**REQ-CFG-11 — Unparsed regions keep their node.** A construct that degrades
under REQ-IN-4 still emits a node, so a parse gap costs fidelity but not a node
count.

## 4. Function selection and resolution

**REQ-SEL-1 — Name blacklist.** Drop functions whose name begins with `<`, `+`,
`*`, `(`, `>`, `JUMPOUT`, or `__builtin_unreachable`, and apply the same filter
to recorded callees.

**REQ-SEL-2 — Duplicate names.** For a repeated `(name, file)`, keep the CFG
with more nodes.

**REQ-SEL-3 — Degeneracy verdict.** A CFG is degenerate iff it has zero nodes,
or exactly one node all of whose statements are `Nop`. A one-block function with
real statements is not degenerate. The verdict must be exported, because the
offline path depends on it.

**REQ-SEL-4 — Per-TU resolution.** Given `{tu_stem: {name: cfg}}` and a target
binary stem, prefer the binary's own TU for each name it defines
non-degenerately, and fall back to the cross-TU non-degenerate largest CFG
otherwise. Port `best_source_by_name` and `resolved_source_for_binary` exactly;
their prior bug capped offline GED coverage at ~39%.

## 5. Output

**REQ-OUT-1 — DecBench serialization, byte-compatible.** Emit the
`decbench/publish/cfg_export.py` shape per binary:

```jsonc
{"opt": …, "project": …, "binary": …, "generator": "glaurung-<sha>",
 "functions": {"<name>": {"nodes": [int], "edges": [[int,int]],
                          "labels": {"<i>": "<block dump>"},
                          "entry": [int], "exit": [int], "degenerate": bool}}}
```

Nodes are relabelled `0..n-1` in a stable order. This makes the output a drop-in
for DecBench's `--source-cfgs` flow with no DecBench change.

**REQ-OUT-2 — Native form.** A Rust type usable inside Glaurung without the JSON
round trip, and a PyO3 view of it, so the component is callable from the
decompiler loop and not only from a file-based harness.

**REQ-OUT-3 — Determinism.** Byte-identical output for identical input across
runs, machines and thread counts. Node ordering is derived from source position,
not hash iteration order. This is a hard requirement because the whole parity
argument is a diff.

**REQ-OUT-4 — Diagnosable divergence.** Every function carries enough provenance
(per-block source line range and statement dump) to localize a degree-sequence
mismatch to a construct without re-running anything.

## 6. Interfaces

**REQ-API-1 — Rust.** `glaurung::csource::cfgs_from_source(text, dialect) -> Result<BTreeMap<String, SourceCfg>>`,
pure and side-effect free, no filesystem access.

**REQ-API-2 — Python.** A binding mirroring the Rust surface, plus file-level
helpers matching DecBench's two entry points, so a shim can substitute
`extract_cfgs_from_source` and `extract_cfgs_from_decompilation` in-process.

**REQ-API-3 — CLI.** `glaurung source-cfg <file>` with `--json`, `--dialect
{preprocessed,decompiled}`, and a summary mode. Adding it drifts a tutorial
fixture — refresh with `scripts/verify_tutorial.py --chapter 01-install
--capture` and read the diff.

**REQ-API-4 — Optional GED.** A native `vj_ged` so Glaurung can score a
structural distance without DecBench present. The cost matrix depends only on
degree classes, so the assignment can be solved over distinct
`(in, out, entry, exit)` classes rather than over nodes — `O(k³)` in the number
of distinct classes, not `O(n³)`.

## 7. Robustness and performance

**REQ-ROB-1 — No worse than Joern's loss rate.** Source side: at most 5.01% of
functions lost (Joern's published rate). Decompiled side, on Glaurung's own
output: at most the best rate any decompiler currently gets from Joern
(kuna, 0.00%; ghidra, 0.04%).

**REQ-ROB-2 — Failure is per-function.** No single function's parse failure may
void another function, and none may void the file. This is a direct correction
of the observed whole-file voiding mode.

**REQ-ROB-3 — Bounded work.** A pathological input terminates. No unbounded
recursion on deeply nested expressions; no super-linear blowup on long
straight-line bodies.

**REQ-PERF-1 — Order-of-magnitude target.** The 56-cell matrix gate currently
costs ~37 minutes, dominated by one JVM per cell. Target: the same 56 cells in
under one minute of CFG extraction, and a single median TU in under 10 ms
(release build). State the build with every measurement — `maturin develop` is
debug.

**REQ-PERF-2 — No new heavyweight dependency.** Whatever parser strategy is
chosen, the wheel must not gain a JVM, a 1.9 GB asset, or a network fetch at
runtime.

## 8. Explicit non-requirements

Naming these keeps the component small; each is something Joern does that
DecBench's GED cannot see.

* **No CPG.** No AST, DDG, PDG, call graph, type hierarchy or query language.
* **No type resolution.** `type_match` reads DWARF, not Joern.
* **No JIL statement fidelity.** 69.2% of Joern's own statement lines are
  `UnsupportedStmt`. Only the `Nop` distinction is load-bearing (REQ-CFG-9).
* **No C++, and no other language.** The corpus is C; the two C++ CPS projects
  are disabled upstream for exactly this reason.
* **No semantic analysis.** Unreachable code is still CFG; `noreturn` calls do
  not terminate a block; constant conditions are not folded. Joern does none of
  these, and doing them would *lose* parity.
* **No attempt to beat Joern.** A "better" CFG that scores differently is a
  regression against this component's purpose. Improvements go behind an
  explicit non-parity mode, if at all.

## 9. Open questions

1. **Parser strategy.** A hand-rolled tolerant recursive-descent parser owns its
   error recovery and adds no dependency; `tree-sitter-c` gets to coverage
   faster but its recovery would still have to be tuned toward Eclipse CDT's.
   The declaration-vs-expression ambiguity that normally forces typedef tracking
   is mostly harmless here — both readings of `A * b;` are one straight-line
   item with the same degree contribution — which materially lowers the cost of
   hand-rolling. Decide with the Phase-1 coverage measurement, not in advance.
2. **Computed `goto`.** yyparse-style tables appear in the corpus. Whether to
   model the target set, over-approximate, or record an abstention changes the
   degree sequence; measure the population before choosing.
3. **Source-side `.i` regeneration.** The published tree ships no `.i` files, so
   direct source-side comparison needs either a recompile (gcc, not Joern) or a
   small committed fixture corpus. See [`parity-plan.md`](parity-plan.md) §2.
4. **Whether to reimplement `vj_ged`** (REQ-API-4) in this component or leave
   scoring to DecBench. Reimplementing removes the last runtime dependency for a
   local structural gate; it also creates a second authority for a number the
   upstream owns.
