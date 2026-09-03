# Source front ends: the shared substrate

> **Kind:** design · **Status:** proposed

Glaurung will read more than one language before this is done — C first, then
inline assembly inside it, then possibly C++ and Rust. This directory designs
what those front ends **share**, and argues carefully about what they do not.

The first consumer is the C front end planned in
[`static-c-analysis/`](../static-c-analysis/README.md). Nothing here is built
and nothing here is scheduled; the live plan is
[`development/roadmap/`](../../development/roadmap/README.md).

| document | what it holds |
|---|---|
| [substrate.md](substrate.md) | `src/syntax/` — the language-neutral layer: source maps and spans, interning, the struct-of-arrays token buffer and AST, the event-stream parser interface, the error model, error-recovery primitives, and the language-neutral CFG builder. Requirements `REQ-SYN-*` and components `SB-*` |
| [benchmarks.md](benchmarks.md) | the four-axis harness — throughput, latency, coverage and determinism — the corpora it runs on, the targets, the ratchet, and the reporting discipline |

## 1. It is not four parsers

The premise worth testing before building anything is "we will need C, C++, Rust
and assembly." Measured against what this repository actually holds and actually
needs, that resolves to roughly **one and a half hand-written parsers**.

| language | fixtures in `tests/decompiler_fixtures/src/` | what Glaurung actually needs | verdict |
|---|---|---|---|
| **C** | 196 `.c` | parse it, build CFGs, lower to LLIR, score GED against it | hand-write. This is the real one |
| **assembly** | — | **already required inside C.** `144_inline_asm.c` and `208_flag_register_roundtrip.c` carry `__asm__` with constraints and clobbers, and inline asm is control-flow relevant | needed now, but line-oriented and directive-driven, over ISA tables the crate already owns. Not a recursive-descent parser |
| **C++** | 10 `.cpp` | upstream DecBench keeps its two C++ projects disabled because the pipeline has no C++ support; the decompilers we compare against emit C-shaped output, not C++ | **defer, possibly permanently.** Templates, the `>>` ambiguity, the most vexing parse and ADL make it several times the cost of C for 5% of the corpus |
| **Rust** | 7 `.rs` | those files are *inputs to rustc*. The Rust interest here is DWARF types recovered from Rust **binaries** (`python/tests/test_decompiler_rust_source_types.py`), not Rust source | **do not hand-write.** If source ever matters, `syn` is pure Rust, mature, and better than anything written here |

Counts from `ls tests/decompiler_fixtures/src/*.{c,cpp,rs} | wc -l` at `935b7db1`.

This matters because infrastructure sized for four languages would be
over-built, and the over-build has a recognizable shape: a grammar DSL, a parser
combinator layer, a generic `Language` trait, a plugin registry. None of those
can be designed correctly from zero working instances, and all of them are
tempting when the brief says "multi-language."

## 2. What generalizes, and what does not

The parts that generalize are the parts **around** the grammar, not the grammar.

| shared | why | first consumer |
|---|---|---|
| source map and spans | byte offsets and line/column are language-neutral | diagnostics, `REQ-GEN-2` function extraction |
| symbol interning | `Symbol(u32)` is language-neutral; the sibling `axeyum` crate's `TermArena` already establishes the pattern | lexer, AST, CFG |
| struct-of-arrays token buffer | the *mechanics* generalize; the token kinds do not | every lexer |
| arena AST with `u32` handles | the *pattern* generalizes; the node tags do not | every AST |
| diagnostics and the error model | `(T, Vec<Error>)`, never `Result<T, E>` | every parser |
| error-recovery primitives | synchronizing sets, explicit-stack traversal, bounded depth | every parser |
| **the CFG builder** | control-flow events — statement, branch, loop header, break, continue, goto, return — are **nearly identical across C, C++ and Rust** | C, then anything else |
| **LLIR as the lowering target** | already exists, already shared, already has an interpreter and a symbolic domain over it | C → LLIR (stage S4) |
| the corpus and benchmark harness | language-neutral | C |

Not shared, and not worth trying to share: grammars, type systems, name
resolution, and anything that reads a declaration's meaning rather than its
shape.

The two entries in bold are the real unification points. A second language front
end that emits the same control-flow events and lowers to the same LLIR is
cheap; one that ships its own CFG type is a second project wearing the first
one's name.

## 3. Adopt or build: three decisions with evidence

**`rowan` — steal the design, skip the dependency.** rust-analyzer's syntax
tree library is pure Rust, lossless, error-tolerant and genuinely
language-agnostic. But losslessness is a property built for *incremental IDE
editing*: untyped green nodes that need a typed AST layer above them, and
interning costs paid to preserve trivia. Our consumers want a **lowerable** AST
(stage S4 lowers to LLIR), not a faithful concrete syntax tree. What is worth
taking is the architectural invariant, not the crate — see §4.

**`logos` — skip.** The lexer generator compiles token definitions into a
single DFA at compile time. In a published head-to-head a hand-written lexer
came out *ahead* — 201,148 ns/iter against logos's 221,110 — so it buys
convenience rather than speed, at the cost of a proc-macro dependency. A
hand-written lexer over the substrate in [substrate.md](substrate.md) is
competitive and adds nothing to the dependency graph.

**`syn` — adopt, if Rust source ever matters.** Pure Rust, mature, and solving
a problem nobody here should re-solve. The same applies to any
already-excellent single-language parser: the substrate exists to make *our*
front ends cheap, not to make every language ours.

The C parser decision — hand-written rather than `lang-c` or `tree-sitter-c` —
is made and evidenced in
[`static-c-analysis/architecture.md`](../static-c-analysis/architecture.md) §4.

## 4. The one idea worth taking wholesale

rust-analyzer's parser architecture, on two points.

**The parser emits a flat stream of events**, not a tree. `TokenSource` and
`TreeSink` bridge it to whatever representation the caller wants, under the
stated invariant that "the parser is independent of the particular tree
structure and particular representation of the tokens." This is what makes a
second language cheap *without* a framework: a new grammar module emits the same
events, and the tree builder, the CFG builder, the diagnostics and the
benchmarks are already there.

**Parsing never fails.** "The parser produces `(T, Vec<Error>)` rather than
`Result<T, Error>`." Two independent codebases converged on this: the sibling
`axeyum` workspace enforces the same shape as a hard rule — "`unknown` is a
first-class solver result, never an error." Adopt it here as a hard rule too,
because the failure it prevents is precisely the whole-file voiding mode that
[`static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md)
§5 records in the tool being replaced.

## 5. How to avoid building the wrong abstraction

Generalizing from zero instances produces the wrong abstraction; the rule of
three exists for a reason. Three disciplines, in order of importance:

1. **Put `src/syntax/` in its own module from the first commit**, with C-specific
   code in `src/csource/`. Extraction later is then a move rather than a
   rewrite, and the boundary is checkable with the same source-text layering
   tests `python/tests/test_src_dependency_boundaries.py` already uses.
2. **Design against two real consumers, not four hypothetical ones.** C, and the
   inline-assembly sublanguage — which is present in the fixture corpus today,
   is control-flow relevant, and is different enough in shape (line-oriented,
   directive-driven, no expression grammar) to be a genuine test of the
   abstraction rather than a rubber stamp.
3. **Do not write a `Language` trait until a second full language exists.** The
   substrate is a set of reusable pieces, not a framework with a plugin point.

## 6. Non-goals

* No grammar description language, no parser generator, no combinator layer.
* No `Language` trait, no front-end registry, no dynamic dispatch over
  languages, until there are two full languages to abstract over.
* No lossless concrete syntax tree, no incremental reparsing, no source
  editing. If Glaurung ever needs to *rewrite* source rather than read it, that
  is when `rowan` gets reconsidered.
* No name resolution, no type checking, no semantic analysis in the substrate.
  Those are per-language and, for the current consumers, mostly unnecessary —
  see `static-c-analysis/requirements.md` §8.

## 7. The falsifier

If C++ never arrives — and the corpus evidence says it will not — and Rust is
served by `syn`, the substrate ends up with one full consumer plus a
sublanguage. That is **still worth building**: source maps, diagnostics,
interning, the token buffer and the CFG builder all pay for themselves inside a
single language, and [benchmarks.md](benchmarks.md) pays for itself the first
time a change makes the parser slower without making it better.

What that outcome would rule out is the *framework* layer. The signal that the
line has been crossed is concrete: **if a grammar DSL, a combinator layer or a
`Language` trait appears before the second full language does, stop and delete
it.**
