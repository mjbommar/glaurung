# `src/syntax/`: the language-neutral substrate

> **Kind:** design · **Status:** proposed

Requirements, data structures and components for the layer every Glaurung source
front end sits on. The case for building it, and the argument about which
languages actually need it, is [`README.md`](README.md); the measurement harness
is [`benchmarks.md`](benchmarks.md); its first consumer is
[`static-c-analysis/`](../static-c-analysis/README.md).

Nothing here is built.

## 1. The layering

```
  src/syntax/            language-neutral
    source.rs            SourceFile, SourceMap, Span, line/column
    intern.rs            Symbol(u32), SymbolTable
    token.rs             struct-of-arrays token buffer, Cursor
    diag.rs              Diagnostic, Severity, the (T, Vec<Error>) contract
    event.rs             the parser event stream and its sinks
    tree.rs              generic arena tree built from events
    recover.rs           synchronizing sets, bounded-depth guards
    cfg.rs               CFG builder over control-flow events
    scan.rs              shared lexical sublanguages: numbers, strings, comments

  src/csource/           C-specific: token kinds, grammar, AST tags, lowering
  src/csource/joern/     Joern-parity quirks (metric only)
```

Three rules the layering exists to enforce, each checkable by source text in the
style of `python/tests/test_src_dependency_boundaries.py`:

* `syntax` must not import `csource`, or any other language module.
* `csource::cfg` must not import `csource::joern`.
* `syntax::cfg` must not know what a C statement is; it consumes events.

## 2. Data structures

### 2.1 Tokens: struct of arrays, not array of structs

Store parallel vectors rather than a `Vec<Token>`:

```rust
pub struct Tokens {
    kinds:  Vec<u16>,   // language-defined tag
    starts: Vec<u32>,   // byte offset into the SourceFile
}                       // kinds.len() == starts.len(); end = starts[i + 1]
```

This is the representation the Zig compiler settled on — `token_tags: []Token.Tag`
alongside `token_starts: []Ast.ByteOffset` — and its AST uses the same shape
through `MultiArrayList`. The documented reasons are "less wasted bytes due to
alignment" and better cache locality.

**Measured, for our field set, not theirs.** The 37.5% figure quoted for Zig is
their four-field struct; ours has two fields, so the entire win is the two bytes
of alignment padding in `(u16, u32)`: 6 bytes per token against 8.

```
size_of::<(u16, u32)>() = 8      # N = 4096 tokens + 1 sentinel, DEBUG build
SoA payload = 24582 bytes        # cargo test --features python-ext --lib \
AoS payload = 32776 bytes        #   syntax::token::tests::struct_of_arrays -- --nocapture
saving      = 8194 bytes (25.0%)
```

25%, not 37.5%. The fixed cost is one extra `Vec` header (48 bytes against 24),
amortized away past about a dozen tokens. Quote our number, not Zig's.

Three consequences worth stating, because they are the trade:

* a token's **length is implicit** — `starts[i + 1] - starts[i]` — so the buffer
  needs a terminating sentinel and the last token cannot be measured without it;
* **that implicit length is the distance to the next token, not the lexeme
  length.** Trivia is discarded (below), so the two differ by exactly the
  whitespace and comments that follow the token: for `let x = 1;` the extents
  are `["let ", "x ", "= ", "1", ";"]`. The substrate *cannot* trim this —
  deciding where a lexeme ends and trivia begins is a language rule
  (`REQ-SYN-1`), and Zig hits the same wall and resolves it language-specifically.
  A front end has two escape hatches: trim with its own trivia predicate, or
  derive the length from the tag for fixed-length kinds. **Two traps sit one
  call site away**: a diagnostic caret drawn from a raw span underlines the
  trailing space, and a front end that interns identifier text straight from
  `text()` interns `"x "`. What does hold, and is the stronger property, is that
  concatenating every token's text reproduces the source exactly from the first
  token's offset onward;
* random access to "the whole token" touches two cache lines rather than one,
  which is the wrong trade for a debugger and the right one for a parser, whose
  hot loop reads `kinds` far more often than `starts`.

Trivia — whitespace and comments — is **not** stored. This is the point where
this design diverges from `rowan`, deliberately: our consumers lower to LLIR and
never re-emit source, so trivia is cost with no reader. `REQ-SYN-9` records what
would have to change if that stops being true.

### 2.2 AST: an arena of small nodes with a side table

```rust
pub struct Nodes {
    tags:  Vec<u16>,       // language-defined node tag
    main:  Vec<u32>,       // index into Tokens — the node's defining token
    lhs:   Vec<u32>,       // child NodeId, or an index into `extra`
    rhs:   Vec<u32>,       // child NodeId, or a length
}
pub struct Arena { nodes: Nodes, extra: Vec<u32> }
```

Also Zig's shape: a node carries a tag, a main token, and two `u32` slots, with
anything wider spilling into a single flat `extra_data` array whose layout is
determined by the tag. A function prototype, for instance, puts a start index in
`lhs` and reads six consecutive fields out of `extra`.

The Rust-specific requirements on top of that:

* handles are **lifetime-free `Copy` newtypes** (`NodeId(u32)`, `TokenId(u32)`),
  never references or `Box` — the same rule the sibling `axeyum` crate states
  for its term arena, and the reason its `TermId`s survive an arena clone;
* ids are assigned **densely in construction order**, so identical input yields
  identical ids and every gate that is a diff stays a diff;
* the arena is append-only during parsing.

**Two vectors more than specced, and the reason is `REQ-SYN-7`.** The four
above hold only the node's *defining* token, so a node's extent — its closing
brace, say — is nowhere, and `span()` cannot be answered. Zig recovers extents
with tag-dependent `firstToken`/`lastToken` walks, which this substrate may not
write because it may not know what a tag means (`REQ-SYN-1`). The arena
therefore keeps `first_token` and `end_token` as well: 8 bytes per node, in
exchange for an exact O(1) span. `span()` takes the token spans as a parameter
rather than importing the token buffer, so the layering holds.

**Measured, again, and again smaller than the cited figure.** 250,000 nodes,
capacity-exact vectors, debug build
(`cargo test --features python-ext --lib syntax::tree::tests::soa_beats -- --nocapture`):

```
specced 4 fields: SoA 3500000 B (14 B/node)  AoS 4000000 B (16 B/node)  saving 12.50%
actual  6 fields: SoA 5500000 B (22 B/node)  AoS 6000000 B (24 B/node)  saving  8.33%
```

The saving is exactly **2 bytes per node** in both configurations — the tail
padding of three `u32`s plus a `u16` — so it *dilutes as fields are added*
rather than scaling with them. Together with the token buffer's measured 25%
(§2.1), that is two independent measurements well below the 37.5% this document
originally quoted from Zig. **The memory case is roughly a third as strong for
our field sets as that number implies, and it should not be read as a
prediction.** The layout is still worth keeping — 500 KB per quarter-million
nodes is free, and the parser's hot loop reads `tags` far more often than the
rest — but the argument that carries the weight is cache locality, not
alignment.

**One capability deliberately absent: `precede`.** rust-analyzer can wrap an
already-closed node in a new parent, which is how it parses left-associative
constructs without lookahead. Doing that needs either an O(n) insert into the
event buffer or a `forward_parent` field on `Open`, and the latter changes the
`Event` enum in §3. Tag patching plus abandonment covers the
declaration-versus-expression case C actually needs. A grammar that needs
left-associative wrapping will have to add it, and adding it is an `Event`
change, not a local one.

### 2.3 Interning and source positions

`Symbol(u32)` into a `SymbolTable`; `Span { lo: u32, hi: u32 }` into a
`SourceFile`; a `SourceMap` owning many files and answering byte offset →
`(file, line, column)` by binary search over a line-start table computed once.
None of this is novel and all of it is load-bearing: it is what lets a finding
point at a line, and what replaces `tools/roundtrip_review.py`'s brace-matching
regular expression, whose own docstring records the debt — "A real parser would
be more robust and is not what makes this useful."

## 3. The parser interface: events, not trees

The parser produces a flat event stream and never touches a tree:

```rust
pub enum Event {
    Open { tag: u16 },        // start a node
    Token { id: TokenId },    // consume a token into the open node
    Close,                    // finish the open node
    Error { diag: DiagId },   // a recorded problem, not a bail-out
}
```

A `TreeSink` turns events into an arena tree; a `CfgSink` turns a *different*
event vocabulary (§5) into a control-flow graph; a counting sink extracts
function names without building anything. This is rust-analyzer's design, kept
for its stated invariant — the parser is independent of the tree structure and
of the token representation — and for the practical consequence that a second
grammar reuses every sink.

`Open`/`Close` may also be **forward-patched**: a parser that discovers a node's
tag only after consuming its first tokens rewrites the earlier `Open` rather
than backtracking. This is what makes C's declaration-versus-expression
ambiguity cheap to handle without a typedef table.

**An honest note on the `Sink` trait.** Two implementations exist — the tree
builder and a tag census that answers "how many nodes of each kind, how deep"
in one pass without allocating an arena — and their cost profiles genuinely
differ, which is the minimum bar for the indirection. But the trait is **not
yet load-bearing**, because the CFG builder of §5 consumes the separate `Flow`
vocabulary rather than these events. If that stays true, `Sink`'s second *real*
consumer never arrives and the trait should be revisited rather than defended.
Treat it as a design commitment being paid forward, not one already amortised.

## 4. The error model

**Parsing never fails.** The signature is `parse(&Tokens) -> (Events, Vec<Diagnostic>)`,
never `Result`. A `Result`-returning parser cannot report a per-function failure,
and per-function failure is exactly what
[`static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md)
§5 shows the incumbent getting wrong: one bad byte voids a whole file's CFGs.

Two independent precedents converge here. rust-analyzer states it directly —
"Parsing never fails, the parser produces `(T, Vec<Error>)` rather than
`Result<T, Error>`." The sibling `axeyum` workspace states the same shape as a
hard rule for a different domain: "`unknown` is a first-class solver result,
never an error."

## 5. The CFG builder

The highest-reuse component in the substrate, because control-flow events are
nearly identical across the C family. The builder consumes:

```rust
pub enum Flow {
    Stmt(Span),                   // straight-line item
    Branch { cond: Span },        // two successors; the grammar orders them
    LoopHeader { kind: LoopKind },
    Break(Option<Symbol>),        // labelled or not
    Continue(Option<Symbol>),
    Goto(Symbol),
    Label(Symbol),
    Switch { arms: u32 },
    Return,
    Diverge,                      // a construct with no successor
}
```

and owns, once, for every language:

* the **control context stack** — the current break target, continue target and
  switch arm list;
* **label backpatching** — a `Symbol -> NodeId` map plus a deferred-fixup list
  resolved in a second pass, exactly as an assembler resolves forward
  references;
* **maximal-chain coalescing** — contract `src -> dst` when `outdeg(src) == 1`
  and `indeg(dst) == 1`, in one pass over chain heads rather than to fixpoint;
* the **structural invariants** of `REQ-GEN-1`.

What it does **not** own is Joern's granularity, Joern's funcend rule, or
Joern's derived entry/exit flags. Those live in `csource/joern/` and are
metric-only; the reasoning is
[`static-c-analysis/architecture.md`](../static-c-analysis/architecture.md) §1.

## 6. Requirements

**REQ-SYN-1 — Language neutrality is enforced, not intended.** `src/syntax/`
contains no token kind, node tag, keyword or grammar rule for any specific
language. Checked by source text, not by convention.

**REQ-SYN-2 — Parsing never fails.** Every parser entry point returns its
product alongside a diagnostic list. No parser entry point returns `Result`, and
none may panic on any input.

**REQ-SYN-3 — Explicit-stack traversal.** The lexer, the parser and every tree
walk use explicit stacks, never native recursion. A recursive scan in the
sibling workspace overflowed the stack and **aborted the process**, so no
first-class result could be reported and the harness read the exit as a crash
(`fcc8760d`). Decompiler output is adversarial in exactly this way: nested
casts, parenthesised spines, long `||` chains.

**REQ-SYN-4 — Bounded work.** Every entry point takes or derives a depth bound
and a work budget. Exceeding either produces a diagnostic and a partial result,
never a hang and never a panic.

**REQ-SYN-5 — Determinism is a public promise.** Identical input yields
byte-identical output across runs, machines and thread counts. Ids are assigned
in construction order; anything iterated into output is a `BTreeMap` or an
`IndexMap`. This is the same promise the sibling workspace makes, and it is
load-bearing here because every gate in the programme is a diff.

**REQ-SYN-6 — No linked dependency, no `unsafe`.** `src/syntax/` adds neither.
The crate already links capstone and mimalloc unconditionally
([`static-c-analysis/architecture.md`](../static-c-analysis/architecture.md)
§5.1), so this is a line held for this module rather than a property of the
build — but it is the module where holding it is cheapest and most useful.

**REQ-SYN-7 — Spans are total.** Every token, every AST node and every CFG node
carries a span into a `SourceFile`. A construct that the parser recovered from
an error still carries the span of the text it skipped.

**REQ-SYN-8 — The CFG builder is language-blind.** It consumes `Flow` events
and nothing else. It never sees a token, a node tag or a keyword.

**REQ-SYN-9 — Trivia is out of scope, and the exit is written down.** Comments
and whitespace are not retained. If a consumer ever needs to rewrite source, the
options are: retain trivia in a parallel array keyed by token index, or adopt
`rowan`. Neither is implied by anything currently planned, and the decision is
deferred rather than pre-empted.

**REQ-SYN-10 — Two consumers before an abstraction.** No trait generalizing
"a language" is introduced until two language front ends exist. The substrate is
a set of pieces, not a framework.

## 7. Components

Sizing bands match
[`static-c-analysis/implementation-inventory.md`](../static-c-analysis/implementation-inventory.md):
`XS` < 100 lines, `S` 100–300, `M` 300–800, `L` 800–2,000.

| ID | Component | Data structure | Size | Test |
|---|---|---|---|---|
| SB-1 | `SourceFile`, `SourceMap`, `Span` | line-start table, binary search for line/column | S | offset → line/column agrees with a naive scan over the 21,296-line fixture corpus |
| SB-2 | `Symbol` interner | `Vec<String>` + `HashMap<&str, Symbol>`; dense ids in first-seen order | XS | identical input yields identical ids (REQ-SYN-5) |
| SB-3 | Token buffer + `Cursor` | parallel `kinds`/`starts`, sentinel terminator; peek, bump, expect, at | S | round-trips every token's text from spans over the whole corpus |
| SB-4 | Lexical sublanguages | shared scanners for C-family numeric literals, string and char literals with escapes, line and block comments | M | escape and literal edge cases, including the raw-control-byte case that voids files today |
| SB-5 | Diagnostics | `Diagnostic { span, severity, message, expected: SmallVec }`, `DiagId` | XS | a parse of deliberately broken input produces diagnostics and a tree |
| SB-6 | Event stream + sinks | `Vec<Event>`; `TreeSink`, `CfgSink`, counting sink | S | the same event stream drives all three sinks; forward-patching an `Open` works |
| SB-7 | Arena tree | `tags`/`main`/`lhs`/`rhs` parallel vectors plus `extra: Vec<u32>` | M | node count and shape stable across runs; memory measured against an array-of-structs control |
| SB-8 | Recovery primitives | synchronizing token sets as bitsets; depth counter; work budget | S | an adversarially nested input terminates with a diagnostic, does not abort |
| SB-9 | CFG builder | `Flow` events, control context stack, label fixup list, chain-head coalescing | M | the structural invariants of `REQ-GEN-1`, plus one fixture per `Flow` variant |

That estimate was wrong for two of the nine, and the miss is worth recording
rather than quietly amending. Measured product lines once implemented (tests
excluded, as the estate's own gate counts them):

| component | estimated | actual | why |
|---|---|---|---|
| SB-4 `scan.rs` | `M` (300-800) | **1,202** | four independent scanner families — trivia, string/char literals, numeric literals, identifiers — each with a long tail of real edge cases (unbounded `\x` escapes, hex floats, digit separators) |
| SB-9 `cfg.rs` | `M` (300-800) | **1,534** | the control context stack, label backpatching, chain coalescing and the `REQ-GEN-1` validators are four separable concerns that arrived as one file |
| the other seven | `XS`-`M` | 91-745 | as estimated |

Both exceed the 1,000-line threshold in
`python/tests/test_large_module_review.py`, which is the estate's mechanism for
asking exactly this question. Each is cohesive — one has a single reason to
change per scanner family, the other per graph-construction phase — but "four
separable concerns in one file" is the definition the threshold exists to
catch, so **both are split candidates, not allowlist candidates**. The natural
cuts are `scan/{trivia,literal,number,ident}.rs` and
`cfg/{flow,build,coalesce,validate}.rs`.

The claim that survives: the substrate is still far smaller than a grammar
will be, and the seven components that were estimated correctly are the ones a
second language reuses without modification.

## 8. Estate obligations

Adding `src/syntax/` and `src/csource/` is not a module *split*, so the four
fixture baselines are untouched. It does touch three lists keyed by file path:
the env-var allowlist in `python/tests/test_src_dependency_boundaries.py`,
`REVIEWED_LARGE_MODULES` in `python/tests/test_large_module_review.py`, and
`REVIEWED_DOC_SUMMARIES` in `python/tests/test_stranded_doc_comments.py`.

The three layering rules in §1 should land as new checks in
`test_src_dependency_boundaries.py` at the same time as the first module, while
the boundary is cheap to enforce and before anything has crossed it.
