# Static C analysis: code layout, layering and dependency policy

> **Kind:** design · **Status:** proposed

Where this code lives, how it layers, what it is allowed to depend on, and why
the parser is hand-written. The programme is [`roadmap.md`](roadmap.md); the
components are [`implementation-inventory.md`](implementation-inventory.md).

## 1. The layering, and why it is not one module

```
  src/syntax/       language-neutral substrate      -> ../source-front-ends/substrate.md
    source.rs       SourceFile, SourceMap, Span
    intern.rs       Symbol(u32)
    token.rs        struct-of-arrays token buffer, Cursor
    diag.rs         Diagnostic; the (T, Vec<Error>) contract
    event.rs        parser event stream + sinks
    tree.rs         generic arena tree
    recover.rs      synchronizing sets, bounded depth
    cfg.rs          CFG builder over control-flow events
    ged.rs          graph edit distance over CFG degree sequences

  src/csource/      C-specific
    lex.rs          C token kinds over syntax::token   \
    ast.rs          C node tags over syntax::tree       |  the general asset
    parse/          C grammar, emitting syntax::Event   |  (outlives the metric)
    cfg/            C -> Flow events; a CORRECT graph  /
    lower/          AST -> LlirFunction                -> feeds src/exec, src/symbolic
    joern/          the parity layer                   -> feeds GED only
```

`ged.rs` lives in `src/syntax/`, not under `csource/`, because it is a graph
algorithm with no C in it: it reads a degree sequence and two boolean flags per
node and nothing else (`joern-behavior.md` section 2), so it is neither
C-specific nor bound to any particular CFG representation. It is also the piece
most likely to be wanted elsewhere in the crate.

The top half is not C's. It is the substrate designed in
[`../source-front-ends/substrate.md`](../source-front-ends/substrate.md), whose
requirements are `REQ-SYN-*` and whose components are `SB-*`; the C front end is
its first consumer, and the argument for sizing it at one and a half parsers
rather than four is [`../source-front-ends/README.md`](../source-front-ends/README.md).

The split between `cfg/` and `joern/` is the load-bearing decision in this
document. `cfg/` builds the graph a person would draw: real successors, real
join points, real loop back edges. `joern/` builds the graph
`cfgutils.similarity.vj_ged` expects: expression-granular nodes coalesced into
chains, a shared method-return node deleted if and only if it stayed a
singleton, entry and exit expressed as derived flags rather than graph
structure, and 1,334 functions in the reference corpus carrying more than one
entry flag.

Those are another tool's artifacts, faithfully reproduced. If they leak
downward, three things break at once: `lower/` inherits a CFG shaped by a JVM
program's expression granularity; the equivalence checker in
[`roadmap.md`](roadmap.md) §7 reasons over a graph whose exits were deleted for
metric-arithmetic reasons; and the general asset becomes good for one metric and
nothing else. Keep them apart from the first commit, not after the first
divergence.

## 2. Interfaces

**Rust.** `csource::cfgs_from_source(text, dialect) -> Result<BTreeMap<String, SourceCfg>>`
— pure, no filesystem access (REQ-API-1). `csource::joern::parity_cfgs(...)` is
the separate entry point for the metric path, and it is the only function that
may produce a graph the invariants of §S2 do not hold for.

**Python.** A PyO3 surface mirroring the Rust one, plus file-level helpers
matching DecBench's two entry points so `tools/decbench_source_cfg.py` can
substitute `extract_cfgs_from_source` and `extract_cfgs_from_decompilation`
in-process (REQ-API-2).

**CLI.** `glaurung source-cfg <file>` with `--json`, `--dialect
{preprocessed,decompiled}` (REQ-API-3). Adding a subcommand drifts a tutorial
fixture — refresh with `uv run python scripts/verify_tutorial.py --chapter
01-install --capture` and read the diff.

## 3. Where it plugs into what exists

The lowering in `lower/` is the whole reason the layering is worth getting
right. `src/exec/interp.rs` is **the one** interpreter — `run_function(&LlirFunction,
&mut Budget)` steps `Op`s over the `Domain` trait in `src/exec/domain.rs`, and
both the concrete emulator (`src/exec/concrete.rs`) and the symbolic engine
(`src/symbolic/symdomain.rs`) implement it. `src/symbolic/mod.rs` states the
property directly: the same interpreter "produces symbolic bit-vector
expressions when run over it — no duplicated semantics."

So `AST -> LlirFunction` is not one more consumer. It is a second *front end* to
an engine that already exists, and it arrives with:

| inherited | from |
|---|---|
| concrete execution of C functions | `src/exec/` |
| symbolic execution over identical semantics | `src/symbolic/symdomain.rs` |
| every solver behind one trait | `src/symbolic/solver/mod.rs` — `solver-axeyum` (pure Rust), `solver-z3`, the SMT-LIB pipe |
| taint, sinks, exploration | `src/symbolic/explore.rs` |
| the concretization policy machinery | `src/symbolic/concretization.rs` |

Nothing in this directory proposes a new symbolic engine, a new solver, or a new
IR. It proposes a new way in.

## 4. The parser is hand-written, and here is the evidence

Three routes were considered. Two fail on requirements that cannot be dropped.

**`lang-c`** — pure Rust, MIT/Apache, "almost full support for C11" with GCC and
Clang extensions behind features. Built from a PEG grammar. **Disqualified by
error handling:** a PEG parser has no recovery mechanism; a parse error is an
`Err` for the whole file. Ill-formed decompiler output is the *dominant* input
here (`undefined4`, `GLIBC_2.2.5::stderr`, `@ rax` before sanitization), and
whole-file failure is exactly the mode this programme exists to remove.

**`tree-sitter-c`** — has the error recovery, and it is the right kind
(ERROR nodes, not abort). **Disqualified by dependency:** the grammar crate
ships a generated C `parser.c` compiled through `cc`. The `tree-sitter-c2rust`
fork (0.25.2, Feb 2025) transpiles only the tree-sitter **runtime**, so a
grammar crate still compiles C; the transpiled runtime is little-endian-only and
non-idiomatic auto-generated `unsafe`, which collides with this repository's
rule that `unsafe` needs justification. Making the tree-sitter route C-free
means transpiling the grammar too — a fork we would then own, which is more work
than writing a parser and leaves us maintaining someone else's generated code.

**Hand-written recursive descent** — pure Rust, zero dependencies, no `unsafe`,
recovery we control and can tune against the oracle. It is also not
unprecedented in this crate: `src/analysis/java_class/` is 2,929 lines of
hand-written class-file and bytecode front end already shipping.

Two facts make C cheaper to hand-write here than it usually is:

1. **No preprocessor.** Inputs are gcc `.i` output or decompiler C. Macros,
   includes and `#if` are already resolved (REQ-IN-2).
2. **The declaration-versus-expression ambiguity is mostly moot.** It normally
   forces typedef tracking, because `A * b;` is a declaration if `A` is a typedef
   and an expression otherwise. For control flow both readings are one
   straight-line item contributing the same degrees, so getting it wrong costs
   fidelity in the AST but not structure in the CFG.

**A decision record is written when the measurement lands, not now.**
`docs/decisions/` holds decisions with their alternatives and why those lost;
the S1 coverage gate in [`roadmap.md`](roadmap.md) §3 is what settles this one,
and its stop condition names the circumstance under which `tree-sitter-c` wins
after all.

**Recovery strategy.** Panic-mode with synchronizing tokens (`;`, matching `}`)
is the starting point, and it is what CDT-style tolerant parsers do in
practice. If it proves too lossy, the algorithm worth reaching for is CPCT+
(Diekmann and Tratt, *Don't Panic! Better, Fewer, Syntax Errors for LR
Parsers*), implemented in the Rust `lrpar` crate — but note that adopting it
means adopting an LR parser generator, and C's context-dependent grammar is
poorly served by LR without the lexer feedback hack. Treat it as a reference for
the recovery *idea*, not as a dependency.

**Traversal.** The lexer and parser use explicit stacks, never native recursion,
as a hard rule — see [`roadmap.md`](roadmap.md) §0 for the incident that makes
this non-negotiable.

## 5. Dependency policy

### 5.1 What the crate is today

Glaurung's default build **already links C, unconditionally, twice**:

* `capstone` (`Cargo.toml:40`, not optional) — and it is load-bearing rather
  than a leaf. Fifteen non-test files use it, including all of `src/disasm/`,
  both ARM lifters (`src/ir/lift_arm32.rs:28`, `src/ir/lift_arm64.rs:29`),
  `src/analysis/dispatch.rs`, `src/analysis/ioctl_surface.rs`,
  `src/analysis/cfg/repair.rs` and `src/identity/structural/spp.rs`. x86 and
  x86-64 decode through the pure-Rust `iced-x86`; **ARM, ARM64, MIPS, PPC and
  RISC-V all decode through capstone.**
* `mimalloc` (`Cargo.toml:86`, `src/lib.rs:15` as the global allocator) — a C
  allocator built through `cc`.

There is no wasm target anywhere in the repository: `Cargo.toml`,
`pyproject.toml` and `.github/workflows/` contain no mention of one, and the
only WASM in the documentation is `docs/design/signature-tiers.md`'s proposal to
run WASM as a sandboxed *guest*.

So there is no purity to preserve. The useful policy is narrower and achievable.

### 5.2 The policy for this directory

**`src/csource/` adds no linked dependency, and no `unsafe`.** Not because the
crate is pure, but because this is the one large remaining component that can
hold that line, and because a front end that could compile to `wasm32-unknown-unknown`
keeps a door open that capstone currently closes.

That line is affordable. Of the 45 components in
[`implementation-inventory.md`](implementation-inventory.md):

| tier | components | situation |
|---|---|---|
| free — pure Rust, zero new dependencies | K-1..4, G-1..4, T-1..8, S-1..4 — **20 of 45** | `gimli`, `object`/`goblin`/`pelite`, `sha2`, `serde_json` are all present and all pure Rust. **All of `type_match` and all of scoring need nothing new** |
| the one real choice | F-1..17 — **17 of 45** | hand-written keeps the line; `tree-sitter-c` crosses it. Settled in §4 |
| impossible regardless | B-1..8 — **8 of 45** | `byte_match` shells out to gcc / MinGW / arm-none-eabi. Not a linking problem, and unfixable by building things ourselves |

So exactly one of the 45 components was ever a build-versus-link decision, and it
is the largest one.

### 5.3 The line for later stages

`lower/` targets LLIR, which is already in the crate. The equivalence checker of
[`roadmap.md`](roadmap.md) §7 uses the existing `Solver` trait, and its
pure-Rust backend (`solver-axeyum`) is already a pinned optional git dependency
— so the *default* build gains no solver, and the checker is a feature-gated
leaf exactly as
[`decisions/solver-002-axeyum-as-default-backend.md`](../../decisions/solver-002-axeyum-as-default-backend.md)
intends.

## 6. Estate obligations

Adding a top-level `src/` module is not a module *split*, so the four fixture
baselines are untouched. It does touch three keyed-by-path lists:

* the env-var allowlist in `python/tests/test_src_dependency_boundaries.py`;
* `REVIEWED_LARGE_MODULES` in `python/tests/test_large_module_review.py`;
* `REVIEWED_DOC_SUMMARIES` in `python/tests/test_stranded_doc_comments.py`.

New layering checks worth adding while the boundary is fresh: `syntax` must not
import `csource` or any other language module; `csource::cfg` must not import
`csource::joern`; and `csource::lex`/`parse` must not import either. These are
pure source-text checks in the style the boundary test already uses, and they are
cheapest to add before anything has crossed them.

Tests land in `python/tests/` with the existing marks — the parity lane is
`slow`, the DecBench A/B lane is `decbench`, so neither runs by default —
and `cargo test --features python-ext` covers the Rust side.
