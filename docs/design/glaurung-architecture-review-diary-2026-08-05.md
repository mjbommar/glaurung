# Glaurung architecture review diary — 2026-08-05

This is the evidence log for the architecture review synthesized in
`glaurung-architecture-redesign-2026-08-05.md`. It deliberately records
observations before recommendations so that later decisions can be checked against
the repository state that motivated them.

## Scope and review boundary

The review covers the five requested themes:

1. a program-level symbol and type environment;
2. symbolic rendering and interpretation of constant operands, not only calls;
3. aggregate and structure recovery;
4. an architecture-parametric machine model, with ARM32 as the stress case; and
5. a sound definedness and reaching-definitions oracle.

It also examines how those themes interact with lifting, LLIR, SSA, decompilation,
general binary analysis, module composition, source-file size, performance, and
failure safety.

The checkout began at `89b220e` on `master`, equal to `origin/master`. It already
contained unrelated modified and untracked decompiler work. This review therefore
adds documentation only and does not edit or normalize any existing source or
design file.

## Pass 0 — governing documents and prior architecture work

- `CLAUDE.md` defines Glaurung as a safe-Rust analysis core with Python as the
  analyst surface, requires real-fixture TDD, and identifies decompiler quality as
  an active frontier.
- `docs/design/decompiler-middle-architecture.md` already identifies the need for
  an authoritative typed SSA/MIR between executable LLIR and structured HIR. Its
  key separation — machine sort, operation interpretation, and recovered source
  type — remains the right semantic foundation.
- `docs/architecture/2026-07-13-architecture-quality-review.md` identifies the
  broader missing runtime: a reusable analysis session, explicit pass dependencies
  and invalidation, a durable project repository, and bounded partial-result
  behavior.
- The current review must connect these two designs. A typed function-local middle
  IR without a program environment cannot keep callee signatures, globals,
  relocations, strings, aggregate layouts, and cross-function evidence coherent. A
  program session without verified function-level semantics merely caches
  inconsistent answers.

## Pass 1 — size and ownership baseline

The following measurements include Rust under `src/` and Python under
`python/glaurung/`, excluding tests, tools, generated artifacts, and bundled
reference implementations:

| Scope | Files | LOC | Mean | Median | Files over 1,000 LOC | LOC in those files |
|---|---:|---:|---:|---:|---:|---:|
| Rust + Python product code | 638 | 352,200 | 552.0 | 309.5 | 71 | 166,880 (47.4%) |
| `src/ir` | 53 | 97,745 | 1,844.2 | 1,014.0 | 27 | 83,005 (84.9%) |
| `src/analysis` | 27 | 22,113 | 819.0 | 353.0 | 5 | 14,001 (63.3%) |

The largest IR files are not merely large containers:

| File | LOC | Initial ownership concern |
|---|---:|---|
| `src/ir/ast.rs` | 15,385 | HIR data model, lowering, rewriting, validation, and tests |
| `src/ir/lift_x86.rs` | 7,913 | decode semantics, machine-state policy, and architecture utilities |
| `src/ir/call_args.rs` | 6,201 | ABI evidence, reaching definitions, call rewriting, and tests |
| `src/ir/types_recover.rs` | 5,467 | constraint collection, type decisions, rewriting, and tests |
| `src/ir/stack_locals.rs` | 5,141 | stack analysis, recovery policy, AST transformation, and tests |
| `src/ir/structure.rs` | 4,823 | graph analysis, region selection, lowering policy, and tests |
| `src/ir/lift_arm32.rs` | 3,847 | ARM-specific semantics with fewer shared abstractions than x86 |
| `src/ir/copy_prop.rs` | 3,826 | several optimization and semantic-cleanup responsibilities |
| `src/ir/value_number.rs` | 3,660 | value equivalence plus architecture- and pass-specific policy |
| `src/ir/lift_arm64.rs` | 3,506 | AArch64 instruction semantics and state effects |

The raw target should not be “every file below 1,000 lines.” The meaningful target
is one reason to change per module, narrow public interfaces, and test modules kept
outside production implementation files. File-size reduction should be a measured
consequence of those ownership changes.

## Questions carried into the code trace

- Where is the authoritative identity for a program symbol, a recovered type, a
  machine value, a memory object, and a definition?
- Which stage is allowed to turn an address-valued constant into a symbol, string,
  relocation, enum member, field address, or plain integer?
- Are aggregate layouts constraints over memory objects or late AST-printing
  guesses?
- Which pieces of x86, AArch64, and ARM32 lifting implement the same machine
  concepts differently, and which differences are genuinely architectural?
- Which transformations ask “what reaches here?” and how many incompatible local
  implementations answer that question?
- Where can incomplete evidence silently become plausible C?

