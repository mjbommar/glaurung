# `docs/design/` — proposals for things that are not built

> **Kind:** guide · **Status:** maintained

Three directories hold the project's thinking, and the difference between them
is tense:

* **[`architecture/`](../architecture/README.md) is what is built.** It
  describes code you can read. If a claim there is wrong, the fix is to check
  the code and correct the document.
* **`design/` — this directory — is what is not built.** Every file here
  proposes something, or records why something was not done. Nothing here
  describes shipped behaviour, and nothing here is a work queue.
* **[`history/`](../history/README.md) is what was.** Dated records: diaries,
  superseded plans, defect registers, measurements pinned to a commit that has
  moved.

The live plan — what is actually being worked on, in what order — is
[`development/roadmap/`](../development/roadmap/README.md). A document in this
directory is not scheduled by being here.

## What is here

| file | what it proposes |
|---|---|
| [open-questions.md](open-questions.md) | six unimplemented ideas and measured negative results — goto sinking, the two loop passes that never fire, the stack-bias affine index, the four-workstream structuring/dispatch redesign, KB schema migration, and `FunctionFacts` — each with the experiment that would decide it |
| [function-facts-and-call-facts.md](function-facts-and-call-facts.md) | an interprocedural fact store keyed by stable function and call-site IDs. Nothing in it is implemented; its §6 is the measurement that rules out founding it on the existing `CallGraph` |
| [signature-tiers.md](signature-tiers.md) | a three-tier signature system — compiled patterns, Aho-Corasick runtime patterns, sandboxed WASM script logic — balancing match cost against expressiveness. Unbuilt |
| [execution-engine-research/](execution-engine-research/README.md) | four research syntheses gathered while designing the execution engine: IR design lessons, emulator engineering, an SMT backend survey, and a symbolic-execution survey. Background for decisions, not a proposal itself |
| [agentic-source-recovery/](agentic-source-recovery/README.md) | a 20-document delivery plan for agent-driven source recovery: scope, runtime and control loop, tool surface, output validation, evaluation design, phased roadmap, and the operational policies (budgets, sandbox, provenance, checkpointing) it would need |
| [cfg-discovery-determinism-2026-09-02.md](cfg-discovery-determinism-2026-09-02.md) | a diagnosis of `analysis::cfg`'s wall-clock budgets and the fix options for them: why the same binary can yield different block walks across runs, and what a deterministic step budget would cost. No `src/` change is made by it |
| [mips-discovery-gap-2026-09-02.md](mips-discovery-gap-2026-09-02.md) | a diagnosis of why MIPS32/MIPS64 function discovery truncates on Cisco Talos Dataset-1 while x86-64 does not, with the reproduction command and the candidate repairs |
| [static-c-analysis/](static-c-analysis/README.md) | the static/source half of Glaurung, starting with a pure-Rust C front end: what Joern does today (characterized against 800 published CFGs), the lifted requirements, a 45-component inventory, and a seven-stage roadmap whose first scored milestone reproduces 85,645 stored GED values without running Joern once. Unbuilt |
| [source-front-ends/](source-front-ends/README.md) | the language-neutral substrate every source front end sits on — source maps, interning, a struct-of-arrays token buffer and AST, an event-stream parser interface, the never-fails error model, and a language-blind CFG builder — with the per-language cost analysis that argues it is one and a half parsers rather than four, and a four-axis benchmark harness. Unbuilt |

The 2026-09-02 decompiler design review is dated evidence rather than a
proposal, so it lives in `history/`:
[`history/decompiler-review-2026-09-02/`](../history/decompiler-review-2026-09-02/README.md).
Its `PLAN.md` supplies file-level work packages, tests, sizing and stop
conditions, but it is not a work queue -- the live plan is
[`development/roadmap/`](../development/roadmap/README.md).

## When a document leaves

A design does not stay here indefinitely. It leaves in one of two directions,
and the move is part of finishing the work:

* **It ships** → rewrite it as a description of what exists and move it to
  `architecture/`, in the present tense, naming the code. A design document
  left in place after the code lands is the most expensive kind of stale doc,
  because it reads as a plan for work already done.
* **It is abandoned, superseded, or answered** → move it to `history/` with a
  `> **Kind:** record · **Date:** YYYY-MM-DD` banner and a row in
  [`history/README.md`](../history/README.md) naming what superseded it and
  which of its claims are now known false.

The one thing not to do is leave a third document behind when two disagree.
When a proposal here is contradicted by the code, the code wins and the
document moves.

## Writing one

Follow [`development/contributing-docs.md`](../development/contributing-docs.md)
for the kind/status banner and the generators. Two rules matter more here than
anywhere else in the tree, because a proposal is unfalsifiable by
construction:

* **Write the command next to the number.** Two tables in this directory's
  predecessor turned out never to have been produced by any run, and both
  shaped later decisions. A number without the command that made it and the
  commit it was made at does not go in.
* **State what would decide it.** A proposal that cannot name the experiment,
  fixture, or measurement that would settle whether to build it is not ready
  to be written down; it is a preference.
