# Research Synthesis

> **Kind:** design · **Status:** proposed

Condensed findings from the literature and existing frameworks, gathered during
the 2026-06 design effort. Each file states **what the best designs do** and
**the trade-off**, with sources.

These are kept as *research*, not as architecture: they describe a field, and
several of their recommendations were rejected in implementation. Where a file
made a call that did not survive, it now says so in place rather than being
quietly corrected. For what was actually built, read
[`architecture/execution-engine.md`](../../architecture/execution-engine.md) and
[`architecture/solver-backends.md`](../../architecture/solver-backends.md).

| File | Topic | One-line takeaway |
|---|---|---|
| [`ir-design-lessons.md`](ir-design-lessons.md) | How VEX/P-code/BIL/BNIL/ESIL/Miasm/Triton make an IR *executable* | Totality + per-value bit width + one interpreter over many value backends |
| [`symbolic-execution-survey.md`](symbolic-execution-survey.md) | angr/KLEE/Triton/QSYM/SymCC/veritesting/memory models | Concretize + concolic + cache + direct toward the sink; completeness is a trap |
| [`emulator-engineering.md`](emulator-engineering.md) | QEMU TCG / Unicorn / bochscpu / snapshot fuzzers | Cached IR interpreter + dirty-page COW snapshots + small-core/helper split |
| [`smt-backends.md`](smt-backends.md) | Z3 / Bitwuzla / cvc5 / axeyum for QF_BV | Abstract behind a `Solver` trait, and gate every backend by feature. The survey's pipe-first recommendation was reversed: what ships is native z3 preferred, pure-Rust axeyum second, pipe last |

## The three cross-cutting conclusions

1. **Totality + typing are non-negotiable for execution.** Every framework used
   as an executor has no "unknown" hole and types every value's bit width. Our
   LLIR violates both. (→ Phase 0.)

2. **One interpreter, many value domains** is the universal winning architecture
   for serving concrete + symbolic from one codebase. (→ the `Domain` trait,
   validated by prototype.)

3. **Tractability beats completeness on real binaries.** The engines that work on
   malware and drivers aggressively concretize, cache solver queries, and bound
   their own exploration. Each is a deliberate, controlled surrender of
   soundness. (→ [`exec-0004`](../../decisions/exec-0004-symbolic-memory.md),
   [`exec-0006`](../../decisions/exec-0006-execution-mode.md).) Two of the four
   levers this conclusion names were *not* adopted: the engine is not concolic
   and its search is not directed. Both decision records say why.
