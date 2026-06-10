# Research Synthesis

Condensed findings from the literature and existing frameworks, gathered during
the 2026-06 design effort. These inform every architecture and phase decision.
Each file states **what the best designs do** and **the tradeoff**, with sources.

| File | Topic | One-line takeaway |
|---|---|---|
| [`ir-design-lessons.md`](ir-design-lessons.md) | How VEX/P-code/BIL/BNIL/ESIL/Miasm/Triton make an IR *executable* | Totality + per-value bit width + one interpreter over many value backends |
| [`symbolic-execution-survey.md`](symbolic-execution-survey.md) | angr/KLEE/Triton/QSYM/SymCC/veritesting/memory models | Concretize + concolic + cache + direct toward the sink; completeness is a trap |
| [`emulator-engineering.md`](emulator-engineering.md) | QEMU TCG / Unicorn / bochscpu / snapshot fuzzers | Cached IR interpreter + dirty-page COW snapshots + small-core/helper split |
| [`smt-backends.md`](smt-backends.md) | Z3 / Bitwuzla / cvc5 / easy-smt for QF_ABV | Abstract behind a `Solver` trait; pipe first, native optional; default Bitwuzla, Z3 fallback |

## The three cross-cutting conclusions

1. **Totality + typing are non-negotiable for execution.** Every framework used
   as an executor has no "unknown" hole and types every value's bit width. Our
   LLIR violates both. (→ Phase 0.)

2. **One interpreter, many value domains** is the universal winning architecture
   for serving concrete + symbolic from one codebase. (→ the `Domain` trait,
   validated by prototype.)

3. **Tractability beats completeness on real binaries.** The engines that work on
   malware/drivers aggressively concretize, run concolically, cache solver
   queries, and direct search toward targets. Each is a deliberate, controlled
   surrender of soundness. (→ ADR-0004, ADR-0006.)
