# Differential Oracle — Unicorn as a Dev-Only Reference

The primary correctness net for instruction semantics. Run identical instruction
streams on our interpreter and an oracle; compare post-execution architectural
state; any divergence is a bug (or a documented oracle/silicon discrepancy).

## Why Unicorn, and why dev-only

- Unicorn is a hook-instrumented QEMU fork with per-instruction `UC_HOOK_CODE` and
  `uc_context_save`, so snapshot + single-step + compare is cheap — the ideal
  oracle.
- It is a **dev dependency and oracle only**, behind the `dev-oracle` Cargo
  feature, **never in the shipped wheel** (Glaurung must not ship angr/Unicorn/
  Triton at runtime — `CLAUDE.md` / [N5](../00-motivation-and-goals.md)).
- **Caveat:** EXAMINER found 100k+ streams where Unicorn/QEMU themselves diverge
  from real ARM silicon. So Unicorn is the oracle for *semantic regression*; for
  exotic encodings, ground truth is real hardware. Document known oracle
  discrepancies rather than "fixing" our engine to match a wrong oracle.

## Harness shape

```
for each test case (instruction stream + initial state):
    set identical regs + mapped memory on (our Machine) and (unicorn uc)
    single-step ONE instruction on each
    diff: full register file + flags + every memory write
    on divergence: record a MINIMAL reproducer fixture + open a regression test
```

- **Inputs:** (a) a generated instruction corpus (random-but-seeded valid
  encodings per arch — deterministic generation, no host RNG in the recorded
  fixtures), and (b) real function slices from `samples/`.
- **Comparison:** exact on integer/flag/memory state. FP compared within a
  documented tolerance (N6). Intrinsics with no helper are expected halts, not
  divergences.
- **Determinism:** the generator is seeded; the corpus is a committed artifact so
  runs are reproducible and reviewable.

## Pass-rate reporting

Report the corpus pass-rate honestly (target ≥95% per phase) and enumerate
divergences as open fixtures. A divergence is triaged as: (1) our bug → fix +
regression test; (2) known oracle/silicon discrepancy → documented exception with
a hardware reference; (3) unsupported intrinsic → coverage backlog item.

## Sources
- [EXAMINER (ASPLOS'22)](https://dl.acm.org/doi/10.1145/3503222.3507736),
  [Unicorn Hooks](https://github.com/unicorn-engine/unicorn/blob/master/docs/Hooks.md),
  [unicorn-engine rust crate](https://github.com/unicorn-engine/unicorn/tree/master/bindings/rust)
- [`../01-research/emulator-engineering.md`](../01-research/emulator-engineering.md) §8
