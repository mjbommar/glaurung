# ADR-0006 — Directed Concolic as the Default Mode

**Status:** Accepted · **Date:** 2026-06

## Context

Our targets are real malware and Windows drivers. Pure symbolic execution is
sound/complete in principle but explodes on real binaries (KLEE saw ~96k
concurrent states in minutes; the environment problem stalls on unmodeled
syscalls/instructions).

## Decision

Default to **directed concolic execution**:

- Run forward along a **concrete seed**, carrying symbolic terms alongside
  (`Val = (ExprId, u128)`, Triton model).
- **Symbolize only attacker-controlled input** (e.g. the IOCTL buffer + length).
- **Fork/query only at input-dependent branches** (taint-gated — Triton).
- Whenever the symbolic side is intractable (symbolic syscall, unmodeled
  instruction, huge symbolic pointer), **use the concrete value and continue** —
  no stall.
- Search is **directed** toward target sinks (ICFG shortest-distance), with
  random-path tie-break against loop fork-bombs.
- Pure symbolic / veritesting remain available modes, not the default.

## Rationale

For **bug-finding** (not verification), concolic is the right trade: it explores
the neighborhood of the concrete trace, always makes progress, and yields a
**concrete witness** (an input that reaches the sink) — exactly the artifact the
driver/malware workflow wants. This is the SAGE/QSYM/Triton lineage. →
[`../01-research/symbolic-execution-survey.md`](../01-research/symbolic-execution-survey.md) §4.

## Alternatives rejected

- **Pure symbolic by default** — state explosion + environment stalls; produces
  proofs we don't need at the cost of tractability we do.
- **Static-only (status quo `ioctl_taint`)** — cheap and useful, but can't produce
  a reaching input witness or resolve computed values; concolic *complements* it
  (static pre-filter → concolic confirm + witness), not replaces it.

## Consequences

- (+) Tractable on real binaries; always progresses; emits actionable witnesses;
  degrades gracefully on unmodeled environment.
- (−) **Incomplete** — only reasons near the concrete trace; may miss paths far
  from the seed. Mitigations: good seeds, directed search toward sinks, optimistic
  solving, and the static pass covering a different slice. Accepted per the
  "tractability over completeness" goal (G4).
- Pairs with ADR-0004 (concretizing memory) — both are deliberate, controlled
  surrenders of soundness for the ability to actually reach the target.

→ [`../02-architecture/symbolic-engine.md`](../02-architecture/symbolic-engine.md)
