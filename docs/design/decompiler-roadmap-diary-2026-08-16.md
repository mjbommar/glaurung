# Decompiler roadmap execution diary — from 2026-08-16

**Plan:** [decompiler-roadmap.md](decompiler-roadmap.md)
**Previous volume:** [decompiler-roadmap-diary-2026-08-13.md](decompiler-roadmap-diary-2026-08-13.md) — Entries 1-48, 2026-08-13..16
**Continues from:** `0acfe20`

Running evidence log for working the roadmap. One entry per increment,
RED -> GREEN -> VERIFY, with the exact command output that justifies each claim.

**Entry numbering continues across volumes**, so a reference to "Entry 34" stays
unambiguous. The next free number is **50**.

Two conventions worth restating, both of which this project has paid to learn:

- **Write the command next to the number.** Two tables in `docs/design/` turned
  out never to have been produced by any run, and both shaped later decisions.
- **Measure the tool's own noise floor before trusting a diff.** A byte-identity
  check over the corpus showed 16 functions changed by a refactor; running the
  unmodified build against itself showed 13 changed there too. Without that
  control the refactor would have been blamed for a pre-existing 0.10%
  non-determinism.

---
