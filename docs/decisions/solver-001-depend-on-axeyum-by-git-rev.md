# Solver ADR-001 — Depend on axeyum by path (dev) then git-rev (release)

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** All axeyum crates are `publish = false`; nothing is on
crates.io. glaurung needs `axeyum-ir` + `axeyum-solver` (rest transitive).
Both repos are the author's, both edition 2024 / rustc >= 1.88.
**Decision:** Use a **path dependency** during co-development (P1-P3), then
pin a **git-rev dependency** at P4 (the default-landing) so the shipped
artifact is reproducible and decoupled from local checkout paths. Never
crates.io (blocked by `publish=false`; not needed).
**Consequences:** glaurung's MSRV floor rises to rustc 1.88 / edition 2024
(already met). API drift is bounded by keeping the consumed surface tiny
(term building + one-shot solve + model read + proof export).
**Alternatives rejected:** vendoring a copy (drift + license duplication);
crates.io (not published).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
