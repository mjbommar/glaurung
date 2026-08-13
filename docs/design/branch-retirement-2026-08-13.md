# Branch retirement manifest, 2026-08-13

Every branch deleted in the audit that emptied them onto master, with the SHA
it pointed at. Nothing here is lost: a deleted branch is restorable with

    git push origin <sha>:refs/heads/<name>

as long as the object survives, and these SHAs are the record of what to ask
for. Kept because branch deletion is the one step of that audit that cannot be
undone by reading the repository.

| branch | sha | disposition |
| ------ | --- | ----------- |
| `agent/aarch64-addv-reduction` | `f5833a3` | contained in master by ancestry |
| `agent/aarch64-bst-inorder` | `f7ded50` | contained in master by ancestry |
| `agent/aarch64-call-result-lifetimes` | `0030d53` | contained in master by ancestry |
| `agent/aarch64-call-result-width` | `9a0f7f1` | contained in master by ancestry |
| `agent/aarch64-call-value-roles` | `045f01e` | contained in master by ancestry |
| `agent/aarch64-clz-semantics` | `59c5f70` | contained in master by ancestry |
| `agent/aarch64-fact-mod` | `ef106c4` | contained in master by ancestry |
| `agent/aarch64-factorial-phi` | `ec5b2b8` | contained in master by ancestry |
| `agent/aarch64-find-first-set` | `79ea9d5` | contained in master by ancestry |
| `agent/aarch64-identity-return` | `2a02bd5` | contained in master by ancestry |
| `agent/aarch64-indirect-dispatch` | `5a0fbea` | contained in master by ancestry |
| `agent/aarch64-kmp-frame` | `ba3ff80` | contained in master by ancestry |
| `agent/aarch64-mul-widen` | `878bef9` | contained in master by ancestry |
| `agent/aarch64-o2-call-flow` | `10c1ac0` | contained in master by ancestry |
| `agent/aarch64-o2-graph-cluster` | `6c80999` | contained in master by ancestry |
| `agent/aarch64-o2-loop-control` | `4e3027a` | contained in master by ancestry |
| `agent/aarch64-packet-validate` | `443a925` | contained in master by ancestry |
| `agent/aarch64-rb-validate` | `7821b89` | contained in master by ancestry |
| `agent/aarch64-readonly-fallthrough` | `96ce97b` | contained in master by ancestry |
| `agent/aarch64-struct-array-process` | `158a99a` | contained in master by ancestry |
| `agent/aarch64-subbyte-width` | `82bb6c5` | contained in master by ancestry |
| `agent/aarch64-topological-sort` | `f9df6c4` | contained in master by ancestry |
| `agent/arm32-loop-o0` | `7d9c8e4` | contained in master by ancestry |
| `agent/arm32-memset` | `b81e799` | contained in master by ancestry |
| `agent/arm32-packet` | `40fc1d1` | contained in master by ancestry |
| `agent/arm32-rb-o0` | `798daf6` | contained in master by ancestry |
| `agent/arm32-residual-shared` | `acdec4f` | contained in master by ancestry |
| `agent/arm32-stack-args` | `f7d068d` | contained in master by ancestry |
| `agent/armv7-next` | `2e584c7` | contained in master by ancestry |
| `agent/armv7-orphan-integration` | `9043324` | contained in master by ancestry |
| `agent/condassign-definedness` | `03e63ee` | contained in master by ancestry |
| `agent/decbench-architecture-followthrough` | `099700c` | contained in master by ancestry |
| `agent/defect-register` | `9f63100` | contained in master by ancestry |
| `agent/definedness-bfi` | `d1911f7` | contained in master by ancestry |
| `agent/explicit-return-values` | `d6944e9` | contained in master by ancestry |
| `agent/ilp32-wide-return` | `d7c974c` | contained in master by ancestry |
| `agent/linkedlist-residual` | `f9d9c60` | contained in master by ancestry |
| `agent/rb-validate` | `9fe94e4` | contained in master by ancestry |
| `agent/return-definedness` | `02d32c9` | contained in master by ancestry |
| `codex/audit-working-snapshot-20260811` | `f8df627` | contained in master by ancestry |
| `codex/boolguard-working-snapshot-20260811` | `8df40f0` | contained in master by ancestry |
| `codex/curriculum-working-snapshot` | `fabec4e` | contained in master by ancestry |
| `codex/decbench-gap-roadmap-20260808` | `59b2f64` | contained in master by ancestry |
| `codex/globaladdr-working-snapshot` | `331cdd4` | contained in master by ancestry |
| `codex/globals-working-snapshot` | `440e42f` | contained in master by ancestry |
| `codex/main-working-snapshot-20260811` | `c902c11` | contained in master by ancestry |
| `codex/master-integration-20260811` | `6768e55` | contained in master by ancestry |
| `codex/ptrtypes-working-snapshot-20260811` | `0118f06` | contained in master by ancestry |
| `codex/typeenv-working-snapshot` | `ad93632` | contained in master by ancestry |
| `codex/x86-working-snapshot-20260811` | `40d5296` | contained in master by ancestry |
| `agent/arm32-flags` | `4530e6f` | **integrated** as `0ac458a` (ARM32 PLT layout rejection) |
| `agent/deref-const` | `c8537d1` | **integrated**: 18 libc prototypes as `60f2c47`; rest is `bool_guard`/`goto_sink`/`static_storage`, reverted on master by `c220be4`/`394eca3` |
| `agent/audit-glaurung-rt` | `59c2c31` | tools recovered in `3827cf7`; remainder is the reverted modules |
| `agent/global-addr` | `b7bdc1a` | same content as `agent/deref-const` |
| `agent/global-externs` | `c601862` | superseded: its `defect-register-2026-08-05.md` is 297 lines, master's is 1088 |
| `agent/ptr-types` | `adaeb39` | superseded: 0% of its added lines absent from master |
| `agent/type-env` | `df425cb` | superseded: `src/ir/symbol_env.rs` is on master; 3 residual lines are call-site variants |
| `agent/x86-flags` | `3b58b5e` | superseded: master already lifts `bsr`/`bsf`, and its zero-case is the LATER fix — writing the count unconditionally, because the branch's `Op::Ite` form made `dst` live-in and cost `shift_until_zero` three phantom parameters |
| `agent/bool-guards` | `1c77782` | `src/ir/bool_guard.rs`, deliberately reverted on master by `c220be4` |
| `agent/stack-bias` | `4ac7657` | **RETAINED, not merged** — see [stack-bias-affine-index-2026-08-13.md](stack-bias-affine-index-2026-08-13.md) |
| `archive/wt-audit-unresolved-merge-20260812-b` | `241e84a` | superseded: function-level parity with master in `src/ir/function_tables.rs` |
| `integrate/session-onto-master` | `eb43aad` | duplicate of `codex/primary-dirty-worktree-20260811` |
| `port/session-onto-master` | `781e62c` | an ancestor of master |

## How each was checked

File presence alone was not enough and produced a wrong answer once: it said
master lacked nothing while three branches held real content inside files master
also had. Every branch was therefore checked at LINE level — take every
substantive line the branch added relative to its merge-base with master, and
look for that exact line, whitespace-normalised, anywhere in master's tracked
text. Two caveats learned the hard way:

* **JSON is invisible to a line-level check across formatting styles.** The
  prototype bundle is hand-formatted compactly on master and `json.dump`-expanded
  on the branches, so 18 genuinely-missing prototypes looked like 700 missing
  lines, and would have looked missing still after they were added. That file was
  compared by prototype NAME instead.
* **"Absent from master" is not "master should have it."** `agent/x86-flags`
  showed 11% absent, and every absent line was the SUPERSEDED half of a decision
  master had already revisited. Absence is a prompt to read, not a verdict.

## What was kept

Two branches survive this sweep, and both are load-bearing:

* **`agent/stack-bias`** holds the only copy of the affine-index work. The SHA
  in the table above is a recovery hint, not a guarantee — an unreferenced
  object is eventually collected — so the branch itself stays until that work is
  either re-derived on master or deliberately abandoned.
* **`codex/primary-dirty-worktree-20260811`** is the pushed session branch that
  [`master-integration-2026-08-12.md`](master-integration-2026-08-12.md) cites
  by name as the source of the port, and that document is on master.
