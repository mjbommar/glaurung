# Adjudicating every orphaned object in the repository

> **Kind:** record · **Date:** 2026-08-19

**Question asked:** review ALL code across all branches and worktrees and decide,
for each: (1) integrate into master, or (2) discard.

**Base:** `master` at `08046a87`, clean, pushed, one worktree, one remote
(`origin/master`). Nothing here was decided from a commit message.

## The population, and why it is not 300

`git fsck --unreachable` reports **300 dangling commits**. That number is
misleading in both directions, so the first job was to partition it honestly.

| Class | Count | What it is |
|---|---:|---|
| `index on …` | 127 | stash internals — the index commit git writes per stash |
| `untracked files on …` | 37 | stash internals — the untracked-files commit |
| `WIP on …` | 88 | **dropped stashes with real content** |
| `On <branch>: <name>` | 32 | **named stashes with real content** |
| real commits | 16 | 11 worktree snapshots, 3 docs, 2 code |

My first pass folded the 88 `WIP on` commits into "stash internals". That was
wrong — internals are only the `index on` / `untracked files on` parents. The 88
are dropped stashes carrying working state, and re-including them is what
surfaced the one finding in this whole review.

So the genuine review population is **136 content-bearing objects**, plus 2 live
stashes.

## Method, and the two traps in it

Two independent tests, because neither alone is sound:

- **`git patch-id --stable`** — proves the exact diff was applied to master.
  Authoritative.
- **Line presence** — are the added lines in the tree now? Corroborates when
  high; **worthless as evidence of absence**.

Line presence reported `2fce2b7b` ("keep the stack protector a function already
had", 2,548 added lines) at **10% on master**, reading as clearly-not-integrated.
Its patch-id matches master's `3827cf79` exactly: it *was* integrated on
2026-08-13, and master has since split `stack_locals.rs` into submodules and
renamed through it. Four more commits showed the same pattern for the same
reason. **Refactoring erases textual evidence of integration.**

Two mechanical traps cost real time and are worth writing down:

- `git show <stash>` prints **no per-path diff** — a stash is a merge commit.
  Every `git show <stash> -- <path>` probe came back silently empty, which reads
  identically to "the content isn't there." Use `git diff <stash>^ <stash>`.
- `comm` without `LC_ALL=C` errors `not in sorted order` and reports **0% for
  everything**. Caught only because one item (`a2057f3d`) had already been proven
  present by symbol grep, so a 0% reading was known-false.

The general rule this repeats: **search for the behaviour, then confirm with the
name — never the reverse.** `2a699279` looked absent because the probe searched
`src/ir/ast.rs`; the rationale comment sits verbatim at
`src/ir/ast/decbench_render.rs:377`, having moved when the renderer was split out.

## Verdicts

### Discard — content proven on master

Every object below is superseded. **Nothing was integrated.**

- **164 stash internals** (127 `index on` + 37 `untracked files on`) carry no
  content of their own.
- **22 patch-id matches**: the exact diff is on master. Spot-proven by
  recomputing `2fce2b7b` → `3827cf79`.
- **24 named stashes**: bulk line-presence mostly 100%. The four that *named*
  themselves as deliberate were each checked by behaviour, not by name:
  - `a2057f3d` "promotion-cluster: held pending regression fix" — all six of its
    distinctive symbols (`rebased_hint_coordinate`,
    `a_cfa_object_reaches_a_body_that_omits_the_frame_pointer`, …) are on master.
    The regression was fixed and it shipped.
  - `3bebbe84` "AGENT-TEMP-do-not-drop" — 100% present; the 8-bit `wide_arith`
    path is `accumulator_halves(width: Width)` on master.
  - `24e84248` "fixture-188" — fixture 188 and its manifest entries are on master.
  - `36e93ab8` "bitscan" — master is **ahead**: it has `tzcnt`, `popcnt` and `bt`,
    which the stash does not, and its ZF test is better named
    (`…_without_reading_the_destination`).
- **5 docs commits** superseded. On `8603be1f` master is ahead
  (`verify_tutorial.py` 1,902 lines vs the orphan's 1,892).
- **`2902bc21`** (3,011 lines, the def-use ratchet) — every file present and
  master far ahead: `verify_defs.rs` 1,493 lines vs the stash's +105,
  `defuse_baseline.json` 7,349 vs 3,087. Its `__init__.pyi` edit is superseded by
  that stub's deliberate deletion.
- **`7fec3d19`** — fixture 204 and both distinctive dispatch tests are on master;
  `may_write_memory` moved into the new `dispatch/memory_guard.rs`.
- **`agent/stack-bias`** (5 stashes, 16% line presence) — capability landed
  2026-08-08 in `798daf60` under different names, four days *before* the snapshot.
- **`codex/primary-dirty-worktree-20260811`** (45%) — integration recorded and
  closed in `docs/design/master-integration-2026-08-12.md`.
- **`stash@{0}`** — its 52 lines are committed in `6617a68d`.

### Discard — reviewed and refused on the merits (4)

- `51514cc0` (x86 scalar float) — landed as `5e24383a` + `b4c7179` + `781e62c`.
  Residue is either **deliberately reverted** on master (`bool_guard.rs`,
  `static_storage.rs`, `goto_sink.rs`, by `c220be4f` / `394eca34`) or already
  ported. One genuinely un-landed piece remains: ~229 lines of dead code in
  `naming.rs` (`apply_role_names`, `live_in_arg_slots` have no production caller;
  the pipeline calls `apply_role_names_with_parameter_roles`). Optional cleanup,
  fixes zero cells.
- `a2f76fa7` (always-hoist GED) — **refused on the record.** Its own direct child
  `2bde5a82`, nine minutes later, is the retraction, and `f4600efd` landed the
  evidence document on master while rewriting its warning to *"The unsafe code was
  deliberately not integrated."* All six cells it admits it breaks currently pass.
  It trades 6 executing cells for a text-similarity gain only DecBench can see.
- `06579dff` (flags WIP) — behaviour present under different names in files that
  did not exist at its branch point (`lift_x86/conditions.rs`,
  `lift_x86/flags.rs`); both its RED tests are green and un-ignored on master.
- `c0b3bc91` (python >=3.12) — landed verbatim, comment included.

### The one real finding — a live defect, and a fix that no longer ports

Dropped stash `0ea79c3a` (branch `agent/arm32-flags`, based on `89b220e`,
2026-08-03) carries three tests. All three product functions and all four test
helpers still exist on master, so the tests apply verbatim. Run against
`08046a87`, **two of the three fail**:

```
aapcs_vfp_argument_setup_is_versioned_not_kept_bare
  FAILS: two distinct argument values were given one name: ["r0", "r0"]
an_indirect_call_through_a_return_register_alias_still_keeps_its_def_bare
  FAILS: the indirect target is a genuine alias read: rax#1
an_impossible_callee_layout_does_not_displace_the_call_site_setup
  PASSES — already fixed on master
```

`def_read_by_alias_before_redef` treats a call's `effects.args` — which is
`abi::call_effects`' ABI **may-use** list, an over-approximation of what the
callee might read — as a read of *this* definition. Under AAPCS-VFP the two
tables overlap: `return_registers` spells `r0`/`s0`/`d0` while
`argument_registers` lists `r0..r3` **and** `s0..s15`, so every call's may-use
list names `s0`, a return-register spelling belonging to the other parameter
bank. Every `r0` set up for a call therefore looks alias-read and is kept **bare**
— and bare is version zero, the function's live-in. Distinct argument values
collapse onto one undefined name.

**The fix is still a discard, and that was measured, not assumed.** Applying the
stash's product change makes all three tests pass and `cargo test --features
python-ext` green at 2,645/0 — and regresses four executing lanes:

```
06_calling_conventions:armv7:O2:fact_mod       pass -> fail
06_calling_conventions:armv7:O2:fib            pass -> fail
11_call_shapes:armv7:O2:call_accumulate_bytes  pass -> fail
11_call_shapes:armv7:O2:call_result_unused     pass -> fail
```

A/B isolated: dropping the indirect-target branch leaves the **same four**
regressions, so the cost is in the core change — skipping the may-use list — not
the indirect special-case. Today's ARM O2 output depends on the current behaviour
to keep certain defs bare. The tree was reverted and those lanes confirmed green
again.

The fix must be **re-derived** against today's `value_number`/`call_args`, not
ported. The obvious untried candidate is a narrower discriminator: ignore only
those may-use names that are return-register spellings from a *different*
parameter bank than `def_name`. Tracked as task #100.

### The three worktree artefacts — discard, minus one test

- **`stash@{1}`** (`copy_prop.rs` +194) is not a capability, it is a *measurement
  harness*: `measure_load_barrier` returns immediately unless
  `GLAURUNG_PASS_STATS` is set. It was used, and its output shipped. Its base
  `76f8d898` is the direct grandparent of `61730974` ("prove disjoint frame slots
  instead of dropping every load at a store"), whose commit message reports a
  census whose rows are this harness's stat categories one for one — 1308
  `stack_same_object_disjoint_offsets`, 543 `needs_pointer_proof`, 116
  `stack_vs_global`, 9 `stack_distinct_objects`, 8
  `stack_same_object_overlaps`. The proof it argued for is implemented in
  `src/ir/copy_prop/alias.rs`, and fixture `196_disjoint_frame_slots` was added
  by that same commit to guard it.
- **`241e84ad` (wt-audit)** — its own commit message is wrong: it claims
  `python_bindings/ir.rs` was committed with conflict markers, and there are
  none anywhere in that tree. Reviewed on the merits, six of seven hunks landed,
  several into files that did not exist at its branch point
  (`lift_arm32/predication.rs`, `types_recover/tagging.rs`). The seventh — a
  DWARF ARM `Register(7)`/`Register(11)` split — is *correctly* refused: `"r7"`
  is filtered out at `stack_locals.rs:390-397` because `STACK_BASES` has no
  `"r7"`, so the change would swap a phantom slot for a dropped hint. A probe
  confirmed `entry_sp` is the base that merges correctly, which master already
  reaches via the `CallFrameCfa` arm — and real toolchains only take that arm:
  `arm-linux-gnueabihf-gcc -g -O0` emits `DW_OP_call_frame_cfa` for
  `DW_AT_frame_base` under both `-mthumb` and `-marm`, never `DW_OP_breg7/11`.
- **`4530e6f5` (wt-arm)** — the patch is a duplicate: `0ac458af` already
  recovered `layout_matches_abi_allocation_order` from this same worktree state
  ~12h later, and the two function bodies are identical. **One test did not come
  with it**, and that gap is real: the unit test pins the *predicate*, but
  nothing pinned that `fold_one_call` actually *consults* it. Proven by mutation
  — removing the `.filter(...)` at `fold_one_call.rs:79` fails **exactly one**
  test out of 2,643, and that test is the recovered one. Integrated.

## What this cost, and what it bought

136 content-bearing objects reviewed — 88 dropped stashes, 32 named stashes,
and 16 real commits. **One live defect found and one coverage gap closed**, in a dropped
stash that my first partition had misfiled as a stash internal. Everything else
was already on master — most of it invisible to textual comparison because the
tree has been split and renamed underneath it.
