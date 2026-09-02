# Phase 9 — Asset hygiene: delete the broken, dedupe the doubled

> **Kind:** record · **Date:** 2026-08-31

Every item here is committed weight that misleads: it reads as coverage,
documentation, or tooling and is none of those. Sources: inventory
`findings.md` §7, each verified before being listed there.

## 9.1 `samples/binaries/metadata/` — 63 files that have never parsed

All 63 fail `json.load` (literal `\n` two-character sequences instead of
newlines), they describe **host binaries absent from the corpus** (bash, gcc,
clang-20, initrd.img), and nothing reads them. The other 339 sidecars parse.

**Action: delete the 63.** They are not fixable into usefulness — even
repaired, they describe binaries that are not there. Deletion is
git-reversible. The Phase 1.1 ratchet (every metadata file parses) prevents
the class from returning.

## 9.2 The 18.8 MB of exact duplication

85 byte-identical pairs (md5-confirmed) between
`samples/binaries/linux/amd64/export/` and the legacy tree, including a
4.5 MB `hello-rust-debug`. Both sides are *live* — referenced by different
tests — so this is not a delete-one-side job:

* Pick the canonical tree (`export/`), repoint every test that references the
  legacy paths (grep gives the list; the inventory's `consumes` field gives
  it faster), then delete the legacy copies.
* One migration commit, test-suite-green before and after, no content
  change — which also means **no baseline touches**.
* Note: bytes already in git history stay in history; the win is checkout
  size, clone cost, and the end of "which copy is the real one".

## 9.3 `assets/` — 92% unreferenced

12.76 MB of 13.8 MB is referenced by nothing, including a 9.5 MB
`glaurung-logo-full.png`. Referenced and staying: the README banner, and
`glaurung-original.png` (a genuine triage negative-case fixture at
`src/triage/api.rs:807` — an image that must *not* be detected as a binary).

**Action:** delete the unreferenced files; if the full-size logo has
sentimental or site value it belongs in `../glaurung.dev`, not in every
clone of the analysis engine.

## 9.4 Dead scripts

* `scripts/setup-references.sh` calls `git submodule add` against
  repositories that are no longer submodules (`.gitmodules` was removed
  when `reference/` was cleaned up). It cannot work. **Delete.**
* `scripts/lint-rust.sh` runs `cargo clippy --all-targets --all-features`,
  would have caught several historical feature-gate breakages, and is
  currently red with ~260 pre-existing errors under `-D warnings`.
  **Keep, but decide:** either burn down the 260 (a separate, sizeable
  effort — not this phase) or change `-D warnings` to a pinned
  `--allow`-list so the script can run green *today* and ratchet down.
  The one unacceptable state is the current one: a correct check that
  nothing runs because it has always been red.

## 9.5 `java/glaurung-jvm-tools`

Self-builds at runtime via `mvn -DskipTests package`; its five JUnit tests
run nowhere. Smallest honest fix: run `mvn test` (without `-DskipTests`) in
the workflow or gate that already exercises the JVM path, and register the
runner in the 1.1 ratchet's registry.

## 9.6 Stale agent worktrees (not a commit — an operational note)

`.claude/worktrees/` held **160 GB** across 11 worktrees at the time of the
inventory. All were verified content-safe to remove: every commit reachable
from every worktree is in `master` by patch-id (`git cherry` all-minus), and
the dirty files were byte-identical to master's copies. Removal is a user
decision (`git worktree remove --force` per tree); recording the
verification method here is the deliverable, since "is it safe to delete"
is the question that recurs.

## Acceptance

* `samples/binaries/metadata/`: 339 files, all parsing.
* Zero byte-identical duplicate pairs across `samples/` (add the check to the
  1.1 ratchet as a slow-marked variant — md5 over samples is not free).
* `assets/` ≤ 1.5 MB, everything in it referenced.
* No script in `scripts/` that cannot succeed when invoked.

## Effort

One day total; 9.2 is most of it (repointing tests deserves care, not speed).
