# Phase 7 — Extend the fixture matrix where reality lives

The matrix today: `{gcc, clang} × {O0, O2}` required on x86-64, `O2strip`
variants, arch lanes `i386 / armv7 / aarch64 / x86_64_gcc15`, Rust via
`rustc`. Each addition below is a **measured** one — the lane's cell-count
cost is stated, and each lane lands separately with its own baseline refresh
(all six side files, per the standing discipline).

## 7.1 Wire Go (written work earning zero return)

Five fixtures (`176`–`180`) exist, are documented in
`docs/development/decompiler-curriculum-corpus.md`, and are built by nothing:
`fixture_harness.py:214` globs `.c`/`.cpp`/`.rs` only. Verified ready:
`go1.23.4` on the host, and the fixtures are already written
`-buildmode=c-shared` with `//export` drivers over C scalar types — which is
**exactly** the dlopen shape the execution differential consumes. This is the
highest return-on-effort item in the whole plan.

* Harness: add `SRC.glob("*.go")`; per-language lane rule like Rust's
  (single toolchain). Go has no `-O` levels; the two lanes are
  `go build` (optimized — the O2 analogue) and
  `-gcflags=all=-N -l` (no optimization, no inlining — the O0 analogue).
  Name them `go:O2` / `go:O0` so every downstream key format holds.
* Add golang to the fixture Docker image for hermetic builds.
* Refresh all six baselines; remove `176-180` from the numbering-gap
  allowlist in the Phase 1.1 ratchet. Expect genuinely bad initial verdicts —
  Go's runtime calling convention and its huge `.gopclntab`-bearing objects
  are *why the fixtures were written*; a red-but-recorded baseline is the
  deliverable, not a green one.
* Cell cost: 5 fixtures × 2 lanes ≈ 10 host cells plus census rows.

## 7.2 `O0strip` — the debug-built malware shape

Stripped lanes exist at `-O2` only (a deliberate, measured scope decision in
`fixture_harness.py`). But a **debug-built, stripped** binary is what an
actual malware drop frequently is, and at O0-stripped the prototype recovery
has no DWARF and no optimization-implied constraints — a shape nothing
currently scores. Add `O0strip` for the C lanes only (same per-language rule
that keeps `rustc` to its own lanes), through the existing
`stripped_differential.py` machinery which already treats strip as a
key-suffix transform. Cell cost: ~200 cells in the stripped differential
population, no new baseline file.

## 7.3 One LTO lane

`gcc:O2:lto` (`-flto` at compile and link). LTO changes what the decompiler
sees more than any flag short of `-O3`: cross-TU inlining, dead-function
elimination, merged identical functions. One lane, host only, differential
included (LTO objects dlopen fine). Cell cost: ~200 host cells.

## 7.4 One musl lane

`zig cc -target x86_64-linux-musl` (zig 0.15.2 verified present — avoids
adding a musl-gcc toolchain). Different libc means different PLT shapes,
different startup scaffolding, different inlined-mem* idioms — the things
FLIRT/stdlib naming and prologue scanning key on (the ELF prologue scan
applying an MSVC rule cost 63% of a sweep once; libc diversity is the
regression test for that whole class). Static-link one variant for the Phase
5.3 FLIRT corpus at the same time. Cell cost: ~200 host cells, differential
included (host can dlopen musl-linked `-shared` objects; verify early — if
not, the lane is decompile-only and says so).

## 7.5 Structural baseline at O2

`structural_baseline.json` is gcc-O0-only. O0 structuring is nearly free;
**O2 is where goto-soup happens** — and the execution differential is blind
to it (memory: goto soup passes every fixture). Extend the structural
predicates (`switch`, `goto_free`, loop kinds) to the `gcc:O2` and
`clang:O2` lanes. Expect the initial capture to be ugly; pin it honestly and
ratchet. This is arguably the highest-value *quality* item in the plan: it is
the only gate that measures whether output is readable rather than merely
correct.

## 7.6 Explicitly deferred

`-O3`/`-Os` (mostly re-tests O2 machinery), PGO (nondeterministic profiles
vs hermetic builds), CET/`endbr64` and stack-protector variants (worth a
*single fixture each* rather than a lane — add as numbered fixtures instead),
big-endian (no consumer demand yet; revisit with s390x qemu when there is).
Each gets a line in the corpus doc so "deferred" is a decision, not a gap.

## Order

7.1 first (finished assets, zero new design). Then 7.5 (quality gate), then
7.2, 7.3, 7.4 one at a time — never two lanes in one change, because a
baseline refresh must be attributable to exactly one cause (the lesson of
every mis-attributed regression in `CLAUDE.md`).

## Effort

7.1 one day. 7.5 one to two days (predicate extension + honest capture on a
quiet machine). 7.2–7.4 half a day each plus baseline refresh runs.
