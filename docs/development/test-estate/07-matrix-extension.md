# Phase 7 — Extend the fixture matrix where reality lives

> **Kind:** plan · **Status:** proposed

**Phase status: partial.** 7.1 landed **opt-in** at `6660f1f7` — the Go toolchain
and lanes are wired behind `GLAURUNG_FIXTURE_GO`, and the manifest entries and
four baseline refreshes they need are still outstanding. 7.5 landed across
`b02b5883`, `225088fb` and `1329382d`: the readability census now covers both
corpora and GCC/Clang O0/O2 at 3,580 entries. 7.2 (`O0strip`), 7.3 (LTO) and
7.4 (musl) are not implemented, and the full closure/effects map at O2 still
needs a lane key. Live status: [`EXECUTION.md`](EXECUTION.md).

The matrix today: `{gcc, clang} × {O0, O2}` required on x86-64, `O2strip`
variants, arch lanes `i386 / armv7 / aarch64 / x86_64_gcc15`, Rust via
`rustc`. Each addition below is a **measured** one — the lane's cell-count
cost is stated, and each lane lands separately with its own baseline refresh
(all six side files, per the standing discipline).

## 7.1 Wire Go (written work earning zero return) — **opt-in** (`6660f1f7`)

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

## 7.5 Structural baseline at O2 — **done** (`b02b5883`, `225088fb`, `1329382d`)

> **Measured 2026-09-01, and it is worse than the plan assumed.** With the
> lane seam now in `structural.py`, building `212_loop_with_returning_arm`
> both ways and decompiling `fsm_returns_from_arm`:
>
> | lane | `goto` | `switch` | lines |
> |---|---:|---:|---:|
> | `gcc:O0` | 5 | **1** | 56 |
> | `gcc:O2` | 11 | **0** | 63 |
>
> At `-O2` the switch is **gone** and the gotos more than double. The
> execution differential scores this fixture as passing in both lanes,
> because the behaviour is correct -- which is the entire argument for a
> structural gate stated as a number instead of a worry. One fixture, one
> function; the baseline is what would tell us how much of the corpus looks
> like this.

**Landed.** A readability census records `switch` / `goto` / `break` COUNTS
per function over **both corpora at both optimisation levels** --
`tests/decompiler_fixtures/src/` and `tests/decbench_corpus/src/`, across
`{gcc,clang}` x `{O0,O2}`. **3,580 entries**, and the baseline is itself a
finding: **85 switches against 4,604 gotos**, with 545 `break`s.

The population grew in three steps, because it gave a wrong answer twice
(`10-ci-environment-gap.md`, appendix):

| population | entries | verdict on the `detect_raw_dispatch_loop` fix |
|---|---|---|
| fixtures, O2 | 1,502 | "free" -- **wrong**, missed the other corpus |
| both corpora, O2 | ~1,800 | "free" -- **wrong**, the regressions are all at O0 |
| both corpora, O0+O2 | **3,580** | **-37 `break`s, +162 `goto`s.** Not free. |

That third measurement is the phase paying for itself: it is the only gate in
the repository that could see the cost, the execution differential was green
for all three, and the fix was reverted on its evidence.

**The O0 lanes are not optional, and that is the counter-intuitive part.** The
plan below assumed O0 structuring is "nearly free" and that O2 is where the
goto-soup lives. Both are true of the *absolute* counts -- and both are why O0
is where a regression shows up. O0 is where structured recovery already
succeeds, so it is where there is something left to lose; at O2 the same change
moved the `break` column by exactly zero, because there were barely any breaks
left to destroy.

What remains of this phase is the full closure/effects map at O2, which needs
the baseline key format to grow a lane component.

`structural_baseline.json` was gcc-O0-only. O0 structuring is nearly free;
**O2 is where goto-soup happens** — and the execution differential is blind
to it (memory: goto soup passes every fixture). Extend the structural
predicates (`switch`, `goto_free`, loop kinds) to the `gcc:O2` and
`clang:O2` lanes. Expect the initial capture to be ugly; pin it honestly and
ratchet. This is arguably the highest-value *quality* item in the plan: it is
the only gate that measures whether output is readable rather than merely
correct.

> *(Kept as written, because its one wrong assumption is instructive.)* The
> last sentence held. The reasoning that "O0 is nearly free, so measure O2"
> did not: it is exactly the argument that produced the second wrong answer,
> by scoping the census to O2 and hiding all seven regressions.

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
