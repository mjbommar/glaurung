# The 74 unreachable entries, classified

`unreachable` in `index.json` means one thing: **nothing runs it without a
human deciding to.** That is the right question for the field to ask, and the
wrong number to act on directly, because it puts a criterion bench with no
baseline in the same bucket as an `examples/` program that is *supposed* to be
compiled and not run.

This is that number split into buckets that imply different actions. Counts
are derived from `index.json`, not estimated.

| count | bucket | what it means | action |
|---:|---|---|---|
| 42 | type-checked only (feature-gated) | behind `symbolic` / `exec` / `solver-*` / `python-ext`; `scripts/feature-build-gate.sh` compiles every one | **acceptable today.** Running them needs solver binaries a hosted runner does not have. The gate is what stops them rotting; see `CLAUDE.md` on the seventeen days three SMT backends did not compile. |
| 13 | genuinely nothing runs it | listed in full below | **triage individually** |
| 10 | criterion bench | ten targets, no baseline, nothing invokes `cargo bench` | **partly addressed.** `tools/perf_gate.py` now gates decompile cost on instruction counts. The criterion targets stay diagnostic — they answer *where* a regression is once the perf gate says *that* one exists. |
| 5 | fuzz target | compile-verified since the twelfth gate lane; still not executed | **open.** Needs a nightly `cargo fuzz` job. `fuzz/seed_corpus.py` builds corpora; the runner does not exist. |
| 4 | opt-in evaluation harness | DecBench / Joern | **correct as-is.** These are evaluation, not gates, and `CLAUDE.md` forbids running them by default. |

## The 13 that genuinely nothing runs

Not all of these are defects, and saying which is the point of listing them.

**Directories and config, not tests** — an artifact of the survey's schema
rather than a gap: `samples/binaries/platforms`, `tests/decompiler_fixtures/src`,
`conftest.py`. Nothing "runs" a directory.

(The three CWD-dead Python test files were in this bucket at the first survey
and are not any more: `95249c54` anchored their sample paths and they pass.)

**Waiting on fixtures nobody fetches** — `tests/fixtures/msvc-pdb`. 21 skips
in the default suite trace here, and `fetch.sh` is called by nothing. This is
phase 1.7 of the estate plan and the largest single real gap in the list.

**Developer convenience scripts** — `scripts/format-python.sh`,
`lint-python.sh`, `typecheck-python.sh`. Thin wrappers over `uvx ruff` / `uvx
ty`, which CI now runs directly. They are unreferenced because they are
redundant, and the honest options are delete or point CI at them; either is
better than a wrapper nobody calls.

**Generators, which are meant to be run by hand** —
`tools/gen_defuse_baseline.py`, `tools/gen_fixture_gallery.py`,
`scripts/build_adversarial_samples.py`, `scripts/build-macho-samples.sh`. A
generator with no caller is normal. Worth noting that
`build_adversarial_samples.py` produced fixtures containing literal `\xNN`
TEXT for its whole life, which nothing caught because nothing read its output
either — so "generator, fine to be unreachable" is not the same as "generator,
fine to be unverified."

**Genuinely dead** — `scripts/fetch-reference.sh` (a sibling of the
`setup-references.sh` deleted in 937425d0; check whether it can still work).

**Another language's tests** — `java/.../MainTest.java`. The JVM tools
self-build with `-DskipTests`; five JUnit tests run nowhere. Estate phase 9.5.

## What moved

89 at the first survey, 77 after the ten `tests/triage/` files were wired and
two deleted subjects removed, 74 after the three CWD-dead Python files were
anchored and started passing. The drops are recorded per entry in
`index.json`'s `notes`, so the reason survives the number.
