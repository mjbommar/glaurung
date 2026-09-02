# Phase 3 — Fuzz the code that eats hostile bytes

> **Kind:** plan · **Status:** proposed

**Phase status: partial.** 3.1 (fuzz crate in a gate lane) landed at `78ad620e`,
3.2/3.3 (three deeper targets plus a seed generator) at `f57014dc`, and 3.4
(nightly runner, with an invariant asserting it is actually run) at `665fe25d`.
`fuzz/fuzz_targets/` now holds eight targets. 3.5 (the structured adversarial
corpus) is open, and `scripts/fuzz-smoke.sh` was never written — the nightly
workflow took its place. Live status:
[`EXECUTION.md`](EXECUTION.md).

## The problem

Glaurung's threat model is *malicious binaries designed to break the
analyzer*, and the fuzzing story is inverted twice over:

1. All five existing targets (`containers_detect`, `entropy_analyze`,
   `headers_validate`, `parsers_parse`, `sniffers_sniff`) are **triage-side**.
   Nothing fuzzes the disassembler, the lifter, CFG discovery, or the
   structurer — the components that consume attacker-controlled bytes
   deepest.
2. Even those five run nowhere: `fuzz/` is not a workspace member, so no
   `cargo check --all-targets` lane sees it; no CI calls `cargo fuzz`; no
   corpus is committed. The crate compiles against features
   `triage-core, triage-heuristics, triage-containers` and could be silently
   broken right now.

## 3.1 Make the fuzz crate buildable by a gate — **done** (`78ad620e`)

Keep it a separate crate (cargo-fuzz convention) but add **lane 12** to
`scripts/feature-build-gate.sh`:

```bash
cargo check --manifest-path fuzz/Cargo.toml
```

This is the same medicine `symbolic` and `triage-parsers-extra` needed, for
the same disease. The 1.1 ratchet already asserts target-file/`Cargo.toml`
correspondence.

## 3.2 New targets, deepest-first

Add in this order (each is a day or less including triage of what it finds):

| target | entry point | why |
|---|---|---|
| `disasm_decode` | per-arch decode loop over raw bytes | first consumer of untrusted bytes past triage |
| `cfg_discover` | function discovery on a synthetic in-memory image | the budget/worklist machinery; must terminate on garbage |
| `ir_lift` | lift a decoded block to LLIR | where `Op::opaque`-class modelling bugs live |
| `structure_cfg` | structurer over an `arbitrary`-derived CFG | bypasses decode entirely; reaches shapes no compiler emits |
| `demangle_all` | Itanium/Rust/MSVC demanglers on raw strings | 1 unit test today; demanglers are classic panic farms |
| `formats_parse` | ELF+PE+Mach-O full parse | broader than the existing `headers_validate` |

`structure_cfg` is the interesting one: use the `arbitrary` crate to derive
CFGs directly (blocks, edges, a terminator enum) rather than going through
bytes. Compilers emit a tiny corner of possible CFGs; the structurer's
recursion and its `stop_at` logic (see fixture `212`) should hold on all of
them. Pair it with the invariant that structuring output re-verifies
(`src/ir/structure/verify.rs` exists — make the fuzzer call it).

Every target runs under a hard timeout and the discovery budgets; a hang *is*
a finding (`Cfg` budgets exist to make it one).

## 3.3 Corpus

* Seed from what we already build: the `.text` sections of
  `tests/decompiler_fixtures/build/` objects, plus headers of the triage
  sample files. A committed script (`fuzz/seed_corpus.py`) regenerates seeds;
  `cargo fuzz cmin` minimizes.
* Commit the minimized corpus under `fuzz/corpus/<target>/` with a size cap
  (~2 MB per target, enforced by the 1.1 ratchet).
* **Every crash becomes a unit test.** A reproducer lands as a regression
  test in the owning module *and* stays in `fuzz/artifacts/` — the unit test
  is what keeps it fixed when nobody runs the fuzzer.

## 3.4 Run it — **done** (`665fe25d`)

Landed as `.github/workflows/fuzz-nightly.yml`, with a test asserting the
workflow actually invokes the targets. The local `scripts/fuzz-smoke.sh` below
was not written and is not planned; the nightly runner covers the role.

* CI: nightly workflow, `cargo fuzz run <target> -- -max_total_time=120` per
  target (~15 min wall for all). Findings upload as artifacts; the job fails
  on a crash.
* Local: `scripts/fuzz-smoke.sh` running 30 s per target, referenced from
  the pre-push docs but not wired into the ~50 min gate (the gate is long
  enough).

## 3.5 Adversarial corpus (structured, not random)

Fuzzing finds crashes; it does not assert *graceful degradation*. Complement
it with generated malformation, which avoids importing third-party corpora
and their licenses:

* `tools/gen_adversarial.py`: takes our own fixture binaries and applies
  targeted mutations — truncation at every section boundary, section headers
  pointing past EOF, overlapping program headers, impossible entry points,
  size fields of 0 and `u64::MAX`, a jump into the middle of an instruction.
* Each mutation class gets a test asserting **error-not-panic and
  budget-respected** — which is exactly the stated purpose of the
  `tests/triage/adversarial.rs` suite that never compiled (Phase 1.2 wires
  it; this extends it downward past triage into disasm/CFG).

## Acceptance

* All targets build in gate lane 12 and survive 10 minutes each locally with
  no crash, or with every found crash converted to a fixed unit test.
* Nightly CI workflow exists and has run green at least once.
* The mutation suite covers ≥8 malformation classes across ELF and PE.

## Effort

Roughly a week: a day for 3.1 + reviving the five existing targets, three to
four days for the six new targets and triaging their first findings (the
first fuzz of a decade-old-pattern codepath always finds something), a day
for corpus + CI + the mutation generator.
