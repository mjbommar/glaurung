# Phase 1 — Reachability

> **Kind:** record · **Date:** 2026-08-31

Everything else in the plan lands into the estate this phase repairs. The
failure mode being closed: a test that exists, is tracked, reads as coverage —
and is run by nothing. The inventory found 89 such entries; the ones below are
the load-bearing subset.

## 1.1 The reachability ratchet (do this first)

A **default-suite** test, `python/tests/test_estate_reachability.py`, asserting
mechanical invariants that would each have caught a real historical failure:

* Every `tests/triage/*.rs` except `mod.rs` is named by a `mod` declaration in
  `mod.rs`. (Catches: the ten files below, unreachable for their whole lives.)
* Every top-level `tests/*.rs` whose first non-doc line is
  `#![cfg(feature = "...")]` names a feature that appears in a registry inside
  the test, and each registry entry names the command that runs it. (Catches:
  `register_view_semantics.rs`, which plain `cargo test` builds empty and
  reports passing.)
* Every `[[bin]]` in `fuzz/Cargo.toml` has a target file, and vice versa.
* Every `[[bench]]` in `Cargo.toml` has a file under `benches/`.
* Every `samples/binaries/metadata/*.json` parses with `json.load`. (Catches:
  all 63 current files, which contain literal `\n` two-character sequences.)
* The fixture numbering gaps in `tests/decompiler_fixtures/src/` exactly match
  a documented allowlist (currently `200`; `176-180` come off the list when
  Phase 7 wires Go).

These are static checks — no compilation, no execution — so the test costs
milliseconds and runs on every `uv run pytest`. Where an invariant cannot be
static (does CI *really* run the suite?), it is out of scope here and covered
by 1.5.

**Also:** regenerating `docs/test-inventory/` is agent-labour and cannot be a
ratchet; the ratchet is this test. The inventory gets a `Last verified` line
and a pointer here.

## 1.2 Wire the ten dead files in `tests/triage/`

`tests/triage/mod.rs` declares `budgets`, `io`, `real_files`, `sniffers`. Ten
siblings are declared by nothing:

```
adversarial  determinism_json  entropy_real  ioc_integration  packers_real
suspicious_integration  symbols_elf  symbols_macho  symbols_pe  truncation_json
```

That is 28 tests including the **adversarial suite** (truncated ELF/PE/gzip
must error, not panic), the **UPX packer suite**, and **determinism_json**.
They have never compiled, so expect rot: add the `mod` declarations one file
at a time, fix what breaks, and where a test's premise is no longer true,
delete it with a commit message saying why rather than `#[ignore]`-ing it into
a new kind of unreachable.

Acceptance: `cargo test --features python-ext` compiles all fourteen modules
and the triage integration test count rises by ~28.

## 1.3 The exec-gated register-view suite

`tests/register_view_semantics.rs` (24 tests, the only lifter↔emulator
differential) is `#![cfg(feature = "exec")]`. Its own doc comment claims
"`cargo test --features exec` is what CI runs" — CI runs no `cargo test` at
all. Add a targeted lane to `scripts/decbench-local-gate.sh` lane 1:

```bash
cargo test --features exec --test register_view_semantics
```

and register the feature/runner pair in the 1.1 ratchet.

## 1.4 The three permanently dead Python files

`test_symbols_demangled.py`, `test_demangle_integration.py`,
`test_view_function_tools.py` hardcode `"../samples/..."` CWD-relative, which
resolves outside the repo from every plausible working directory. Two are
duplicates of each other. Fix: resolve paths from `Path(__file__)` up to the
repo root (the pattern the rest of the suite uses), delete the duplicate, and
confirm the survivors actually pass — they have not run in their current form.

## 1.5 Invert the CI split

The expensive slow matrix runs on every push; the cheap 439-file default suite
has no workflow. Add `.github/workflows/test-suite.yml`:

* Job 1 (Rust): `cargo test --features python-ext`. This is the command
  `CLAUDE.md` names as the one that means a change is done; CI currently
  never types it.
* Job 2 (Python): `uv sync --locked --dev`, `uv run maturin develop --release`,
  `uv run pytest python/tests/ -ra`. Fixture-dependent tests will skip on the
  gitignored `build/` — that is fine **and visible**, because of 1.6.

Cost control: cache `~/.cargo` and `target/` keyed on `Cargo.lock`; expect
~15–25 min cold, much less warm. If that proves too slow for every push, run
on PRs + master pushes only — but it exists before it is optimized.

## 1.6 Make skips visible

176 Python files call `pytest.skip()` at runtime and `addopts` has no `-ra`,
so a run with 200 silent skips is visually identical to a clean one. Add `-ra`
to `addopts` in `pytest.ini`. No skip *budget* — a hard cap would be flaky
across environments — visibility is the deliverable.

## 1.7 The msvc-pdb fixtures nothing fetches

13 files / 142 tests wait on `tests/fixtures/msvc-pdb/*.exe|dll`, gitignored,
with a `fetch.sh` that **nothing in the repository calls** (the fixture README
claims otherwise). Interim fix here, real fix in Phase 4: a session-scoped
pytest fixture that runs `fetch.sh` into a cache directory when the network
allows and skips *visibly* when it does not. The README claim gets corrected
either way.

## Effort and order

1.1 first (half a day, and it locks in everything after). 1.2 is the long
pole — never-compiled code, budget a day. 1.4 and 1.6 are an hour each.
1.5 is a day including CI iteration. 1.3 and 1.7 an hour each.
