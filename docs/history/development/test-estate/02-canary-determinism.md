# Phase 2 — A canary in the default suite, and a determinism gate

> **Kind:** record · **Date:** 2026-08-31

## The problem

Of the six ratchets, the only one in the default suite
(`tools/fitness_baseline.json`) measures **code size**. Every behavioural
baseline is `slow`-marked. So the command everyone actually types —
`uv run pytest python/tests/` — can pass on a build whose decompiler produces
garbage, and on a fresh checkout it cannot exercise the decompiler at all,
because `tests/decompiler_fixtures/build/` is gitignored.

## 2.1 Canary binaries, committed

Commit ~10 small prebuilt fixture binaries under
`tests/decompiler_fixtures/canary/`, chosen to span the shapes that break:

* a loop with early exit (`13`), a switch ladder (`04`), a state machine with
  a returning arm (`212`), a packed union (`216`), a float kernel (`172`),
  a Rust fixture (`166`), a stripped-O2 variant of one of them, and 2–3 more
  chosen by which structurer paths they reach (measure with coverage, don't
  guess).
* Built **hermetically in the fixture Docker image**
  (`glaurung-fixture-toolchain:1`) so the bytes are stable across machines —
  the same reason `fixture_harness.py` uses it. Record the image digest and
  compiler versions in a `canary/MANIFEST.json`.
* Size budget: these are `-shared` objects of one-page functions; the set
  should stay under ~500 KB total. The manifest test fails if it grows past
  1 MB.

Note the known trap from `CLAUDE.md`: fixture binaries embed their build path.
Canaries are built once and committed, so this is a feature here — the bytes
never vary — but the build must happen from the canonical checkout, not a
worktree.

## 2.2 The canary test

`python/tests/test_decompiler_canary.py`, default suite, target <60 s total:

* Decompile each canary through the real pipeline (the
  `python_bindings/ir.rs` entry point — the one most passes are only reachable
  through).
* Assert per-canary **structural predicates**, not golden text: function
  found at the expected address, recovered arity matches the manifest,
  `switch` present where the source has one, `goto`-free where the baseline
  says so, no undefined reads. Golden-text assertions rot on every renderer
  change; predicates encode what must stay true.
* The manifest carries the expected values, so adding a canary is: build in
  Docker, add bytes + manifest entry.

This is deliberately redundant with the slow differential — that is the
point. The differential proves correctness in ~50 minutes when someone runs
the gate; the canary proves non-brokenness in ~60 seconds every time anyone
runs pytest.

## 2.3 The determinism gate

Everything downstream assumes decompile-twice-diffs-clean: all six baselines,
the byte-identity sweeps used to validate refactors, every A/B measurement
this project has ever made. It has never been asserted.

* `python/tests/test_decompiler_determinism.py`, default suite: decompile
  each canary **twice in one process** and once **in a fresh subprocess**;
  all three outputs byte-identical. The subprocess leg catches ASLR-dependent
  pointer ordering and hash-seed dependence (`SipHash` is 7.8% of the profile;
  any iteration order leaking from a default `HashMap` into output ordering
  is exactly the bug this catches).
* If the pipeline gains threading, add a `RAYON_NUM_THREADS=1` vs `=N` leg.
* Wire `tests/triage/determinism_json.rs` (Phase 1.2 does the `mod`; this
  phase makes sure its assertions still hold) so triage JSON has the same
  property.

## Acceptance

* Fresh clone, `uv sync`, `maturin develop --release`, `uv run pytest
  python/tests/` — the canary and determinism tests **run** (no skip) and
  pass, in under 90 s combined.
* Breaking the structurer on purpose (e.g. disabling `detect_if_shape`) turns
  the canary red. Verify this once, by doing it.

## Effort

One day: half for choosing/building/committing canaries with the manifest,
half for the two test files and the deliberate-breakage check.
