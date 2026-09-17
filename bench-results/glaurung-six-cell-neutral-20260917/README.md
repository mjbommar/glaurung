# Glaurung four-cell rerun at the 2026-09-16 Axeyum pin — registration

This directory is a **zero-result-row registration** at the time of this
commit. The protocol is ADR-0272's (Axeyum
`docs/research/09-decisions/adr-0272-preregister-six-cell-neutral-warm-regime.md`),
executed by `run-glaurung-four-cell-20260917.py`, a copy of Axeyum's
`scripts/run-glaurung-six-cell-neutral.py` with exactly the producer revision,
the executable hash, the validator path, and the docstring changed. The pins
that differ from July and why are in
[`docs/development/six-cell-rerun-2026-09-17.md`](../../docs/development/six-cell-rerun-2026-09-17.md)
and in `registration.json` under `changed_pins_against_adr_0272`.

- Producer: Glaurung `b1f420ab1e406ec2479509f65143211191428be0` (master
  `11b68faf` + the preflight alias fix), Axeyum pin `8df853252`.
- Cells: four — `{Z3, Axeyum} × {cold, warm}` (no Bitwuzla; see the note).
- Executable SHA-256:
  `4f3e5c376ef2da45ec0fc904b94874931ba3d5ff717da1e4482ca46c3a055f3f`.
- Runner SHA-256:
  `1a85b88ad7c78884291b35765191b08bcf5f0e5305dd930a14bf37c41c8ffbb7`.

At registration there are no trace paths, timing values, ratios, confidence
intervals, or driver conclusions here.
