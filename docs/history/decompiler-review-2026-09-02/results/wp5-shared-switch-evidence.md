# WP5 shared typed switch evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

Commit `9ad9414d` replaces the production and shadow-v2 structurers' separate
case/default reconstruction with one immutable `SwitchEvidence` object built
from `Cfg`'s typed `SwitchCase` and `SwitchDefault` edges and ordered case
labels. The object carries dispatch identity, ordered case values and targets,
the formal default and guard provenance, a typed-edge provenance tag, and an
explicit completeness bit. Production and v2 consume the same facts; the v2
verifier remains an independent relational checker rather than trusting or
re-running the producer algorithm.

Fixture `204_adjacent_dispatch_tables:clang:O2:adt204_guarded_control` proves
fact agreement on a real binary: production and v2 observe the same cases
`0..6` and the same formal-default presence. This preserves the earlier
production result: no indirect placeholder and 34 of 34 deterministic
executions. The SSA-transitive unsigned-comparison requirement remains the
admission proof for the guarded default, so superficially similar conditionals
are not misclassified as switches.

## Fail-closed review fixes

- Completeness requires every typed case edge to map to a present, non-empty
  case-label set; a missing positional label cannot be filtered away while the
  evidence remains complete.
- Missing, forged, or ambiguous formal defaults are refused. Tree verification
  compares proven versus rendered default presence, cardinality, and identity.
- Verifier label lookup is bounds-safe and returns
  `SwitchEvidenceMismatch` for missing, short, or empty labels rather than
  panicking.
- Shadow-v2 explicitly declines incomplete evidence before tree recovery,
  rendering, or later accounting can make it appear acceptable.

Synthetic refusal tests cover missing and empty labels, forged and ambiguous
defaults, deletion of a proven default from a tree, and incomplete candidate
evidence. Direct-switch semantics remain unchanged when the default target is
also reachable as a table case or guard bypass: the typed edge roles and
ordered labels, not target uniqueness, determine case and default identity.

## Changed surface

- `src/ir/structure/cfg.rs`: shared immutable evidence types and the sole
  typed-edge/label producer.
- `src/ir/structure/switch_shape.rs`: production consumer with complete-only
  admission.
- `src/ir/structure_v2/region.rs`, `recover.rs`, and `mod.rs`: remove duplicate
  evidence construction, consume the shared object, and decline incomplete
  candidates before recovery.
- `src/ir/structure_v2/verify.rs`: independent relational validation and safe
  refusal paths.
- `src/ir/structure.rs`: exports the shared contract.

## Validation

Focused shared-evidence, production-structure, v2, and verifier groups pass:
2/2, 55/55, 25/25, and 5/5 respectively. The fixture-204 assertion confirms
production/v2 fact agreement.

The complete required Rust gate was run in an isolated clean worktree at exact
commit `9ad9414d`:

```text
cargo test --features python-ext
35 test-result summaries: 4,351 passed; 0 failed; 17 ignored
library target: 4,094 passed; 0 failed; 5 ignored
documentation target: 2 passed; 0 failed; 1 ignored
```

HEAD and both staged and unstaged diffs were checked before and after the run;
the detached worktree remained clean at `9ad9414d`.

The isolated parent/tip fitness A/B measures `+104` product LOC. Only mean
product LOC worsens; no threshold or maximum-size ratchet does. Shadow-v2 is
33 product lines smaller and remains at 3,284 of its pre-approved 4,400-line,
nine-file cap. The shared object therefore consolidates duplicated ownership
while staying inside the registered WP4/WP5 architecture allowance.

## Limits

This increment does not complete WP5. Explicit execution evidence across the
remaining compiler and architecture cells, residual decline classification,
the full Python gate, and the complete fixture/architecture matrix are still
pending. The verifier and structure accounting deliberately remain independent
of the evidence producer; sharing semantic facts does not mean sharing trust.

No DecBench run or upstream interaction was performed.
