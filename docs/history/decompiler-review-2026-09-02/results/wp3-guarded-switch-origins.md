# WP3 guarded-switch origin propagation

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `52914784` makes guarded-switch recovery transparent to statement-origin
wrappers. Recursive matching now reaches semantic statements through attributed
`if`, loop, switch, and `try`/`catch` nodes. The direct nested-switch, copied
discriminator, speculative assignment, and early-return forms preserve the
deterministic union of every removed statement that justifies the replacement
switch.

This is a bounded WP3 wildcard-consumer migration. It does not complete the
remaining guard-chain and switch-ladder consumers, expression origins,
non-contiguous transformation policy, structured Python line mappings, or
authoritative SSA consumer migration.

## Correctness boundary

Origin wrappers are metadata, not control-flow nodes. Candidate recognition and
its safety proofs therefore inspect `semantic()` statements, while mutations
descend through `semantic_mut()`. Recovery still requires the same exhaustive
label ownership, discriminator equivalence, unsigned range proof, and
side-effect restrictions as before. Only wrapper visibility and attribution of
the synthesized switch changed.

Focused tests cover attributed direct and copied-discriminator switches plus an
attributed early-return guard. They assert both the recovered semantic shape
and the exact canonical union of contributing instruction addresses.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext guarded_switch
22 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 changed; 0 infrastructure problems
```

That result is exactly neutral against the preceding control-consumer boundary.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,253 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The required post-commit whole Python gate completed red with exit status 1.
Its pytest cache records 227 failing node IDs across the shared checkout, down
from 228 at the preceding control-consumer boundary. No guarded-switch node is
present, and the effectful-loop node remains absent. The guarded-call node
remains red because an earlier SSA/dataflow stage loses the call-result value
before that consumer runs. The broad canonical-output, architecture,
generated-reference, baseline-ratchet, and known-defect groups remain open;
this result is not global repository closure.

## Next ordered increment

Continue the wildcard audit in `src/ir/guard_chain.rs`, split by semantic
responsibility rather than as one big-bang conversion. First make recursive
traversal, label/goto counting, unstructured-transfer detection, and
contradictory nested-guard pruning origin-transparent. Then migrate terminal
return/break synthesis, shared-assignment synthesis, and shared-exit ladder
synthesis with deterministic origin unions for every removed contributor.
