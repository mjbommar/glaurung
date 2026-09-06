# WP3 control-consumer origin propagation

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `cb9e5b10` makes six remaining control-oriented AST consumers transparent
to statement-origin wrappers: loop-header safety, structured reaching,
stack-idiom recovery, terminal-loop recovery, guarded-call false-edge recovery,
and effectful-call loop rotation. Synthesized push, pop, terminal-loop,
guarded-false-edge, and rotated-loop statements retain deterministic unions of
the instruction origins that justify them.

This is a bounded WP3 wildcard-consumer migration. It does not complete the
wildcard audit, expression origins, non-contiguous transformation policy,
structured Python line mappings, or authoritative SSA consumer migration.

## Correctness boundary

Statement attribution is deliberately semantically transparent. A wrapper may
not hide an assignment from a loop-carried-value proof, hide a goto from an
unstructured-control check, or prevent an exact control idiom from matching.
Conversely, every recovery remains fail-closed under the same dataflow and
control preconditions as before; this increment changes wrapper visibility and
origin composition, not those proofs.

The effectful-loop integration fixture now reaches the intended cleaner form:

```c
var2 = sub_401120(arg0, arg1);
while (var2 != 0) {
    var1 = (var1 + *(long *)((var2)));
    var2 = sub_401120(arg0, arg1);
}
```

Its Python assertion was narrowed to the semantic loop condition instead of
requiring obsolete redundant parentheses. The separate guarded-call fixture
still fails because its call result is lost before this consumer sees the AST;
that is an open SSA/dataflow defect, not treated as success here.

## Evidence

Focused Rust coverage:

```text
lower_conds:          9 passed
stack_idiom:         11 passed
structured_reaching: 17 passed
terminal_loop:        6 passed
guarded_call:         4 passed
effectful_loop:       3 passed
total:               50 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 changed; 0 infrastructure problems
```

That is exact output neutrality against the preceding exception-origin
boundary. The four isolated float/x87 cells also remain unchanged; they belong
to the distinct type/value-identity work recorded by that boundary.

The complete Rust gate was rerun after one transient identity-harness population
mismatch. The exact failed test passed in isolation with all four cells scoring
the same 172 XC-O2 queries, and the complete rerun is green:

```text
cargo test --features python-ext
library: 4,251 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The required post-commit whole Python gate completed red. Its pytest cache
records 228 failing node IDs across the shared checkout, down from 230 in the
preceding run. The directly related effectful-loop node is no longer among
them; the guarded-call node remains red because the earlier dataflow defect
described above loses the call result before this pass. The other failures span
the same broad canonical-output, cross-architecture, generated-reference, and
known-defect groups as the preceding run. This is an honestly red repository
gate, not evidence of global closure; the focused tests, complete Rust gate,
and matched stripped differential above are the attributable evidence for this
bounded increment.

## Next ordered increment

Continue the wildcard audit with `src/ir/guarded_switch.rs`. Its recursive walk,
candidate recognition, speculation proof, discriminator-copy recognition, and
synthesized switch/default nodes currently inspect raw statements. Migrate that
consumer without weakening its exhaustive-label and unsigned-range proofs, then
repeat focused tests, release corpus measurement, the complete Rust gate, and
the post-commit Python gate.
