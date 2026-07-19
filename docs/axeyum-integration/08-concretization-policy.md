# 08 - Concretization policy

Status: A0 accepted on `axeyum-concretization-policy-a0` at `07ea0c1`;
taint-provenance correction accepted at `845239f`
(2026-07-18).

## Why this is one policy seam

Glaurung has two places where a satisfying model becomes an explorer value:

- `concretize_addr` chooses and then binds a symbolic memory address;
- `eval_concrete` reads a representative value without binding it.

The value-selection rule is configuration, not a separate solver algorithm.
Both seams now call the same public `ConcretizationPolicy` contract. The
explorer, rather than a policy implementation, still owns checked solver calls,
model evaluation, equality binding, and ordered-trace emission. Consequently a
custom policy cannot bypass the established soundness and evidence boundaries.

`witness_for_value` is deliberately outside this abstraction: its caller fixes
the target value and asks only whether that exact value is feasible.

## Contract

`src/symbolic/concretization.rs` defines:

```rust
pub trait ConcretizationPolicy {
    fn policy_id(&self) -> &'static str;
    fn choose(&self, request: ConcretizationRequest<'_>) -> ConcretizationChoice;
    fn trace_policy_id(&self, site: ConcretizationSite) -> &'static str;
}
```

`ConcretizationRequest` contains only stable choice-site data: the seam, a
semantic purpose string, and the instruction address. It excludes expression
IDs, solver models, mutable counters, and process order. `ConcretizationChoice`
can describe `AnyModel`, one unsigned extremum, a deterministic `BoundarySet`,
or `Defer`.

The current production built-ins are:

| config | policy ID | behavior |
|---|---|---|
| `any-model` | `glaurung-any-model-v1` | backend-provided satisfying model; default |
| `min-unsigned` / `least-unsigned` | `glaurung-min-unsigned-v1` | least satisfying unsigned value |
| `max-unsigned` / `greatest-unsigned` | `glaurung-max-unsigned-v1` | greatest satisfying unsigned value |
| `site-hash-0` | `glaurung-site-hash-0-v1` | stable site-selected min/max endpoint |
| `site-hash-1` | `glaurung-site-hash-1-v1` | complementary endpoint at every site |

Select a built-in with `GLAURUNG_CONCRETIZATION_POLICY`. An unset variable
selects `any-model`. The preregistered experiment variable
`GLAURUNG_CANONICAL_MODEL_CHOICE` remains supported byte-for-byte, including its
historical `1`, `true`, and empty-string aliases for minimum unsigned. Setting
both variables is a precise configuration error rather than an ambiguous run.

## Compatibility gate

A0 must preserve the default explorer behavior. The contract tests pin:

- default selection to `AnyModel`;
- the historical address trace ID `glaurung-any-address-v1`;
- the historical representative trace ID
  `glaurung-representative-value-v1`;
- every legacy canonical-policy alias and stable policy ID;
- the exact complementary site-hash schedule used by ADR-0239;
- read-only representative selection versus address equality binding;
- fail-closed behavior for infeasible paths and unsupported widths.

The original release acceptance gate compared the pre-A0 `e98c090`
`ioctlance` binary with the A0 candidate under default AnyModel on the same
tcpip input and 15-of-338 fixed-work boundary. Both clean A0 repetitions emit
126 findings with ordered-finding SHA-256
`a67d7bca28602ab20bbc46d9a5d42705463bd340067dc8e6ec660b35d58ba265`,
exactly 2,991 solves, and the unchanged zeroed `glaurung-any-model-v1` counters.
Those fields match all three accepted pre-A0 repetitions byte for byte. The
known two Z3-only raw diagnostics also remain; A0 preserves the rejected
arbitrary-model divergence rather than selecting a favorable result.

That byte-for-byte gate subsequently exposed an independent analyzer defect:
uninitialized loads collapsed exact address provenance to `*attacker`. The
accepted correction at `845239f` intentionally changes taint labels while
leaving the A0 selection seam intact. The two raw Z3-only rows are now
`**Arg0`, and both authority outputs have zero high-confidence findings on this
15-function slice. See
[`09-taint-provenance-and-finding-labels.md`](09-taint-provenance-and-finding-labels.md).
Pre-correction ordered hashes remain valid A0 compatibility evidence but are
not the baseline for a finding-coverage claim.

A one-function production exercise then selects minimum unsigned through the
preferred and legacy variables separately. Both emit identical finding output,
13/13 completed choices, 858 probes, 869 total solves, and zero inconclusive,
unsupported, unknown, no-solver, error, or final-UNSAT choice. Only elapsed
solver time differs, as expected.

## Validation status

- All six policy-contract and all 17 explorer tests pass with
  `solver-axeyum`.
- `cargo check --features solver-z3,solver-axeyum --all-targets` passes.
- `cargo doc --features solver-axeyum --no-deps` completes; its 23 warnings are
  inherited broken/private-link and HTML-tag warnings outside this module.
- The complete `cargo test --features solver-axeyum --no-fail-fast` run passes
  977/979 library tests, every integration test, and doctests. The two failures
  are existing WinAPI prototype-rendering assertions and reproduce unchanged on
  untouched base `e98c090`.
- The new module passes a direct `rustfmt --check`, and a filtered strict Clippy
  run reports no diagnostic in `concretization.rs` or the changed explorer
  seam. Repository-wide format and `-D warnings` gates remain red on the
  historical base because of unrelated pre-existing drift; A0 does not rewrite
  those files merely to create a green-looking branch.

## What A0 does not claim

`BoundarySet` and `Defer` are explicit contract values so A3 and A2 do not need
another value-selection API redesign. They are not production-selectable yet.
At the current single-successor seams they fail closed instead of silently
collapsing a set or a symbolic address to one value.

- A3 must teach the explorer to fork over every checked member of a bounded,
  deterministic set and account for the resulting work.
- A2 must change the memory model so an address can remain symbolic.

The next experiment is therefore a preregistered policy sweep over a corrected
baseline, not another one-off canonical algorithm. Its coverage gate must use a
nonzero labeled finding population and report raw, confidence-gated, and
validated partitions separately. Symbolic memory remains conditional on
measured validated-coverage headroom after that sweep.

## Policy-robust detector semantics

The first preregistered sweep attempts exposed two distinct limits. Minimum
unsigned made the former AnyModel-complete usbprint boundary exceed its fixed
resource limit. Maximum unsigned retained all 14 expected source-backed
positive rows but added one false `StackOverflow` classification at the
attacker-pointer `RtlCopyMemory` in `test_physical_memory.sys`.

The old stack check concretized `dst` and `rsp` separately and treated numeric
proximity within 64 KiB as proof that `dst` denoted a stack object. Under
maximum, unrelated free symbols can acquire adjacent witnesses even though the
destination was loaded from `SystemBuffer`. This is a detector-classification
artifact, not validated coverage.

The corrected check requires structural evidence first: the destination and
current stack or frame pointer must be the same expression or share symbolic
ancestry.
Only then may the bounded numeric window refine the stack-overflow result. An
attacker-controlled destination remains correctly reported by the existing
arbitrary-read/write/null detectors, but cannot become a stack object merely
because one model places it nearby. The regression fixes both sides of the
contract: a constrained attacker pointer next to `rsp` is not stack storage,
while `dst = rsp` with attacker-controlled length remains a stack overflow.

The stopped sweep prefix remains rejected evidence. Rebuild both sole-authority
binaries and rerun the exact source-backed maximum control before preregistering
a corrected five-policy sweep; do not continue the unobserved site-hash cells
from the failed campaign.
