# Concretization policy

> **Kind:** architecture · **Status:** maintained

> "A0" below is the workstream name for the extraction of this seam out of
> `explore.rs`; it is decided by
> [`solver-026`](../../decisions/solver-026-concretization-as-a-policy.md), and
> A2 (deferred symbolic memory) and A3 (forking over a boundary set) are the two
> follow-ons it deliberately did not do. The commits are `07ea0c16`
> (behaviour-preserving policy seam), `845239f0` (taint provenance preserved
> through symbolic loads) and `931d8a84` (findings partitioned by confidence),
> all on `master`.

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
- the exact complementary site-hash schedule of the two `site-hash-{0,1}` policies;
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
[`taint-provenance.md`](taint-provenance.md).
Pre-correction ordered hashes remain valid A0 compatibility evidence but are
not the baseline for a finding-coverage claim.

A one-function production exercise then selects minimum unsigned through the
preferred and legacy variables separately. Both emit identical finding output,
13/13 completed choices, 858 probes, 869 total solves, and zero inconclusive,
unsupported, unknown, no-solver, error, or final-UNSAT choice. Only elapsed
solver time differs, as expected.

## How it is gated

The contract lives in `src/symbolic/concretization.rs` and is covered by its own
policy-contract tests plus the explorer tests that exercise both seams; both run
under any `solver-*` feature. `scripts/feature-build-gate.sh` type-checks the
`solver-z3,solver-axeyum` lane the sweep needs, and the CI
`cargo test --features symbolic` lane compiles the module on every push.

A measurement made with this seam is only comparable when the *whole* identity
matches: policy id, trace id, driver, fixed-work boundary, and the ordered
finding hash. That is the point of pinning the trace ids above — two runs whose
selection differed are supposed to be distinguishable from two runs whose
*engine* differed.

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
current stack or frame pointer must be the same expression, the destination
must contain the non-leaf stack expression in its interned DAG, or the two
expressions must share free-symbol ancestry.
Only then may the bounded numeric window refine the stack-overflow result. An
attacker-controlled destination remains correctly reported by the existing
arbitrary-read/write/null detectors, but cannot become a stack object merely
because one model places it nearby. The regression fixes both sides of the
contract: a constrained attacker pointer next to `rsp` is not stack storage,
while the real constant-base `dst = rbp - 0x70` expression with
attacker-controlled length remains a stack overflow.

The accepted source-backed maximum control at `0581f57` restores all 14
expected high-confidence rows with zero false negatives and zero unexpected
high-confidence rows. Both authorities agree exactly in both repetitions. The
final dual-backend library suite at the documented corrected tree passes
992/994 tests; only the same two independently baselined WinAPI
prototype-rendering assertions fail. The
stopped sweep prefix remains rejected evidence; preregister and rerun all five
policies from the corrected revision rather than splicing the unobserved
site-hash cells onto the failed campaign.
