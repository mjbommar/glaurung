# 08 - Concretization policy

Status: A0 implemented on `axeyum-concretization-policy-a0` (2026-07-18).

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

The release acceptance gate additionally compares the pre-A0 `e98c090`
`ioctlance` binary with the A0 candidate under default AnyModel on the same
fixed input and work boundary. Finding rows, finding-kind counts, solve counts,
and policy counters must match exactly; elapsed-time fields are not compared.

## What A0 does not claim

`BoundarySet` and `Defer` are explicit contract values so A3 and A2 do not need
another value-selection API redesign. They are not production-selectable yet.
At the current single-successor seams they fail closed instead of silently
collapsing a set or a symbolic address to one value.

- A3 must teach the explorer to fork over every checked member of a bounded,
  deterministic set and account for the resulting work.
- A2 must change the memory model so an address can remain symbolic.

The next experiment is therefore a preregistered policy sweep, not another
one-off canonical algorithm. Symbolic memory remains conditional on measured
coverage headroom after that sweep.
