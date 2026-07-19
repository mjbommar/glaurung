# 09 - Taint provenance and finding labels

Status: accepted correction and machine-readable confidence partition on
`axeyum-concretization-policy-a0` at `931d8a8` (2026-07-18).

## Why raw sinks are not a coverage oracle

The authority harness deliberately sets `IOCTLANCE_ALL=1` and compares every
diagnostic sink. That is a useful determinism and explorer-equivalence check,
but it is not the same population as ioctlance's normal high-confidence
output. In particular, the assume-tainted-entry model assigns generic `ArgN`
labels to function parameters. A dereference of an ordinary parameter remains
useful diagnostic output, but is not evidence of an attacker-controlled IRP
buffer.

Before this correction, an uninitialized load through any tainted address
discarded the address's provenance and marked the fresh value as
`*attacker`. That transformed `Arg0` into `*attacker` and bypassed the normal
`is_attacker_real` filter. Model choice could then steer these laundered rows,
making raw authority differences look like a true-positive coverage gap.

## Correction

`TaintSpec` now retains a stable set of labels per symbol. An uninitialized
load prefixes every exact address source rather than replacing it:

- `Arg0` becomes `*Arg0`;
- `*Arg0` becomes `**Arg0`;
- `SystemBuffer` becomes `*SystemBuffer`;
- mixed provenance remains mixed rather than losing all but one source.

The normal confidence gate already strips dereference prefixes before testing
for `ArgN`, so generic parameter ancestry remains suppressed at every depth,
while genuine `SystemBuffer`, `UserBuffer`, `Type3InputBuffer`, and other
non-`ArgN` sources remain high confidence.

The regression test constructs one uninitialized load through an address with
both `Arg0` and `SystemBuffer` provenance and requires the loaded value to carry
exactly `*Arg0` and `*SystemBuffer`. It failed as `*attacker` before the fix.

## Tcpip classification

The two stable Z3-only AnyModel rows on the first 15 tcpip functions are at
`0x1c000830d` and `0x1c000832e`. Public and module PDB symbols place both in
`TcpSendTrackerMarkTransmits` (`sendtracker.obj`), whose function begins at
`0x1c0008270` and spans 2,104 bytes. Disassembly shows internal tree traversal:

```text
0x1c000830d  subl -0xc(%rax), %ecx
0x1c000832e  movq 0x8(%rax), %rcx
```

A valid ordered Z3 trace contains 14,549 events, 771 paths, 2,477 unique
queries, 586 assertions, 3,079 checks, and 1,405 model reads. At the second
site, the chosen address depends on `sym0_64`, `sym5_64`, and `sym7_64`; the
trace records the expression as an XOR/add traversal rooted in the generic
entry argument and fresh values loaded through that ancestry. The corrected
raw rows are consequently labeled `**Arg0`, not `*attacker`.

Two clean repetitions per authority on the same 15-of-338 fixed-work boundary
produce:

| policy | Z3 raw | Axeyum raw | normal high confidence | raw relation |
|---|---:|---:|---:|---|
| AnyModel | 128 | 126 | 0 / 0 | two Z3-only `**Arg0` double-fetch diagnostics |
| least unsigned | 110 | 110 | 0 / 0 | exact authority parity |

AnyModel remains a useful rejected raw-parity control. It is no longer evidence
that Z3 authority found two true double fetches that Axeyum missed. Likewise,
least-unsigned exact raw parity is not finding preservation: this bounded slice
contains no accepted finding under the existing confidence policy.

## Measurement consequence

Future policy sweeps must publish separate populations:

1. all raw diagnostics, for deterministic explorer and authority accounting;
2. confidence-gated findings, for the tool's user-visible output;
3. manually or independently labeled true/false positives, for coverage and
   precision claims.

No policy is Pareto-dominant merely because it maximizes raw sink count. Select
a fixed-work corpus with nonzero labeled positives before using finding recall
as an acceptance gate. Keep raw losses and additions visible, but do not treat
the arbitrary-model raw union as ground truth.

Boundary-set or diverse enumeration remains a configuration sweep under the A0
contract. Symbolic memory remains the only architectural item and starts only
if the corrected, labeled sweep leaves measured headroom.

## Machine-readable confidence partition

`IOCTLANCE_ALL=1` historically exposed the complete raw population but gave a
consumer no reliable way to distinguish rows that normal ioctlance output
would accept from rows retained only for diagnostics. Counting the raw lines
or scraping taint strings would duplicate producer policy in every benchmark
harness and could silently drift when the policy changed.

`IOCTLANCE_ANNOTATE_CONFIDENCE=1` now appends one producer-owned annotation to
each already-sorted finding line:

```text
confidence=high
confidence=diagnostic
```

The annotation is opt-in and applied only when printing, so output is
byte-for-byte unchanged for every legacy invocation. An annotated run also
ends with an exhaustive footer:

```text
[finding-confidence] schema=glaurung-ioctlance-confidence-v1 high=N diagnostic=M
```

The two counts partition the emitted population. With `IOCTLANCE_ALL=1`, the
ordinary `[ioctlance] high-confidence=` field reports the actual accepted
count, while `suppressed=` reports the diagnostic population that a normal run
would omit. Consumers can therefore reject missing, mixed, unknown, or
non-exhaustive annotations instead of guessing.

Two focused tests keep nested `ArgN` ancestry diagnostic and prove that adding
either annotation leaves the underlying finding bytes unchanged. The Axeyum
authority harness consumes this schema as two explicit populations while
retaining the annotation-free raw line for historical hashes and set
comparisons.
