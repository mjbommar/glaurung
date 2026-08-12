# IOC Validator V2: candidate-bound decisions

> **Status: maintained security design and compatibility implementation.** The
> live implementation is
> `python/glaurung/llm/agents/ioc_validator_v2.py`; focused schema and
> post-processing tests are in `python/tests/test_ioc_validator_v2.py`.

The V2 contract prevents the model from introducing a new IOC value in its
validation response. It does **not** prove that an input candidate is present in
the binary, malicious, or correctly classified. Candidate extraction,
validation judgement, and downstream impact remain separate evidence stages.

## Security property

The model receives a numbered list of `IOCCandidate` objects and returns
`IOCValidationDecision` objects containing a `candidate_index`, verdict,
confidence, reasoning, and optional labels. The model output schema has no IOC
value field.

Post-processing constructs each `ValidatedIOC` by copying `value`, `ioc_type`,
offset, and context from the original candidate at that index. Consequently,
every returned value originates in the caller-supplied candidate list.

This is the guaranteed invariant:

```text
for every output row v:
    v.value == candidates[i].value for one caller-supplied index i
```

It is deliberately narrower than “hallucination-proof analysis.” If an
upstream extractor or caller supplies an invented value, this layer preserves
it. The model can also make a wrong accept/reject decision or unsupported risk
claim.

## Current behavior

- Duplicate decision indices are rejected by the Pydantic output model.
- A missing decision fails closed for that candidate: it is returned invalid
  with confidence `0.5` and a “No validation decision provided” reason.
- An out-of-range decision does not create an output row; it is ignored when
  the candidate-index map is joined back to the input list.
- `filter_iocs_from_artifact_v2(...)` currently takes
  `artifact.strings.ioc_samples[:max_batch_size]` before it filters by sample
  kind. It maps unrecognized sample kinds to `IOCType.HOSTNAME`, so generic
  samples can consume batch slots or be mislabeled. The maintained examples
  avoid this compatibility limitation by selecting supported IOC kinds before
  applying their cap; it is not a security guarantee of the helper.
- Empty input returns an empty list and zero counts without invoking a model.
- The returned `tp_count` and `fp_count` names are compatibility terminology.
  They count model-accepted and model-rejected candidates, not independently
  established ground truth.
- `confidence` is currently a plain float. The schema does not constrain it to
  `[0, 1]`; callers must not assume that bound until the model adds validation.

## API

Import the V2 compatibility API from its actual module:

```python
from glaurung.llm.agents.ioc_validator_v2 import (
    IOCCandidate,
    IOCType,
    filter_iocs_from_artifact_v2,
    validate_iocs_v2,
)
```

`validate_iocs_v2(candidates, ...)` returns all candidates with their joined
decisions plus the two compatibility counts.
`filter_iocs_from_artifact_v2(artifact, ...)` extracts IOC samples already
present on a triage artifact, validates them, and returns only accepted rows,
subject to the batching and fallback behavior described above.

Model selection uses the normal Glaurung LLM configuration. See
[`docs/llm/README.md`](llm/README.md) and the
[runtime configuration guide](development/setup.md#runtime-configuration).

## Validation boundary

Run the focused contract tests with:

```bash
uv run pytest python/tests/test_ioc_validator_v2.py -q
```

Those tests use controlled model-output objects to verify schema joining and
fail-closed behavior. They do not exercise a live model or establish semantic
IOC accuracy. A live evaluation must additionally preserve the input artifact,
extracted candidate evidence, exact model/configuration identity, raw decision,
and an independently labeled expected result.

## Extension rules

Keep the value-free decision schema. If the model needs to propose a new IOC,
place that in a separate, explicitly untrusted discovery output and require an
independent byte-level provenance check before promotion. Do not merge proposed
values into this validation response.

When changing the contract, add tests for duplicate, missing, negative, and
out-of-range indices; empty input; repeated values at distinct indices; and
confidence validation. Update the implementation, exported typing surface, and
this guide together.
