"""Inspect the candidate-bound IOC V2 schema using a real checked-in sample."""

from __future__ import annotations

from pathlib import Path

from analyze_with_ioc_validation import analyze_for_iocs, extract_supported_candidates
from glaurung.llm.agents.ioc_validator_v2 import IOCValidationDecision

SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/c2_demo-gcc-O0"
)


def main() -> int:
    """Show that model decisions cannot carry a replacement IOC value."""
    if not SAMPLE.is_file():
        raise FileNotFoundError(SAMPLE)

    artifact = analyze_for_iocs(SAMPLE)
    candidates = extract_supported_candidates(artifact)
    if not candidates:
        raise RuntimeError("the checked-in sample produced no supported IOC candidates")

    decision_fields = set(IOCValidationDecision.model_fields)
    assert "candidate_index" in decision_fields
    assert "value" not in decision_fields

    print(f"sample: {SAMPLE}")
    print(f"candidate count: {len(candidates)}")
    print(f"decision fields: {sorted(decision_fields)}")
    print("The decision schema has an index but no value field.")
    print("Post-processing must copy each value from the indexed candidate.")
    print("This constrains value provenance; it does not validate maliciousness.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
