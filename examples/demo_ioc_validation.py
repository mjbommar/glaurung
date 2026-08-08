"""Demonstrate IOC Validator V2 with a real checked-in binary."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from analyze_with_ioc_validation import analyze_for_iocs, extract_supported_candidates
from glaurung.llm.agents.ioc_validator_v2 import validate_iocs_v2
from glaurung.llm.config import get_config

DEFAULT_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/c2_demo-gcc-O0"
)


def main(argv: Sequence[str] | None = None) -> int:
    """List real candidates and optionally obtain candidate-bound decisions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--model")
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")

    artifact = analyze_for_iocs(args.binary)
    candidates = extract_supported_candidates(artifact)
    print(f"binary: {args.binary}")
    print(f"byte-derived candidates: {len(candidates)}")
    for index, candidate in enumerate(candidates):
        print(f"  {index}: {candidate.ioc_type.value} {candidate.value!r}")

    if not args.validate:
        print("No model was called. Add --validate to request model judgements.")
        return 0

    config = get_config()
    if not any(config.available_models().values()):
        print("No supported model is configured.")
        return 3

    rows, accepted, rejected = validate_iocs_v2(candidates, model=args.model)
    print(f"model accepted={accepted} rejected={rejected}")
    print("The V2 guarantee binds values to candidates; it does not prove risk.")
    for row in rows:
        print(f"  {row.is_valid}: {row.value!r} - {row.reasoning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
