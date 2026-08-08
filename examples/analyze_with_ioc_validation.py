"""List byte-derived IOC candidates and optionally request model judgements."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import glaurung as g
from glaurung.llm.agents.ioc_validator_v2 import (
    IOCCandidate,
    IOCType,
    validate_iocs_v2,
)
from glaurung.llm.config import get_config

IOC_TYPE_BY_SAMPLE_KIND = {
    "ipv4": IOCType.IPV4,
    "ipv6": IOCType.IPV6,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.HOSTNAME,
    "url": IOCType.URL,
    "email": IOCType.EMAIL,
    "path_windows": IOCType.FILE_PATH,
    "path_posix": IOCType.FILE_PATH,
    "path_unc": IOCType.FILE_PATH,
    "registry": IOCType.REGISTRY_KEY,
}


def analyze_for_iocs(path: Path) -> Any:
    """Triage a path with bounded sampling sized for the IOC demonstration."""
    return g.triage.analyze_path(
        str(path),
        10_485_760,
        104_857_600,
        1,
        4,
        200,
        False,
        0,
        True,
        500,
        32,
    )


def extract_supported_candidates(
    artifact: Any, *, max_candidates: int = 20
) -> list[IOCCandidate]:
    """Return supported IOC samples copied from a triage artifact.

    Args:
        artifact: A native ``TriagedArtifact``.
        max_candidates: Maximum supported candidates to retain.

    Returns:
        Candidate objects whose values and offsets came from the artifact.
    """
    strings = getattr(artifact, "strings", None)
    samples = getattr(strings, "ioc_samples", None) if strings else None
    if not samples:
        return []

    candidates: list[IOCCandidate] = []
    for sample in samples:
        ioc_type = IOC_TYPE_BY_SAMPLE_KIND.get(str(sample.kind))
        if ioc_type is None:
            continue
        candidates.append(
            IOCCandidate(
                value=str(sample.text),
                ioc_type=ioc_type,
                offset=getattr(sample, "offset", None),
                context=None,
            )
        )
        if len(candidates) >= max_candidates:
            break
    return candidates


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Binary to inspect")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Ask the configured model to judge the extracted candidates",
    )
    parser.add_argument("--model", help="Optional configured model override")
    parser.add_argument("--max-candidates", type=int, default=20)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the candidate listing and optional validation workflow."""
    args = build_parser().parse_args(argv)
    if not args.binary.is_file():
        build_parser().error(f"binary does not exist: {args.binary}")
    if args.max_candidates < 1:
        build_parser().error("--max-candidates must be positive")

    artifact = analyze_for_iocs(args.binary)
    candidates = extract_supported_candidates(
        artifact, max_candidates=args.max_candidates
    )
    print(f"binary: {args.binary}")
    print(f"size_bytes: {artifact.size_bytes}")
    print(f"supported IOC candidates: {len(candidates)}")
    for index, candidate in enumerate(candidates):
        print(
            f"  {index}: {candidate.ioc_type.value} {candidate.value!r} "
            f"offset={candidate.offset!r}"
        )

    if not args.validate:
        print("validation: not requested; candidates are untrusted observations")
        return 0

    config = get_config()
    if not any(config.available_models().values()):
        print("validation: unavailable; configure a supported model first")
        return 3

    validated, accepted_count, rejected_count = validate_iocs_v2(
        candidates,
        binary_format=(str(artifact.verdicts[0].format) if artifact.verdicts else None),
        model=args.model,
    )
    print(f"model-accepted candidates: {accepted_count}")
    print(f"model-rejected candidates: {rejected_count}")
    print("These are model judgements, not confirmed threat intelligence.")
    for row in validated:
        decision = "accepted" if row.is_valid else "rejected"
        print(f"  {decision}: {row.value!r} ({row.confidence}) {row.reasoning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
