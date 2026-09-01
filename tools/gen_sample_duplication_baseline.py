#!/usr/bin/env python3
"""Record the current byte-duplication in `samples/`.

See `python/tests/test_sample_corpus_duplication.py` for why this ratchets
instead of deduplicating: 6 of the 75 groups have every copy referenced by
literal path, and much of the suite globs over `samples/**` rather than naming
files, so a deletion sweep would shrink test populations silently.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python" / "tests"))

from test_sample_corpus_duplication import (  # ty: ignore[unresolved-import]
    BASELINE,
    duplicate_groups,
    redundant_bytes,
)


def main() -> int:
    groups = duplicate_groups()
    payload = {
        "groups": len(groups),
        "redundant_bytes": redundant_bytes(groups),
        "note": (
            "Byte-identical files under samples/. Ratcheted, not deduplicated "
            "-- see the test module docstring."
        ),
        "inventory": {
            h[:16]: paths for h, paths in sorted(groups.items(), key=lambda kv: kv[0])
        },
    }
    BASELINE.write_text(json.dumps(payload, indent=1) + "\n")
    print(
        f"{BASELINE.relative_to(ROOT)}: {payload['groups']} groups, "
        f"{payload['redundant_bytes'] / 1e6:.1f} MB redundant"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
