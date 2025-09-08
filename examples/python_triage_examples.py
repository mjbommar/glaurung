"""
Simple examples for using the Python API.

Run with: uv run python examples/python_triage_examples.py <path>
"""
from __future__ import annotations
import sys
import glaurung as g


def main(path: str) -> int:
    # Basic triage with default budgets
    art = g.triage.analyze_path(path, 10_485_760, 104_857_600, 2, 4, 40, True, 100, True, 200, 16)
    print(f"Top verdicts: {len(art.verdicts)}; size={art.size_bytes} bytes")
    if art.symbols is not None:
        print(
            "Symbols:",
            f"imports={art.symbols.imports_count}",
            f"exports={art.symbols.exports_count}",
            f"libs={art.symbols.libs_count}",
        )
    if art.budgets is not None:
        b = art.budgets
        extra = []
        if b.limit_bytes is not None:
            extra.append(f"limit_bytes={b.limit_bytes}")
        if b.max_recursion_depth is not None:
            extra.append(f"max_depth={b.max_recursion_depth}")
        print(
            "Budgets:",
            f"bytes_read={b.bytes_read}",
            f"time_ms={b.time_ms}",
            f"depth={b.recursion_depth}",
            f"hit_byte_limit={b.hit_byte_limit}",
            " ".join(extra),
        )

    # JSON round-trip is deterministic
    j1 = art.to_json()
    back = g.TriagedArtifact.from_json(j1)
    j2 = back.to_json()
    assert j1 == j2
    print("JSON determinism OK")

    # Inspect environment hints for PE/Mach-O if needed
    try:
        env = g.analyze_env(path)
        print("Env keys:", list(env.keys()))
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python examples/python_triage_examples.py <path>")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
