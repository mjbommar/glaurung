"""CLI: ``python -m glaurung.bench`` — run the benchmark harness."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, List

from .harness import (
    DECOMPILE_TIMEOUT_MS,
    DEFAULT_MAX_DECOMPILE_FUNCTIONS,
    DEFAULT_MAX_FUNCTIONS,
    run_harness,
    to_json,
    to_markdown,
)


# Default ELF/Mach-O/PE detection: a binary is anything whose first four
# bytes are an executable magic and whose path is a file (not a script).
_EXEC_MAGICS = (
    b"\x7fELF",
    b"MZ",  # PE / DOS stub
    b"\xca\xfe\xba\xbe",  # Mach-O fat
    b"\xcf\xfa\xed\xfe",  # Mach-O 64 LE
    b"\xfe\xed\xfa\xcf",  # Mach-O 64 BE
)


def _looks_like_binary(p: Path) -> bool:
    if not p.is_file():
        return False
    # Skip metadata sidecars and obvious non-binaries early.
    name = p.name
    if name.endswith(".json") or name.endswith(".md") or name.endswith(".txt"):
        return False
    try:
        with p.open("rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return any(head.startswith(m) for m in _EXEC_MAGICS)


def _discover_binaries(roots: Iterable[Path], explicit: Iterable[Path]) -> List[Path]:
    out: List[Path] = []
    seen: set[str] = set()

    for p in explicit:
        rp = p.resolve()
        if rp.exists() and str(rp) not in seen:
            seen.add(str(rp))
            out.append(p)

    for root in roots:
        for p in sorted(root.rglob("*")):
            if not _looks_like_binary(p):
                continue
            rp = p.resolve()
            if str(rp) in seen:
                continue
            seen.add(str(rp))
            out.append(p)
    return out


# A small, fixed CI matrix that's fast and exercises every code path
# we care about: name resolution, .cold chunk merge, callgraph,
# Fortran/C++/C decompilation. Keep this list short.
DEFAULT_CI_MATRIX = [
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2",
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2",
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
    "samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O2",
    "samples/binaries/platforms/linux/amd64/export/native/clang/O2/hello-c-clang-O2",
    "samples/binaries/platforms/linux/amd64/export/native/clang/O2/hello-cpp-clang++-O2",
]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m glaurung.bench",
        description="Glaurung deterministic benchmark harness (#159)",
    )
    p.add_argument(
        "--root", type=Path, action="append", default=[],
        help="Recursively search this directory for binaries. Can repeat.",
    )
    p.add_argument(
        "--binary", type=Path, action="append", default=[],
        help="Explicit binary path. Can repeat.",
    )
    p.add_argument(
        "--ci-matrix", action="store_true",
        help="Use the built-in CI matrix (small, fast, language coverage).",
    )
    p.add_argument(
        "--output", type=Path, default=None,
        help="Write JSON scorecard to this path (defaults to stdout).",
    )
    p.add_argument(
        "--markdown", type=Path, default=None,
        help="Write Markdown summary to this path. If omitted and --output "
        "is set, writes alongside as .md.",
    )
    p.add_argument(
        "--max-functions", type=int, default=DEFAULT_MAX_FUNCTIONS,
        help="Cap on functions analysed per binary.",
    )
    p.add_argument(
        "--max-decompile-functions", type=int, default=DEFAULT_MAX_DECOMPILE_FUNCTIONS,
        help="Cap on functions decompiled per binary.",
    )
    p.add_argument(
        "--decompile-timeout-ms", type=int, default=DECOMPILE_TIMEOUT_MS,
        help="Per-function decompile timeout in ms.",
    )
    p.add_argument("--quiet", action="store_true", help="Hide per-binary progress.")
    args = p.parse_args(argv)

    explicit = list(args.binary)
    if args.ci_matrix:
        explicit.extend(Path(s) for s in DEFAULT_CI_MATRIX if Path(s).exists())

    binaries = _discover_binaries(args.root, explicit)
    if not binaries:
        print("error: no binaries to score (use --root, --binary, or --ci-matrix)", file=sys.stderr)
        return 2

    summary = run_harness(
        binaries,
        max_functions=args.max_functions,
        max_decompile_functions=args.max_decompile_functions,
        decompile_timeout_ms=args.decompile_timeout_ms,
        progress=not args.quiet,
    )

    payload = to_json(summary)
    if args.output:
        args.output.write_text(payload)
        print(f"wrote {args.output}")
    else:
        print(payload)

    md_path = args.markdown
    if md_path is None and args.output:
        md_path = args.output.with_suffix(".md")
    if md_path:
        md_path.write_text(to_markdown(summary))
        print(f"wrote {md_path}")

    # Exit code reflects whether any binary errored — useful for CI gating.
    return 1 if summary.errored else 0


if __name__ == "__main__":
    sys.exit(main())
