#!/usr/bin/env python3
"""Emit the labelled mutant corpus that scores the S5 equivalence checker.

The ground truth is not invented here. Every rewrite and every
``changes_behaviour`` label comes from ``tools/metric_mutation.py``'s
``CATALOGUE`` -- the same 15 semantics-changing and 14 semantics-preserving
classes, applied with the same seeded generator
(``random.Random(f"{seed}|{unit key}|{class}")``), so a cell here and a cell in
the GED/tree-distance scorecard are the same experiment on the same mutant.
This tool only chooses the corpus and writes the pairs out; the verdicts are
computed in Rust by
``src/csource/equiv/scorecard_tests.rs``.

Why a different corpus from ``metric_mutation.py``'s. That harness scores
metrics that need only a CFG, so it can run on any function that parses. The
equivalence checker needs both sides *lowered to LLIR and executed*, and
``src/csource/lower`` covers scalar integer C only -- 168 of the 900 functions
in ``tests/decompiler_fixtures/src`` at the time of writing. So the corpus is
that fixture tree, each function carved out as a standalone translation unit.
The syntactic prefilter below is an efficiency measure only: the Rust side
re-checks by attempting the real lowering and reports a refusal as a decline,
so a prefilter that lets something through costs a line in the output and
nothing else.

    export TMPDIR="$HOME/.cache/glaurung/tmp"
    uv run python tools/equiv_mutants.py                 # the default corpus
    uv run python tools/equiv_mutants.py --limit 40      # a smaller sweep

Output is JSON Lines, one record per (function, mutation class), written to
``tests/csource_equiv/mutants.jsonl`` -- a generated, gitignored corpus in the
same spirit as ``tests/decompiler_fixtures/build/``. Regenerate it rather than
edit it.

Exit codes: 0 when the run produced mutants; 1 when it produced none, because a
generator that emitted nothing must not read as a success; 2 when the fixture
corpus is missing.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import re
import sys
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parent.parent

#: The single-construct C corpus the lowering was scoped to.
DEFAULT_CORPUS = ROOT / "tests" / "decompiler_fixtures" / "src"

#: Where the Rust scorecard test looks for the corpus.
DEFAULT_OUTPUT = ROOT / "tests" / "csource_equiv" / "mutants.jsonl"

#: The same default seed as `metric_mutation.py`. Changing it is a new
#: experiment, not a re-run.
DEFAULT_SEED = 20260904

#: Constructs `src/csource/lower` refuses outright. Purely an efficiency filter
#: (see the module docstring); the Rust side is the authority. `*` is
#: deliberately absent -- it is multiplication as often as it is a pointer, and
#: blocking it dropped the corpus from 168 functions to 24.
_BLOCKED = re.compile(
    r"[\[\]]|\bstruct\b|\bunion\b|\benum\b|\bfloat\b|\bdouble\b|\bswitch\b"
    r"|\bgoto\b|\bstatic\b|\bextern\b|\btypedef\b|\basm\b|->"
)

#: Keywords that may be followed by `(` without that being a call.
_NOT_A_CALL = frozenset(
    {"if", "while", "for", "switch", "return", "sizeof", "do", "_Alignof"}
)


def _load_harness():
    """Import `tools/metric_mutation.py` as a module.

    Returns:
        The imported module, whose `CATALOGUE`, `split_functions`, `code_mask`
        and `Declined` this tool reuses.

    Raises:
        ImportError: If the harness cannot be loaded.
    """
    path = ROOT / "tools" / "metric_mutation.py"
    spec = importlib.util.spec_from_file_location("metric_mutation", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` resolves a class's module through `sys.modules`, so a
    # module executed without being registered there raises on the first
    # `@dataclass` it defines.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _has_call(harness, text: str) -> bool:
    """Whether `text` contains a call expression.

    Args:
        harness: The imported `metric_mutation` module.
        text: One function's text.

    Returns:
        True when an identifier that is not a control keyword is applied.
    """
    mask = harness.code_mask(text)
    for match in harness.code_sites(text, harness._CALL_RE, mask):
        if match.group(1) not in _NOT_A_CALL:
            return True
    return False


def units(harness, corpus: Path, limit: int | None) -> Iterator[tuple[str, str, str]]:
    """Standalone function texts from the fixture corpus, in a stable order.

    Args:
        harness: The imported `metric_mutation` module.
        corpus: The directory of `.c` fixture sources.
        limit: Stop after this many units, or None for all.

    Yields:
        ``(unit key, function name, function text)``.
    """
    produced = 0
    for path in sorted(corpus.glob("*.c")):
        text = path.read_text(errors="replace")
        for name, piece in harness.split_functions(text):
            body = piece[piece.find("{") :] if "{" in piece else piece
            if _BLOCKED.search(piece) or _has_call(harness, body):
                continue
            yield f"{path.name}::{name}", name, piece
            produced += 1
            if limit is not None and produced >= limit:
                return


def emit(harness, corpus: Path, output: Path, seed: int, limit: int | None) -> int:
    """Write the mutant corpus.

    Args:
        harness: The imported `metric_mutation` module.
        corpus: The fixture source directory.
        output: The JSONL file to write.
        seed: The experiment seed.
        limit: Maximum units to walk.

    Returns:
        The number of records written.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output.open("w", encoding="utf-8") as handle:
        for key, name, text in units(harness, corpus, limit):
            for mutation in harness.CATALOGUE:
                rng = random.Random(f"{seed}|{key}|{mutation.name}")
                try:
                    mutated = mutation.apply(text, rng)
                except harness.Declined:
                    continue
                if mutated == text:
                    continue
                handle.write(
                    json.dumps(
                        {
                            "unit": key,
                            "name": name,
                            "class": mutation.name,
                            "changes": mutation.changes,
                            "original": text,
                            "mutant": mutated,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
                written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments, or None to read `sys.argv`.

    Returns:
        The process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="stop after this many source functions (default: all)",
    )
    args = parser.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 2
    harness = _load_harness()
    written = emit(harness, args.corpus, args.output, args.seed, args.limit)
    print(
        f"wrote {written} mutant pairs to {args.output} "
        f"(seed {args.seed}, catalogue v{harness.CATALOGUE_VERSION})"
    )
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
