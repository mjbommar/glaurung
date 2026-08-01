#!/usr/bin/env python3
"""Emit one DecBench backend's exact function results as machine-readable JSON.

This helper runs under the DecBench checkout's Python environment.  It performs
decompilation only: behavioral comparison belongs to Glaurung's isolated
fixture harness, and graph metrics must not be repeated when they were already
measured at the same binary/backend revision.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

JSON_PREFIX = "__GLAURUNG_DECOMPILATION_JSON__="


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("backend")
    parser.add_argument("output", type=Path)
    parser.add_argument("--function", action="append", default=[])
    args = parser.parse_args()

    # The stock CLI imports this package for its registration side effects.
    # This lightweight helper deliberately bypasses the CLI, so it must make
    # the same import explicitly or a fresh process sees an empty registry.
    import decbench.decompilers  # noqa: F401

    if args.backend == "glaurung":
        import decbench_glaurung  # noqa: F401 - import registers the backend

    from decbench.pipeline.decompile import decompile_binary

    result = decompile_binary(
        args.binary,
        args.backend,
        args.output,
        function_names=set(args.function) or None,
    )
    payload = {
        "backend": result.decompiler.decompiler_name,
        "version": result.decompiler.decompiler_version,
        "failed_functions": result.decompiler.failed_functions,
        "functions": [
            {
                "name": function.name,
                "address": function.address,
                "code": function.decompiled_code,
            }
            for function in result.functions.values()
        ],
    }
    print(JSON_PREFIX + json.dumps(payload, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
