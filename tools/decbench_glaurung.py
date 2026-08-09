#!/usr/bin/env python3
"""Register Glaurung as an out-of-tree DecBench backend.

DecBench does not discover external Python entry points.  This launcher runs
inside DecBench's own virtual environment, registers the Glaurung backend, and
then delegates to its normal CLI.  Glaurung itself remains isolated in its own
environment and is driven through ``$GLAURUNG_BIN``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)

ROOT = Path(__file__).resolve().parent.parent


@register_decompiler("glaurung")
class GlaurungDecompiler(Decompiler):
    """Raw Glaurung backend using the parseable-C batch CLI."""

    name = "glaurung"
    display_name = "Glaurung"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)

    @staticmethod
    def _binary() -> str | None:
        configured = os.environ.get("GLAURUNG_BIN")
        if configured:
            path = Path(configured)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            return None
        return shutil.which("glaurung")

    def is_available(self) -> bool:
        return self._binary() is not None

    def get_version(self) -> str | None:
        """Bind metric artifacts to the exact Glaurung Git revision."""
        configured = os.environ.get("GLAURUNG_VERSION")
        if configured:
            return configured
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        revision = result.stdout.strip()
        return f"git-{revision}" if result.returncode == 0 and revision else "unknown"

    def _run_batch(
        self, binary_path: Path, requested_addresses: set[int] | None = None
    ) -> list[dict[str, Any]]:
        executable = self._binary()
        if executable is None:
            raise RuntimeError("GLAURUNG_BIN does not name an executable")
        env = dict(os.environ, NO_COLOR="1", TERM="dumb")
        env.pop("FORCE_COLOR", None)
        selectors = (
            ["--vas", ",".join(hex(address) for address in sorted(requested_addresses))]
            if requested_addresses
            else ["--all", "--limit", "2000"]
        )
        result = subprocess.run(
            [
                executable,
                "decompile",
                str(binary_path),
                *selectors,
                "--style",
                "decbench",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=self.config.binary_timeout_seconds,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            diagnostic = " ".join((result.stderr or result.stdout).split())[-1000:]
            raise RuntimeError(
                f"glaurung exited {result.returncode}: {diagnostic or 'no output'}"
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"glaurung emitted invalid JSON: {exc}") from exc
        if not isinstance(payload, list):
            raise TypeError("glaurung batch output is not a JSON list")
        return [record for record in payload if isinstance(record, dict)]

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | set[str] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Decompile one binary and return DecBench's canonical result shape."""
        if not self.is_available():
            raise RuntimeError("Decompiler 'glaurung' is not available")

        started = time.monotonic()
        requested_addresses = {address for _name, address in functions or []}
        requested_addresses.update(
            selector
            for selector in function_names or ()
            if isinstance(selector, int) and not isinstance(selector, bool)
        )
        requested_names = {
            selector for selector in function_names or () if isinstance(selector, str)
        }
        records = self._run_batch(binary_path, requested_addresses or None)
        text_range = common.elf_text_range(binary_path)
        requested = set(functions or [])
        enumerated: list[tuple[str, int, str]] = []
        for record in records:
            name = record.get("name")
            address = record.get("entry_va")
            code = record.get("pseudocode")
            if not isinstance(name, str) or not isinstance(address, int):
                continue
            if not isinstance(code, str) or not code.strip():
                continue
            address_requested = address in requested_addresses or any(
                (address & ~1) == (requested & ~1) for requested in requested_addresses
            )
            # Some embedded linkers retain one section per function instead of
            # folding every `.text.*` input section into the output `.text`.
            # An exact source/DWARF address request is stronger evidence than
            # the ordinary whole-binary `.text` filter in that case.
            if (
                common.should_skip_function(name, address, text_range)
                and not address_requested
            ):
                continue
            if requested and (name, address) not in requested:
                continue
            enumerated.append((name, address, code))

        candidates = [(name, address) for name, address, _code in enumerated]
        if requested_addresses:
            narrowed = common.narrow_to_source(
                candidates,
                requested_addresses,
                backend=self.name,
                binary_name=binary_path.name,
            )
        elif requested_names:
            # Current DecBench project runs narrow by source name. Glaurung's
            # batch CLI accepts addresses, so enumerate once and apply the name
            # contract here. Preserve DecBench's fail-open fallback when an
            # unexpected symbol spelling matches nothing; returning an empty
            # result would silently shrink the evaluator denominator.
            narrowed = [item for item in candidates if item[0] in requested_names]
            if not narrowed:
                narrowed = candidates
        else:
            narrowed = candidates
        allowed = set(narrowed)
        decompiled: dict[str, FunctionDecompilation] = {}

        def metadata(partial: bool) -> DecompilerMetadata:
            extra: dict[str, Any] = {"backend": "glaurung", "via": "cli-json"}
            if partial:
                extra["partial"] = True
            return DecompilerMetadata(
                decompiler_name=self.id,
                decompiler_version=self.get_version(),
                total_time_seconds=time.monotonic() - started,
                extra=extra,
            )

        for name, address, code in enumerated:
            if (name, address) not in allowed:
                continue
            decompiled[name] = FunctionDecompilation(
                name=name,
                address=address,
                decompiled_code=code,
                line_count=code.count("\n") + 1,
                variables=[],
                line_mappings=[],
                metadata=common.extract_metrics(code),
            )
            if progress_path is not None:
                common.dump_progress(
                    progress_path,
                    DecompilationResult(
                        binary_path=binary_path,
                        binary_name=binary_path.stem,
                        decompiler=metadata(partial=True),
                        functions=dict(decompiled),
                        output_dir=output_dir,
                    ),
                )

        result = DecompilationResult(
            binary_path=binary_path,
            binary_name=binary_path.stem,
            decompiler=metadata(partial=False),
            functions=decompiled,
            output_dir=output_dir,
        )
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            result.to_c_file(output_dir / f"{self.name}_{binary_path.stem}.c")
            result.to_toml(output_dir / f"{self.name}_{binary_path.stem}.toml")
        return result


def _probe(binary_path: Path) -> int:
    backend = GlaurungDecompiler()
    result = backend.decompile_binary(binary_path)
    print(
        json.dumps(
            {
                "decompiler": result.decompiler.decompiler_name,
                "version": result.decompiler.decompiler_version,
                "functions": {
                    name: function.address
                    for name, function in result.functions.items()
                },
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--probe":
        return _probe(Path(sys.argv[2]))
    from decbench.cli import main as decbench_main

    decbench_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
