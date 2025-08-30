#!/usr/bin/env python3
"""
Generate an index manifest for built/collected samples.
Scans samples/binaries and emits samples/binaries/index.json with per-file
size, sha256, and `file`-type (when available), plus tool versions snapshot.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "samples" / "binaries"
INDEX_PATH = BIN_DIR / "index.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_type(path: Path) -> Optional[str]:
    file_cmd = shutil.which("file")
    if not file_cmd:
        return None
    try:
        out = subprocess.check_output([file_cmd, "-b", str(path)], text=True)
        return out.strip()
    except Exception:
        return None


def cmd_version(cmd: str) -> Optional[str]:
    exe = shutil.which(cmd)
    if not exe:
        return None
    try:
        out = subprocess.check_output([exe, "--version"], text=True, stderr=subprocess.STDOUT)
        return out.splitlines()[0]
    except Exception:
        return None


def collect_tool_versions() -> Dict[str, Optional[str]]:
    tools = [
        "gcc",
        "clang-20",
        "gfortran-15",
        "javac",
        "jar",
        "python3",
        "ldd",
        "file",
    ]
    return {t: cmd_version(t) for t in tools}


def scan_binaries(base: Path) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    if not base.exists():
        return entries
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(base)
        try:
            size = p.stat().st_size
            entries.append(
                {
                    "path": str(rel),
                    "size": size,
                    "sha256": sha256_file(p),
                    "type": file_type(p),
                }
            )
        except Exception as e:
            entries.append({"path": str(rel), "error": str(e)})
    entries.sort(key=lambda x: str(x.get("path", "")))
    return entries


def main() -> int:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "root": str(BIN_DIR),
        "generated_at": subprocess.check_output(["date", "-Iseconds"], text=True).strip(),
        "host": subprocess.check_output(["hostname"], text=True).strip(),
        "tools": collect_tool_versions(),
        "files": scan_binaries(BIN_DIR),
    }
    INDEX_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {INDEX_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

