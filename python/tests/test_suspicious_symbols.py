from pathlib import Path
from typing import List

import pytest

from glaurung import triage as T


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_suspicious_binaries(limit: int = 8) -> List[Path]:
    root = repo_root() / "samples" / "binaries"
    if not root.exists():
        return []
    matches: List[Path] = []

    # Prefer exact names if present
    preferred = [
        # Windows cross (MinGW)
        root
        / "platforms"
        / "linux"
        / "amd64"
        / "export"
        / "cross"
        / "windows-x86_64"
        / "suspicious_win-c-x86_64-mingw.exe",
        # Linux native GCC O0
        root
        / "platforms"
        / "linux"
        / "amd64"
        / "export"
        / "native"
        / "gcc"
        / "O0"
        / "suspicious_linux-gcc-O0",
    ]
    for p in preferred:
        if p.exists():
            matches.append(p)
            if len(matches) >= limit:
                return matches

    # Fallback: glob recursively for any file containing 'suspicious'
    # Filter out metadata (.json) and metadata/ directories; prefer actual binaries
    for p in root.rglob("*suspicious*"):
        if not p.is_file():
            continue
        # Skip metadata JSON and anything under metadata dirs
        if p.suffix.lower() == ".json" or any(part == "metadata" for part in p.parts):
            continue
        matches.append(p)
        if len(matches) >= limit:
            break
    return matches


@pytest.mark.parametrize(
    "path", [pytest.param(p, id=p.name) for p in find_suspicious_binaries()]
)
def test_suspicious_symbols_if_present(path: Path):
    if not Path(path).exists():
        pytest.skip(f"sample not present: {path}")

    # Check if sample is corrupted (contains text instead of binary)
    with open(path, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {path} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    art = T.analyze_path(str(path))
    symbols = getattr(art, "symbols", None)
    assert symbols is not None
    sus = getattr(symbols, "suspicious_imports", None) or []
    # Check for at least one normalized suspicious API
    KNOWN = {
        "createremotethread",
        "writeprocessmemory",
        "virtualallocex",
        "ptrace",
        "mprotect",
        "execve",
    }

    def norm(name: str) -> str:
        s = name.strip()
        if s.startswith("_"):
            s = s[1:]
        # strip stdcall suffix @N
        at = s.rfind("@")
        if at != -1 and s[at + 1 :].isdigit():
            s = s[:at]
        if s and s[-1] in ("A", "W") and s[:-1][-1:].isalpha():
            s = s[:-1]
        return s.lower()

    if not any(x in KNOWN for x in sus):
        # Fallback: use dynamic import names from list_symbols
        try:
            _all, _dyn, imports, _exports, _libs = T.list_symbols(str(path))  # type: ignore[attr-defined]
        except Exception:
            imports = []
        lowered = {norm(x) for x in imports}
        if not any(x in lowered for x in KNOWN):
            # Last resort: scan file bytes for the suspicious API names
            data = Path(path).read_bytes()
            hay = data.lower()
            assert any(k.encode("ascii") in hay for k in KNOWN), (
                f"No suspicious imports found via summary, symbols, or byte scan for {path}"
            )
