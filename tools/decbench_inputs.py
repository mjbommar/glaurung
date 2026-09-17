"""Prepare checked, stripped inputs for local DecBench replay."""

import hashlib
import pathlib
import re
import shutil
import subprocess


def find_binary(directory: pathlib.Path, stem: str) -> pathlib.Path | None:
    """Resolve an exact filename or a unique exact stem; reject prefix matches."""
    if not directory.is_dir():
        return None
    exact = directory / stem
    if exact.is_file():
        return exact
    candidates = sorted(
        p for p in directory.iterdir() if p.is_file() and p.stem == stem
    )
    if len(candidates) > 1:
        raise RuntimeError(f"ambiguous exact-stem binary {stem}: {candidates}")
    return candidates[0] if candidates else None


def normalise_address(binary: pathlib.Path, address: int) -> int:
    """Normalise only ARM ELF's Thumb marker when matching output identities."""
    with binary.open("rb") as handle:
        header = handle.read(20)
    if len(header) >= 20 and header[:4] == b"\x7fELF" and header[5] in (1, 2):
        order = "little" if header[5] == 1 else "big"
        if int.from_bytes(header[18:20], order) == 40:
            return address & ~1
    return address


def strip_copy(source: pathlib.Path, destination: pathlib.Path) -> dict[str, str]:
    """Strip a copy, fail on tool errors, validate symbols, and return hashes."""
    original = source.read_bytes()
    is_elf = original[:4] == b"\x7fELF"
    tool = (
        (shutil.which("llvm-strip") or shutil.which("strip"))
        if is_elf
        else shutil.which("strip")
    )
    if tool is None:
        raise RuntimeError(f"no strip tool available for {source}")
    if source.resolve() == destination.resolve():
        raise ValueError("stripped destination must differ from source")
    shutil.copy2(source, destination)
    subprocess.run(
        [tool, "--strip-all", str(destination)],
        capture_output=True,
        text=True,
        check=True,
    )
    if is_elf:
        output = subprocess.run(
            ["readelf", "-SW", str(destination)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        if re.search(r"\.(?:symtab\b|debug[_.]|zdebug)", output):
            raise RuntimeError(
                f"symbol/debug sections survived stripping: {destination}"
            )
        validation = "ELF: no symtab or debug sections"
    else:
        output = subprocess.run(
            [
                "llvm-readobj",
                "--file-headers",
                "--sections",
                "--coff-debug-directory",
                str(destination),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        if re.search(r"SymbolCount: (?!0\b)\d+", output) or re.search(
            r"Name: \.(?:debug|zdebug)", output
        ):
            raise RuntimeError(
                f"COFF symbol/debug records survived stripping: {destination}"
            )
        validation = "COFF: checked symbol count and debug sections"
    return {
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "stripped_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "validation": validation,
    }
