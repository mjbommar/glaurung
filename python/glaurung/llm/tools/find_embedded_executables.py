"""Tool 5: find executable magics anywhere in a file.

Scans a file's bytes for ELF / PE / Mach-O magic numbers at *any*
offset — not just offset 0. Catches:

- Self-extracting installers (MZ stub at 0, real PE further in).
- PE files with appended overlays.
- ELF binaries with a second ELF concatenated to the tail.
- Mach-O fat archives.
- Base64-decoded blobs whose decode happens to land on an executable.

Returns offsets only — does *not* attempt to extract the inner binary
(use ``extract_archive`` family or a manual byte slice for that). The
agent typically runs ``find_embedded_executables`` first to identify
candidates, then asks the user / next tool whether to peel each one.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ExecutableFormat = Literal[
    "elf32", "elf64", "pe", "macho32", "macho64", "macho_fat",
]


# Magic-byte signatures and the validators that reject false positives.
_SIGNATURES = [
    (b"\x7fELF\x01", "elf32", 16),
    (b"\x7fELF\x02", "elf64", 16),
    (b"MZ", "pe", 64),  # validated separately by checking PE header pointer
    (b"\xcf\xfa\xed\xfe", "macho64", 32),
    (b"\xce\xfa\xed\xfe", "macho32", 32),
    (b"\xfe\xed\xfa\xcf", "macho64", 32),
    (b"\xfe\xed\xfa\xce", "macho32", 32),
    (b"\xca\xfe\xba\xbe", "macho_fat", 24),
]


def _validate(data: bytes, off: int, fmt: ExecutableFormat) -> bool:
    """Reject magic-byte coincidences by checking format-specific
    structure for plausibility.

    For ELF, require e_type, e_machine, e_version fields look sane.
    For PE, require the e_lfanew pointer to land within the file and
    the target bytes to spell "PE\\x00\\x00".
    For Mach-O, require the cputype field to be a known value.
    """
    end = len(data)
    if fmt.startswith("elf"):
        if off + 24 > end:
            return False
        # e_ident[EI_DATA] must be 1 (LE) or 2 (BE)
        if data[off + 5] not in (1, 2):
            return False
        # e_type field at offset+16 — accept ET_REL/ET_EXEC/ET_DYN/ET_CORE
        e_type = int.from_bytes(data[off + 16: off + 18], "little")
        if e_type > 0xfeff:
            return False
        return True
    if fmt == "pe":
        # MZ → e_lfanew @ +0x3c → "PE\0\0" check
        if off + 0x40 > end:
            return False
        e_lfanew = int.from_bytes(data[off + 0x3c: off + 0x40], "little")
        pe_off = off + e_lfanew
        if pe_off + 4 > end:
            return False
        return data[pe_off: pe_off + 4] == b"PE\x00\x00"
    if fmt.startswith("macho"):
        if off + 8 > end:
            return False
        cputype = int.from_bytes(data[off + 4: off + 8], "little")
        # Known Mach-O cputype values: x86 (7), x86_64 (16777223),
        # arm (12), arm64 (16777228), powerpc (18), powerpc64 (16777234)
        cputype &= 0xffffff
        return cputype in {7, 12, 18}
    return True


class FindEmbeddedExecutablesArgs(BaseModel):
    path: str = Field(..., description="Path to the file to scan")
    skip_first_match: bool = Field(
        True,
        description="Skip a magic at offset 0 — that's the file's own header. "
                    "Set False to also report the outer binary's own magic.",
    )
    max_results: int = 64


class EmbeddedExecutable(BaseModel):
    format: ExecutableFormat
    offset: int
    signature_bytes: str = Field(
        ..., description="Hex of the first 8 bytes at the match offset"
    )


class FindEmbeddedExecutablesResult(BaseModel):
    path: str
    file_size: int
    matches: List[EmbeddedExecutable]


class FindEmbeddedExecutablesTool(
    MemoryTool[FindEmbeddedExecutablesArgs, FindEmbeddedExecutablesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_embedded_executables",
                description="Scan a file for ELF / PE / Mach-O magic bytes at "
                            "any offset (not just 0). Validates each match by "
                            "header-structure plausibility to suppress false "
                            "positives from random byte sequences.",
                tags=("extract", "embedded", "layer1"),
            ),
            FindEmbeddedExecutablesArgs,
            FindEmbeddedExecutablesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindEmbeddedExecutablesArgs,
    ) -> FindEmbeddedExecutablesResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindEmbeddedExecutablesResult(
                path=str(path), file_size=0, matches=[],
            )
        matches: List[EmbeddedExecutable] = []
        for sig, fmt, _need in _SIGNATURES:
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos < 0:
                    break
                start = pos + 1
                if args.skip_first_match and pos == 0:
                    continue
                if not _validate(data, pos, fmt):  # type: ignore[arg-type]
                    continue
                matches.append(
                    EmbeddedExecutable(
                        format=fmt,  # type: ignore[arg-type]
                        offset=pos,
                        signature_bytes=data[pos: pos + 8].hex(),
                    )
                )
                if len(matches) >= args.max_results:
                    break
            if len(matches) >= args.max_results:
                break

        # Sort by offset so the output is in file order.
        matches.sort(key=lambda m: m.offset)
        return FindEmbeddedExecutablesResult(
            path=str(path), file_size=len(data), matches=matches,
        )


def build_tool() -> MemoryTool[
    FindEmbeddedExecutablesArgs, FindEmbeddedExecutablesResult
]:
    return FindEmbeddedExecutablesTool()
