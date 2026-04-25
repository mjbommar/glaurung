"""Tools 1–4: enumerate / extract / recursively-unpack archives.

Container archives (zip, tar, tar.gz, tar.bz2, tar.xz, gz, bz2, xz,
zstd, 7z, rar) wrap the *real* binary in cases ranging from benign
(typical software distribution) to adversarial (samples deliberately
nested to slow down triage). These tools let the analysis pipeline
peek inside without growing the Rust surface — they're pure Python on
top of stdlib + a couple of optional decoders.

Each tool follows the ``MemoryTool[Args, Result]`` pattern. None of
them call the LLM; they're deterministic Phase 1.5 utilities.

The recursive driver is bounded:
- ``max_depth`` caps how many archives-inside-archives we open.
- ``max_total_bytes`` caps the cumulative output size to prevent a
  malicious zip-bomb from exhausting disk.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ArchiveFormat = Literal[
    "zip", "tar", "tar.gz", "tar.bz2", "tar.xz", "gz", "bz2", "xz",
    "7z", "rar", "zstd", "unknown",
]


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def _peek_format(path: Path) -> ArchiveFormat:
    """Return a coarse archive-format label by sniffing magic bytes.

    Distinguishes wrapped tarballs (.tar.gz vs plain .gz) by trying to
    open the gz/bz2/xz stream and probing for a tar header inside.
    """
    try:
        head = path.read_bytes()[:262]
    except Exception:
        return "unknown"

    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:7] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01"):
        return "rar"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if head[:2] == b"\x1f\x8b":
        # gzip — could be .gz or .tar.gz
        try:
            with gzip.open(path, "rb") as gz:
                inner = gz.read(512)
            if len(inner) >= 262 and inner[257:262] == b"ustar":
                return "tar.gz"
        except Exception:
            pass
        return "gz"
    if head[:3] == b"BZh":
        try:
            with bz2.open(path, "rb") as bz:
                inner = bz.read(512)
            if len(inner) >= 262 and inner[257:262] == b"ustar":
                return "tar.bz2"
        except Exception:
            pass
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        try:
            with lzma.open(path, "rb") as xz:
                inner = xz.read(512)
            if len(inner) >= 262 and inner[257:262] == b"ustar":
                return "tar.xz"
        except Exception:
            pass
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    # Last-ditch tar detection — old-style tar without ustar magic
    try:
        with tarfile.open(path, "r"):
            return "tar"
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Tool 1: enumerate_archive
# ---------------------------------------------------------------------------


class ArchiveEntry(BaseModel):
    name: str
    size: int = Field(..., description="Uncompressed size in bytes")
    offset: int = Field(0, description="Stream offset, when meaningful (zip)")
    encrypted: bool = False
    is_dir: bool = False


class EnumerateArchiveArgs(BaseModel):
    path: str = Field(..., description="Path to the archive file")


class EnumerateArchiveResult(BaseModel):
    archive_path: str
    archive_format: ArchiveFormat
    entries: List[ArchiveEntry]
    total_uncompressed_size: int


class EnumerateArchiveTool(
    MemoryTool[EnumerateArchiveArgs, EnumerateArchiveResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="enumerate_archive",
                description="List entries in a zip / tar / gz / bz2 / xz / "
                            "7z / zstd archive without extracting bodies. "
                            "Reports per-entry size and encryption status.",
                tags=("extract", "container", "layer1"),
            ),
            EnumerateArchiveArgs,
            EnumerateArchiveResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: EnumerateArchiveArgs,
    ) -> EnumerateArchiveResult:
        path = Path(args.path)
        fmt = _peek_format(path)
        entries: List[ArchiveEntry] = []
        total = 0
        if fmt == "zip":
            try:
                with zipfile.ZipFile(path) as zf:
                    for info in zf.infolist():
                        entries.append(
                            ArchiveEntry(
                                name=info.filename,
                                size=info.file_size,
                                offset=info.header_offset,
                                encrypted=bool(info.flag_bits & 0x1),
                                is_dir=info.is_dir(),
                            )
                        )
                        total += info.file_size
            except zipfile.BadZipFile:
                pass
        elif fmt in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
            try:
                mode = {
                    "tar": "r:", "tar.gz": "r:gz",
                    "tar.bz2": "r:bz2", "tar.xz": "r:xz",
                }[fmt]
                with tarfile.open(path, mode) as tf:
                    for m in tf.getmembers():
                        entries.append(
                            ArchiveEntry(
                                name=m.name,
                                size=m.size,
                                offset=m.offset_data,
                                is_dir=m.isdir(),
                            )
                        )
                        total += m.size
            except tarfile.TarError:
                pass
        elif fmt in ("gz", "bz2", "xz"):
            # Single-stream archives — present as a single synthetic entry.
            try:
                opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[fmt]
                with opener(path, "rb") as f:
                    body = f.read()
                entries.append(
                    ArchiveEntry(
                        name=path.stem, size=len(body), offset=0, is_dir=False,
                    )
                )
                total = len(body)
            except Exception:
                pass

        return EnumerateArchiveResult(
            archive_path=str(path),
            archive_format=fmt,
            entries=entries,
            total_uncompressed_size=total,
        )


def build_enumerate_archive() -> MemoryTool[
    EnumerateArchiveArgs, EnumerateArchiveResult
]:
    return EnumerateArchiveTool()


# ---------------------------------------------------------------------------
# Tool 2: extract_archive_entry — single named entry
# ---------------------------------------------------------------------------


class ExtractArchiveEntryArgs(BaseModel):
    path: str
    entry_name: str
    out_path: Optional[str] = Field(
        None,
        description="Output file path. When None, write to a temp file and "
                    "return its path.",
    )


class ExtractArchiveEntryResult(BaseModel):
    extracted_to: str
    bytes_written: int


class ExtractArchiveEntryTool(
    MemoryTool[ExtractArchiveEntryArgs, ExtractArchiveEntryResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="extract_archive_entry",
                description="Extract one named entry from an archive to disk. "
                            "Streams to a temp file when out_path is None.",
                tags=("extract", "container", "layer1"),
            ),
            ExtractArchiveEntryArgs,
            ExtractArchiveEntryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ExtractArchiveEntryArgs,
    ) -> ExtractArchiveEntryResult:
        path = Path(args.path)
        fmt = _peek_format(path)
        if fmt == "unknown":
            # Soft-fail: return a zero-byte sentinel rather than raising,
            # so an LLM agent that calls us with a non-archive can keep
            # going. The bytes_written=0 result is the "no extraction"
            # signal.
            return ExtractArchiveEntryResult(
                extracted_to="", bytes_written=0,
            )
        if args.out_path:
            out = Path(args.out_path)
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            tmp = tempfile.NamedTemporaryFile(
                delete=False, prefix="glaurung_extract_"
            )
            out = Path(tmp.name)
            tmp.close()

        if fmt == "zip":
            with zipfile.ZipFile(path) as zf:
                with zf.open(args.entry_name) as src:
                    body = src.read()
        elif fmt in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
            mode = {
                "tar": "r:", "tar.gz": "r:gz",
                "tar.bz2": "r:bz2", "tar.xz": "r:xz",
            }[fmt]
            with tarfile.open(path, mode) as tf:
                m = tf.getmember(args.entry_name)
                f = tf.extractfile(m)
                if f is None:
                    body = b""
                else:
                    body = f.read()
        elif fmt in ("gz", "bz2", "xz"):
            opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[fmt]
            with opener(path, "rb") as f:
                body = f.read()
        else:
            raise ValueError(f"unsupported archive format: {fmt}")

        out.write_bytes(body)
        return ExtractArchiveEntryResult(
            extracted_to=str(out), bytes_written=len(body),
        )


def build_extract_archive_entry() -> MemoryTool[
    ExtractArchiveEntryArgs, ExtractArchiveEntryResult
]:
    return ExtractArchiveEntryTool()


# ---------------------------------------------------------------------------
# Tool 3: extract_archive_all — bulk extraction with bounds
# ---------------------------------------------------------------------------


class ExtractArchiveAllArgs(BaseModel):
    path: str
    out_dir: str
    max_files: int = 64
    max_bytes: int = 256 * 1024 * 1024


class ExtractedEntry(BaseModel):
    name: str
    extracted_to: str
    size: int


class ExtractArchiveAllResult(BaseModel):
    archive_format: ArchiveFormat
    extracted: List[ExtractedEntry]
    skipped: List[str] = Field(
        default_factory=list,
        description="Entries skipped because of bounds or unsafe paths.",
    )
    total_bytes: int


def _safe_join(base: Path, name: str) -> Optional[Path]:
    """Reject zip-slip / path-traversal names. Returns None if unsafe."""
    target = (base / name).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError:
        return None
    return target


class ExtractArchiveAllTool(
    MemoryTool[ExtractArchiveAllArgs, ExtractArchiveAllResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="extract_archive_all",
                description="Extract every entry of an archive into out_dir, "
                            "with bounds on file count and total bytes. "
                            "Refuses zip-slip / path-traversal entries.",
                tags=("extract", "container", "layer1"),
            ),
            ExtractArchiveAllArgs,
            ExtractArchiveAllResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ExtractArchiveAllArgs,
    ) -> ExtractArchiveAllResult:
        path = Path(args.path)
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        fmt = _peek_format(path)

        extracted: List[ExtractedEntry] = []
        skipped: List[str] = []
        total = 0
        files = 0

        def _accept(name: str, body: bytes) -> bool:
            nonlocal total, files
            if files >= args.max_files:
                skipped.append(f"{name}: max_files reached")
                return False
            if total + len(body) > args.max_bytes:
                skipped.append(f"{name}: max_bytes reached")
                return False
            target = _safe_join(out_dir, name)
            if target is None:
                skipped.append(f"{name}: unsafe path (zip-slip)")
                return False
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            extracted.append(
                ExtractedEntry(name=name, extracted_to=str(target), size=len(body))
            )
            total += len(body)
            files += 1
            return True

        if fmt == "zip":
            try:
                with zipfile.ZipFile(path) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        with zf.open(info) as src:
                            body = src.read()
                        _accept(info.filename, body)
            except zipfile.BadZipFile:
                pass
        elif fmt in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
            mode = {
                "tar": "r:", "tar.gz": "r:gz",
                "tar.bz2": "r:bz2", "tar.xz": "r:xz",
            }[fmt]
            try:
                with tarfile.open(path, mode) as tf:
                    for m in tf.getmembers():
                        if not m.isfile():
                            continue
                        f = tf.extractfile(m)
                        if f is None:
                            continue
                        _accept(m.name, f.read())
            except tarfile.TarError:
                pass
        elif fmt in ("gz", "bz2", "xz"):
            opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[fmt]
            try:
                with opener(path, "rb") as f:
                    _accept(path.stem or "payload", f.read())
            except Exception:
                pass

        return ExtractArchiveAllResult(
            archive_format=fmt,
            extracted=extracted,
            skipped=skipped,
            total_bytes=total,
        )


def build_extract_archive_all() -> MemoryTool[
    ExtractArchiveAllArgs, ExtractArchiveAllResult
]:
    return ExtractArchiveAllTool()


# ---------------------------------------------------------------------------
# Tool 4: recursive_unpack — apply 1+3 until everything is primitive
# ---------------------------------------------------------------------------


class RecursiveUnpackArgs(BaseModel):
    path: str
    out_dir: str
    max_depth: int = 4
    max_total_bytes: int = 256 * 1024 * 1024


class UnpackStep(BaseModel):
    depth: int
    input_path: str
    archive_format: ArchiveFormat
    extracted_count: int
    extracted_paths: List[str] = Field(default_factory=list)


class RecursiveUnpackResult(BaseModel):
    steps: List[UnpackStep]
    final_files: List[str] = Field(
        default_factory=list,
        description="Files that are not themselves archives — the leaves",
    )
    total_bytes: int
    truncated: bool = False


class RecursiveUnpackTool(
    MemoryTool[RecursiveUnpackArgs, RecursiveUnpackResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="recursive_unpack",
                description="Recursively unpack archives until every file is "
                            "a non-archive. Bounded by max_depth and "
                            "max_total_bytes to defuse zip bombs.",
                tags=("extract", "container", "layer1"),
            ),
            RecursiveUnpackArgs,
            RecursiveUnpackResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RecursiveUnpackArgs,
    ) -> RecursiveUnpackResult:
        out_root = Path(args.out_dir)
        out_root.mkdir(parents=True, exist_ok=True)
        steps: List[UnpackStep] = []
        leaves: List[str] = []
        # Worklist: (path, depth, subdir-name)
        work: List[tuple[Path, int, str]] = [(Path(args.path), 0, "_root")]
        total = 0
        truncated = False
        seen: set[bytes] = set()

        while work:
            cur_path, depth, sub = work.pop(0)
            if depth > args.max_depth:
                truncated = True
                continue
            try:
                content = cur_path.read_bytes()
            except Exception:
                continue
            digest = (cur_path.stat().st_size, hash(content[:4096]))
            if digest in seen:
                continue
            seen.add(digest)

            fmt = _peek_format(cur_path)
            if fmt == "unknown":
                leaves.append(str(cur_path))
                continue

            sub_dir = out_root / sub / f"depth_{depth}"
            inner = ExtractArchiveAllTool().run(
                ctx, kb,
                ExtractArchiveAllArgs(
                    path=str(cur_path),
                    out_dir=str(sub_dir),
                    max_bytes=args.max_total_bytes - total,
                ),
            )
            total += inner.total_bytes
            steps.append(
                UnpackStep(
                    depth=depth,
                    input_path=str(cur_path),
                    archive_format=fmt,
                    extracted_count=len(inner.extracted),
                    extracted_paths=[e.extracted_to for e in inner.extracted],
                )
            )
            if total >= args.max_total_bytes:
                truncated = True
                break
            for e in inner.extracted:
                child = Path(e.extracted_to)
                next_sub = f"{sub}/{Path(e.name).stem or 'entry'}"
                work.append((child, depth + 1, next_sub))

        return RecursiveUnpackResult(
            steps=steps,
            final_files=leaves,
            total_bytes=total,
            truncated=truncated,
        )


def build_recursive_unpack() -> MemoryTool[
    RecursiveUnpackArgs, RecursiveUnpackResult
]:
    return RecursiveUnpackTool()
