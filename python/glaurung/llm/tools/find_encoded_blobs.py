"""Tools 10–13, 20: detect encoded blobs (base64 / hex / PEM / XOR /
compressed) inside arbitrary file bytes.

These are the workhorses for "I see something that looks like encoded
data — what is it?" investigations. Every tool returns offset / length
ranges plus, where decoding is unambiguous, the decoded bytes (or a
short preview).

None of these call the LLM. The LLM enters one rung up — given a list
of candidate blobs, the orchestrator can ask the model to *prioritise*
which blob to chase first, or whether a brute-forced XOR result looks
meaningful.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import io
import lzma
import re
from pathlib import Path
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


# ---------------------------------------------------------------------------
# Magic-byte map for "what does this decoded blob look like?"
# ---------------------------------------------------------------------------

_DECODED_LOOKS_LIKE = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/MZ executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (BE)"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (BE)"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"\x28\xb5\x2f\xfd", "zstd stream"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"%PDF-", "PDF document"),
    (b"<?xml", "XML document"),
    (b"{", "JSON document (likely)"),
]


def _looks_like(data: bytes) -> str:
    """Identify the first bytes of a decoded blob.

    Tries the Rust `infer`-based content sniffer first — it knows
    JPEG / PNG / PDF / ZIP / executables and ~120 other formats from a
    single magic-bytes table that's already in the binary. Falls back
    to a hand-rolled table for entries `infer` doesn't cover (like
    raw zlib streams) and finally to a printable-text heuristic.
    """
    if not data:
        return "empty"
    try:
        import glaurung as g
        sniff = g.strings.sniff_bytes(data)
        if sniff is not None:
            mime, ext, label = sniff
            if mime:
                return f"{mime}" + (f" ({label})" if label and label != ext else "")
            if label:
                return label
    except Exception:
        pass
    # Hand-rolled fallbacks for a few signatures `infer` doesn't carry.
    for sig, label in _DECODED_LOOKS_LIKE:
        if data.startswith(sig):
            return label
    sample = data[:128]
    try:
        import glaurung as g
        ratio = g.strings.printable_ascii_ratio(sample)
    except Exception:
        ratio = sum(
            1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)
        ) / max(1, len(sample))
    if ratio >= 0.85:
        return "printable text"
    return "unknown binary"


# ---------------------------------------------------------------------------
# Tool 10: find_base64_blobs
# ---------------------------------------------------------------------------


_B64_RUN_RE = re.compile(rb"[A-Za-z0-9+/]{32,}={0,2}")


class FindBase64BlobsArgs(BaseModel):
    path: str
    min_len: int = Field(
        32, description="Minimum encoded-text length before considering a run"
    )
    max_results: int = 64


class Base64Blob(BaseModel):
    offset: int
    encoded_length: int
    decoded_size: int
    decoded_preview_hex: str = Field(
        ..., description="Hex of the first 32 bytes of the decoded blob"
    )
    looks_like: str


class FindBase64BlobsResult(BaseModel):
    path: str
    blobs: List[Base64Blob]


class FindBase64BlobsTool(MemoryTool[FindBase64BlobsArgs, FindBase64BlobsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_base64_blobs",
                description="Scan a file for runs of base64-alphabet "
                            "characters and try to decode each. Reports "
                            "decoded size and a magic-byte guess at what "
                            "the decoded content is.",
                tags=("extract", "encoded", "layer1"),
            ),
            FindBase64BlobsArgs,
            FindBase64BlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindBase64BlobsArgs,
    ) -> FindBase64BlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindBase64BlobsResult(path=str(path), blobs=[])
        blobs: List[Base64Blob] = []
        for m in _B64_RUN_RE.finditer(data):
            run = m.group(0)
            if len(run) < args.min_len:
                continue
            try:
                decoded = base64.b64decode(run, validate=True)
            except (binascii.Error, ValueError):
                continue
            if not decoded:
                continue
            blobs.append(
                Base64Blob(
                    offset=m.start(),
                    encoded_length=len(run),
                    decoded_size=len(decoded),
                    decoded_preview_hex=decoded[:32].hex(),
                    looks_like=_looks_like(decoded),
                )
            )
            if len(blobs) >= args.max_results:
                break
        return FindBase64BlobsResult(path=str(path), blobs=blobs)


def build_find_base64_blobs() -> MemoryTool[
    FindBase64BlobsArgs, FindBase64BlobsResult
]:
    return FindBase64BlobsTool()


# ---------------------------------------------------------------------------
# Tool 11: find_hex_blobs
# ---------------------------------------------------------------------------


_HEX_RUN_RE = re.compile(rb"(?:[0-9A-Fa-f]{2}){32,}")


class FindHexBlobsArgs(BaseModel):
    path: str
    min_bytes: int = Field(64, description="Minimum decoded byte count")
    max_results: int = 32


class HexBlob(BaseModel):
    offset: int
    encoded_length: int
    decoded_size: int
    decoded_preview_hex: str
    looks_like: str


class FindHexBlobsResult(BaseModel):
    path: str
    blobs: List[HexBlob]


class FindHexBlobsTool(MemoryTool[FindHexBlobsArgs, FindHexBlobsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_hex_blobs",
                description="Scan for runs of hex digits at least min_bytes "
                            "long and decode them. Catches hex-encoded "
                            "payloads in config files / strings tables.",
                tags=("extract", "encoded", "layer1"),
            ),
            FindHexBlobsArgs,
            FindHexBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindHexBlobsArgs,
    ) -> FindHexBlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindHexBlobsResult(path=str(path), blobs=[])
        blobs: List[HexBlob] = []
        for m in _HEX_RUN_RE.finditer(data):
            run = m.group(0)
            if len(run) // 2 < args.min_bytes:
                continue
            try:
                decoded = bytes.fromhex(run.decode("ascii"))
            except ValueError:
                continue
            blobs.append(
                HexBlob(
                    offset=m.start(),
                    encoded_length=len(run),
                    decoded_size=len(decoded),
                    decoded_preview_hex=decoded[:32].hex(),
                    looks_like=_looks_like(decoded),
                )
            )
            if len(blobs) >= args.max_results:
                break
        return FindHexBlobsResult(path=str(path), blobs=blobs)


def build_find_hex_blobs() -> MemoryTool[FindHexBlobsArgs, FindHexBlobsResult]:
    return FindHexBlobsTool()


# ---------------------------------------------------------------------------
# Tool 12: find_pem_blocks
# ---------------------------------------------------------------------------


_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----"
    rb"\s*([A-Za-z0-9+/=\s]+)"
    rb"-----END \1-----"
)


class FindPemBlocksArgs(BaseModel):
    path: str
    max_results: int = 32


class PemBlock(BaseModel):
    offset: int
    pem_type: str
    body_size: int
    body_preview_hex: str


class FindPemBlocksResult(BaseModel):
    path: str
    blocks: List[PemBlock]


class FindPemBlocksTool(MemoryTool[FindPemBlocksArgs, FindPemBlocksResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_pem_blocks",
                description="Find PEM-armored blocks (-----BEGIN ... / "
                            "-----END ...-----). Detects keys, certs, CSRs, "
                            "and arbitrary BEGIN <TYPE> payloads.",
                tags=("extract", "encoded", "layer1"),
            ),
            FindPemBlocksArgs,
            FindPemBlocksResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindPemBlocksArgs,
    ) -> FindPemBlocksResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindPemBlocksResult(path=str(path), blocks=[])
        blocks: List[PemBlock] = []
        for m in _PEM_RE.finditer(data):
            ptype = m.group(1).decode("ascii", errors="ignore")
            body = b"".join(m.group(2).split())
            try:
                decoded = base64.b64decode(body, validate=True)
            except (binascii.Error, ValueError):
                continue
            blocks.append(
                PemBlock(
                    offset=m.start(),
                    pem_type=ptype,
                    body_size=len(decoded),
                    body_preview_hex=decoded[:32].hex(),
                )
            )
            if len(blocks) >= args.max_results:
                break
        return FindPemBlocksResult(path=str(path), blocks=blocks)


def build_find_pem_blocks() -> MemoryTool[
    FindPemBlocksArgs, FindPemBlocksResult
]:
    return FindPemBlocksTool()


# ---------------------------------------------------------------------------
# Tool 13: try_xor_brute
# ---------------------------------------------------------------------------


# Letter-frequency log probabilities for English (rough). Used as a
# scoring function to recognise plausibly-decoded plaintext.
_EN_LETTER_FREQ = {
    "a": 0.082, "b": 0.015, "c": 0.028, "d": 0.043, "e": 0.127,
    "f": 0.022, "g": 0.020, "h": 0.061, "i": 0.070, "j": 0.002,
    "k": 0.008, "l": 0.040, "m": 0.024, "n": 0.067, "o": 0.075,
    "p": 0.019, "q": 0.001, "r": 0.060, "s": 0.063, "t": 0.091,
    "u": 0.028, "v": 0.010, "w": 0.024, "x": 0.002, "y": 0.020,
    "z": 0.001, " ": 0.180,
}


def _english_score(b: bytes) -> float:
    """Heuristic plausibility score for a candidate plaintext.

    Higher = more English-y. Combines printable-ASCII fraction with
    a letter-frequency match. Pure binary blobs score near 0.
    """
    if not b:
        return 0.0
    n = len(b)
    printable = sum(
        1 for x in b if 32 <= x < 127 or x in (9, 10, 13)
    )
    if printable / n < 0.7:
        return 0.0
    s = 0.0
    text = b.decode("latin-1").lower()
    for c in text:
        s += _EN_LETTER_FREQ.get(c, 0.001)
    return s / n


class TryXorBruteArgs(BaseModel):
    path: str
    offset: int = 0
    length: int = Field(
        256,
        description="How many bytes to try decoding. Brute force is O(256 * length); keep this small.",
    )
    key_lengths: List[int] = Field(default_factory=lambda: [1])
    top_k: int = 3


class XorCandidate(BaseModel):
    key_hex: str
    key_length: int
    score: float
    decoded_preview: str = Field(
        ..., description="First 80 chars of the decoded text (latin-1 escaped)"
    )


class TryXorBruteResult(BaseModel):
    path: str
    candidates: List[XorCandidate]


def _xor_with_key(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class TryXorBruteTool(MemoryTool[TryXorBruteArgs, TryXorBruteResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="try_xor_brute",
                description="Brute-force XOR-decode a byte range with all "
                            "256 single-byte keys (or all keys of the given "
                            "lengths). Returns the top-K candidates ranked "
                            "by English-plaintext plausibility.",
                tags=("extract", "encoded", "layer1"),
            ),
            TryXorBruteArgs,
            TryXorBruteResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: TryXorBruteArgs,
    ) -> TryXorBruteResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return TryXorBruteResult(path=str(path), candidates=[])
        slice_ = data[args.offset: args.offset + args.length]
        if not slice_:
            return TryXorBruteResult(path=str(path), candidates=[])

        cands: List[XorCandidate] = []
        for klen in args.key_lengths:
            if klen == 1:
                for k in range(256):
                    key = bytes([k])
                    decoded = _xor_with_key(slice_, key)
                    score = _english_score(decoded)
                    if score > 0.05:
                        cands.append(
                            XorCandidate(
                                key_hex=key.hex(),
                                key_length=1,
                                score=score,
                                decoded_preview=decoded[:80].decode(
                                    "latin-1", errors="replace"
                                ),
                            )
                        )
            else:
                # Skip multi-byte for now — exhaustive brute is O(256^N)
                # which is impractical past 2 bytes. Add a smarter
                # cipher-text-only attack later if needed.
                continue

        cands.sort(key=lambda c: -c.score)
        return TryXorBruteResult(
            path=str(path), candidates=cands[: args.top_k],
        )


def build_try_xor_brute() -> MemoryTool[TryXorBruteArgs, TryXorBruteResult]:
    return TryXorBruteTool()


# ---------------------------------------------------------------------------
# Tool 13b: scan_xor_encoded_strings — slide a window over the whole file
# ---------------------------------------------------------------------------


class ScanXorEncodedStringsArgs(BaseModel):
    path: str
    window: int = Field(
        32,
        description="Width of the sliding window in bytes — the minimum "
                    "length of the encoded plaintext to detect.",
    )
    stride: int = Field(8, description="Window step size")
    min_score: float = Field(
        0.06,
        description="Minimum English-plausibility score to report a hit",
    )
    max_results: int = 32


class XorRegion(BaseModel):
    offset: int
    length: int
    key_hex: str
    score: float
    decoded: str


class ScanXorEncodedStringsResult(BaseModel):
    path: str
    regions: List[XorRegion]


class ScanXorEncodedStringsTool(
    MemoryTool[ScanXorEncodedStringsArgs, ScanXorEncodedStringsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="scan_xor_encoded_strings",
                description="Slide a window across a file, brute-force "
                            "single-byte XOR each window, and report any "
                            "region whose top-scoring decode looks like "
                            "plain English (printable + letter-frequency).",
                tags=("extract", "encoded", "layer1"),
            ),
            ScanXorEncodedStringsArgs,
            ScanXorEncodedStringsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ScanXorEncodedStringsArgs,
    ) -> ScanXorEncodedStringsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return ScanXorEncodedStringsResult(path=str(path), regions=[])
        # Try to use the Rust IOC pattern matcher as a strong signal —
        # a window that contains a URL / IP / domain after XOR decode
        # is much more likely to be real plaintext than one that just
        # has high letter frequencies.
        try:
            import glaurung as g  # noqa: F401
            _has_search = True
        except Exception:
            _has_search = False

        def _ioc_bonus(text: str) -> float:
            if not _has_search:
                return 0.0
            try:
                hits = g.strings.search_text(text, time_guard_ms=2)
                if hits:
                    # Each IOC hit is worth a meaningful score boost.
                    return 0.15 * min(len(hits), 3)
            except Exception:
                pass
            return 0.0

        regions: List[XorRegion] = []
        last_offset = -10_000_000
        window, stride = args.window, args.stride
        for off in range(0, len(data) - window, stride):
            slice_ = data[off: off + window]
            # Skip windows whose source bytes already look mostly like
            # text — XOR-decoding plaintext with any key yields more
            # printable text and trivially scores well, which would
            # flood the result with the symbol table / strings table.
            src_printable = sum(
                1 for b in slice_ if 32 <= b < 127 or b in (9, 10, 13)
            )
            if src_printable / len(slice_) >= 0.5:
                continue
            best_key, best_score, best_decoded = 0, 0.0, b""
            for k in range(1, 256):  # skip key=0 (would equal the plaintext)
                decoded = bytes(b ^ k for b in slice_)
                base = _english_score(decoded)
                if base <= 0.0:
                    continue
                # The IOC bonus is the discriminator — a URL after XOR
                # is the textbook signal we want to surface.
                preview = decoded.decode("latin-1", errors="replace")
                score = base + _ioc_bonus(preview)
                if score > best_score:
                    best_key, best_score, best_decoded = k, score, decoded
            if best_score >= args.min_score:
                # Coalesce adjacent windows reporting the same key.
                if regions and regions[-1].key_hex == bytes([best_key]).hex() \
                   and off - last_offset <= window:
                    regions[-1] = XorRegion(
                        offset=regions[-1].offset,
                        length=off + window - regions[-1].offset,
                        key_hex=regions[-1].key_hex,
                        score=max(regions[-1].score, best_score),
                        decoded=(
                            regions[-1].decoded
                            + best_decoded.decode("latin-1", errors="replace")[
                                stride:
                            ]
                        )[:200],
                    )
                else:
                    regions.append(
                        XorRegion(
                            offset=off, length=window,
                            key_hex=bytes([best_key]).hex(),
                            score=best_score,
                            decoded=best_decoded.decode(
                                "latin-1", errors="replace"
                            )[:200],
                        )
                    )
                last_offset = off
                if len(regions) >= args.max_results:
                    break
        regions.sort(key=lambda r: -r.score)
        return ScanXorEncodedStringsResult(
            path=str(path), regions=regions[: args.max_results],
        )


def build_scan_xor_encoded_strings() -> MemoryTool[
    ScanXorEncodedStringsArgs, ScanXorEncodedStringsResult
]:
    return ScanXorEncodedStringsTool()


# ---------------------------------------------------------------------------
# Tool 20: find_compressed_blobs (probe-based)
# ---------------------------------------------------------------------------

CompressedFormat = Literal["gzip", "zlib", "bzip2", "xz", "zstd"]


_COMPRESSED_SIGNATURES = [
    (b"\x1f\x8b", "gzip"),
    (b"\x78\x01", "zlib"),  # no-compression
    (b"\x78\x9c", "zlib"),  # default
    (b"\x78\xda", "zlib"),  # best
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
]


def _try_decompress(data: bytes, fmt: str, max_out: int = 4 * 1024 * 1024) -> Optional[bytes]:
    """Try to decompress ``data`` as ``fmt``. Tolerates a truncated input
    (the caller often passes a probe slice that doesn't include the
    full stream) by reading incrementally where the format supports it.

    Returns up to ``max_out`` bytes of decoded output; None on failure.
    """
    try:
        if fmt == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                return f.read(max_out)
        if fmt == "zlib":
            import zlib
            d = zlib.decompressobj()
            return d.decompress(data, max_out)
        if fmt == "bzip2":
            d = bz2.BZ2Decompressor()
            return d.decompress(data, max_out)
        if fmt == "xz":
            d = lzma.LZMADecompressor()
            return d.decompress(data, max_out)
        if fmt == "zstd":
            try:
                import zstandard  # type: ignore
            except ImportError:
                return None
            d = zstandard.ZstdDecompressor().decompressobj()
            return d.decompress(data)[:max_out]
    except Exception:
        return None
    return None


class FindCompressedBlobsArgs(BaseModel):
    path: str
    max_results: int = 32
    probe_bytes: int = Field(
        4096,
        description="When a magic match is found, attempt to decompress this "
                    "many trailing bytes to confirm. Larger = slower but "
                    "fewer false positives.",
    )


class CompressedBlob(BaseModel):
    offset: int
    format: CompressedFormat
    confirmed_size: int = Field(
        ..., description="Bytes of decoded output from the probe (0 if probe failed)"
    )
    decoded_preview_hex: str
    looks_like: str


class FindCompressedBlobsResult(BaseModel):
    path: str
    blobs: List[CompressedBlob]


class FindCompressedBlobsTool(
    MemoryTool[FindCompressedBlobsArgs, FindCompressedBlobsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_compressed_blobs",
                description="Scan for gzip / zlib / bzip2 / xz / zstd magics "
                            "and confirm each by trial-decompressing a small "
                            "prefix. Returns offsets that survive the probe.",
                tags=("extract", "encoded", "layer1"),
            ),
            FindCompressedBlobsArgs,
            FindCompressedBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindCompressedBlobsArgs,
    ) -> FindCompressedBlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindCompressedBlobsResult(path=str(path), blobs=[])
        blobs: List[CompressedBlob] = []
        for sig, fmt in _COMPRESSED_SIGNATURES:
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos < 0:
                    break
                start = pos + 1
                # Pass the full tail starting at pos, not a probe slice —
                # most stream decoders need the complete stream to confirm.
                trail = data[pos:]
                decoded = _try_decompress(trail, fmt)
                if decoded is None:
                    continue
                blobs.append(
                    CompressedBlob(
                        offset=pos,
                        format=fmt,  # type: ignore[arg-type]
                        confirmed_size=len(decoded),
                        decoded_preview_hex=decoded[:32].hex(),
                        looks_like=_looks_like(decoded),
                    )
                )
                if len(blobs) >= args.max_results:
                    break
            if len(blobs) >= args.max_results:
                break
        blobs.sort(key=lambda b: b.offset)
        return FindCompressedBlobsResult(path=str(path), blobs=blobs)


def build_find_compressed_blobs() -> MemoryTool[
    FindCompressedBlobsArgs, FindCompressedBlobsResult
]:
    return FindCompressedBlobsTool()
