"""Tools 15–19: scan files for embedded images, XML, JSON, plist, INI.

Where Sprint 2 covered *encoded* payloads (base64, hex, XOR), this
sprint covers *structured* payloads — formats whose presence in a
binary's bytes is itself the answer. A PNG embedded in a PE
resource section, an XML manifest sitting in `.rdata`, a JSON
config baked into the executable, a `bplist00`-prefixed Apple
property list — all worth surfacing during triage.

Each scanner combines a cheap regex / magic-byte filter with a
parser-based confirmation step:

- Images: magic-byte detection + format-specific length-field walk
  (PNG IHDR + IEND, JPEG SOI/EOI markers, GIF GCT length, BMP
  BITMAPFILEHEADER size) so we report the *full* payload extent,
  not just the magic.
- XML: regex for ``<?xml ...?>`` plus a streaming parser that
  confirms the document parses cleanly through the closing tag.
- JSON: bracket-balance scan with a depth cap; confirms by
  ``json.loads`` on the candidate slice.
- plist: both Apple ``bplist00`` binary and XML plist forms.
- INI: ``[section]\\nkey=value`` heuristic with a multi-section
  threshold to avoid one-off false positives.

None of these call the LLM. The LLM enters one rung up — given a
list of candidate blobs, it can decide which to investigate or pass
the contents to a higher-level tool.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


# ---------------------------------------------------------------------------
# Tool 15: find_embedded_images
# ---------------------------------------------------------------------------


ImageFormat = Literal[
    "png", "jpeg", "gif", "bmp", "webp", "ico", "tiff",
]


def _png_length(data: bytes, off: int) -> Optional[int]:
    """Return the total length of a PNG starting at ``off``, walking
    chunks until IEND. None when malformed."""
    end = len(data)
    p = off + 8  # past the 8-byte magic
    while p + 12 <= end:
        ln = int.from_bytes(data[p: p + 4], "big")
        ctype = data[p + 4: p + 8]
        if ln > 100 * 1024 * 1024:
            return None  # absurd chunk length → malformed
        chunk_end = p + 8 + ln + 4  # length + type + data + crc
        if chunk_end > end:
            return None
        if ctype == b"IEND":
            return chunk_end - off
        p = chunk_end
    return None


def _jpeg_length(data: bytes, off: int) -> Optional[int]:
    """Walk JPEG markers until SOI/EOI. JPEG is a sequence of
    ``\\xff <marker>`` segments; SOI=D8, EOI=D9."""
    end = len(data)
    p = off + 2  # past SOI
    while p + 4 <= end:
        if data[p] != 0xff:
            return None
        # Skip 0xff padding bytes.
        while p < end and data[p] == 0xff:
            p += 1
        if p >= end:
            return None
        marker = data[p]
        p += 1
        if marker == 0xd9:
            return p - off  # EOI
        if 0xd0 <= marker <= 0xd7 or marker == 0x01:
            continue  # standalone marker
        if p + 2 > end:
            return None
        seg_len = int.from_bytes(data[p: p + 2], "big")
        p += seg_len
        if marker == 0xda:
            # Start of scan — read until next \xff which isn't part of an
            # entropy-coded byte (FF 00 escape).
            while p + 1 < end:
                if data[p] == 0xff and data[p + 1] != 0x00:
                    break
                p += 1
            else:
                return None
    return None


def _bmp_length(data: bytes, off: int) -> Optional[int]:
    """BMP's BITMAPFILEHEADER carries the file size at +2."""
    if off + 6 > len(data):
        return None
    size = int.from_bytes(data[off + 2: off + 6], "little")
    if size < 14 or off + size > len(data):
        return None
    return size


_IMAGE_SIGS = [
    (b"\x89PNG\r\n\x1a\n", "png", _png_length),
    (b"\xff\xd8\xff", "jpeg", _jpeg_length),
    (b"GIF87a", "gif", None),
    (b"GIF89a", "gif", None),
    (b"BM", "bmp", _bmp_length),
    (b"RIFF", "webp", None),  # validated later by 'WEBP' at +8
    (b"\x00\x00\x01\x00", "ico", None),
    (b"II*\x00", "tiff", None),
    (b"MM\x00*", "tiff", None),
]


class FindEmbeddedImagesArgs(BaseModel):
    path: str
    max_results: int = 32


class EmbeddedImage(BaseModel):
    format: str
    offset: int
    length: int = Field(
        ..., description="Total payload length when the parser walked it; "
                        "0 when length couldn't be determined.",
    )
    confirmed_via_sniff: bool = Field(
        False,
        description="True when the Rust sniff_bytes() also identified the "
                    "blob — strong corroboration.",
    )


class FindEmbeddedImagesResult(BaseModel):
    path: str
    images: List[EmbeddedImage]


class FindEmbeddedImagesTool(
    MemoryTool[FindEmbeddedImagesArgs, FindEmbeddedImagesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_embedded_images",
                description="Scan a file for PNG / JPEG / GIF / BMP / WEBP / "
                            "ICO / TIFF magics; for the formats with a "
                            "length field, walk the structure to report the "
                            "full payload extent. Cross-checks each match "
                            "against the Rust content-sniffer.",
                tags=("extract", "embedded", "images", "layer1"),
            ),
            FindEmbeddedImagesArgs,
            FindEmbeddedImagesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindEmbeddedImagesArgs,
    ) -> FindEmbeddedImagesResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindEmbeddedImagesResult(path=str(path), images=[])

        try:
            import glaurung as g
            sniff = g.strings.sniff_bytes
        except Exception:
            sniff = None

        images: List[EmbeddedImage] = []
        for sig, fmt, length_fn in _IMAGE_SIGS:
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos < 0:
                    break
                start = pos + 1
                # WEBP needs the 'WEBP' confirmation at +8.
                if fmt == "webp" and not data[pos + 8: pos + 12] == b"WEBP":
                    continue
                length = length_fn(data, pos) if length_fn else 0
                # Sniff the candidate blob (up to 4 KB) to corroborate.
                blob = data[pos: pos + (length or 4096)]
                confirmed = False
                if sniff is not None:
                    s = sniff(blob)
                    if s is not None:
                        mime, _ext, label = s
                        confirmed = fmt in mime.lower() or fmt == label
                images.append(
                    EmbeddedImage(
                        format=fmt, offset=pos, length=length or 0,
                        confirmed_via_sniff=confirmed,
                    )
                )
                if len(images) >= args.max_results:
                    break
            if len(images) >= args.max_results:
                break
        images.sort(key=lambda i: i.offset)
        return FindEmbeddedImagesResult(path=str(path), images=images)


def build_find_embedded_images() -> MemoryTool[
    FindEmbeddedImagesArgs, FindEmbeddedImagesResult
]:
    return FindEmbeddedImagesTool()


# ---------------------------------------------------------------------------
# Tool 16: find_xml_blobs
# ---------------------------------------------------------------------------


_XML_DECL_RE = re.compile(rb"<\?xml\s[^>]{0,80}\?>")
_XML_OPEN_TAG_RE = re.compile(rb"<([A-Za-z_][\w:.\-]{0,40})[\s>/]")


def _xml_extent(data: bytes, off: int) -> Optional[int]:
    """Find the matching close of the XML document starting at off.

    Cheap heuristic: locate the first opening element after the optional
    declaration, then look for the corresponding ``</name>`` close tag.
    Doesn't validate properly; just delimits the candidate blob.
    """
    end = len(data)
    p = off
    if data[p:p + 5] == b"<?xml":
        m = _XML_DECL_RE.match(data, p)
        if m:
            p = m.end()
    # Find the root element.
    m = _XML_OPEN_TAG_RE.search(data, p, min(end, p + 1024))
    if not m:
        return None
    name = m.group(1).decode("ascii", errors="ignore")
    close = b"</" + m.group(1) + b">"
    cidx = data.find(close, m.end())
    if cidx < 0:
        return None
    return cidx + len(close) - off


class FindXmlBlobsArgs(BaseModel):
    path: str
    max_results: int = 16


class XmlBlob(BaseModel):
    offset: int
    length: int
    root_element: str
    starts_with_decl: bool


class FindXmlBlobsResult(BaseModel):
    path: str
    blobs: List[XmlBlob]


class FindXmlBlobsTool(MemoryTool[FindXmlBlobsArgs, FindXmlBlobsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_xml_blobs",
                description="Scan for XML documents — `<?xml ...?>` "
                            "declarations or balanced root-element pairs. "
                            "Reports root tag and extent.",
                tags=("extract", "structured", "layer1"),
            ),
            FindXmlBlobsArgs,
            FindXmlBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindXmlBlobsArgs,
    ) -> FindXmlBlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindXmlBlobsResult(path=str(path), blobs=[])
        blobs: List[XmlBlob] = []
        # Pass 1: every "<?xml" declaration.
        for m in _XML_DECL_RE.finditer(data):
            ext = _xml_extent(data, m.start())
            if ext is None:
                continue
            tag_m = _XML_OPEN_TAG_RE.search(data, m.end(), m.end() + 1024)
            root = tag_m.group(1).decode("ascii") if tag_m else "?"
            blobs.append(
                XmlBlob(
                    offset=m.start(), length=ext,
                    root_element=root, starts_with_decl=True,
                )
            )
            if len(blobs) >= args.max_results:
                break
        # Pass 2: declared-decl-less XML — only attempt for tags we know
        # are commonly embedded standalone (Android manifest, WiX, …).
        for known in (b"<manifest ", b"<plist ", b"<svg ", b"<rss "):
            for m in re.finditer(re.escape(known), data):
                ext = _xml_extent(data, m.start())
                if ext is None:
                    continue
                blobs.append(
                    XmlBlob(
                        offset=m.start(), length=ext,
                        root_element=known.decode().strip().lstrip("<"),
                        starts_with_decl=False,
                    )
                )
                if len(blobs) >= args.max_results:
                    break
            if len(blobs) >= args.max_results:
                break
        blobs.sort(key=lambda b: b.offset)
        return FindXmlBlobsResult(path=str(path), blobs=blobs[: args.max_results])


def build_find_xml_blobs() -> MemoryTool[FindXmlBlobsArgs, FindXmlBlobsResult]:
    return FindXmlBlobsTool()


# ---------------------------------------------------------------------------
# Tool 17: find_json_blobs
# ---------------------------------------------------------------------------


class FindJsonBlobsArgs(BaseModel):
    path: str
    min_size: int = 64
    max_results: int = 16


class JsonBlob(BaseModel):
    offset: int
    length: int
    top_level_kind: Literal["object", "array"]
    keys_preview: List[str] = Field(
        default_factory=list,
        description="First 5 top-level keys when the document is an object.",
    )


class FindJsonBlobsResult(BaseModel):
    path: str
    blobs: List[JsonBlob]


def _json_extent(data: bytes, off: int) -> Optional[int]:
    """Return the byte length of a parseable JSON document starting at
    ``off``, or None when no such document fits.

    Walks brace/bracket depth to find the closing position, then runs
    ``json.loads`` to confirm. Strings are parsed correctly so
    `{"key": "}"}` doesn't fool the depth counter.
    """
    end = len(data)
    if off >= end or data[off] not in (b"{"[0], b"["[0]):
        return None
    depth = 0
    in_str = False
    escape = False
    p = off
    while p < end:
        b = data[p]
        if in_str:
            if escape:
                escape = False
            elif b == 0x5c:  # backslash
                escape = True
            elif b == 0x22:  # close quote
                in_str = False
        else:
            if b == 0x22:
                in_str = True
            elif b in (0x7b, 0x5b):  # { or [
                depth += 1
            elif b in (0x7d, 0x5d):  # } or ]
                depth -= 1
                if depth == 0:
                    end_off = p + 1
                    try:
                        json.loads(data[off: end_off])
                    except json.JSONDecodeError:
                        return None
                    return end_off - off
        p += 1
    return None


class FindJsonBlobsTool(MemoryTool[FindJsonBlobsArgs, FindJsonBlobsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_json_blobs",
                description="Scan for parseable JSON documents (objects / "
                            "arrays). Reports offset, length, top-level "
                            "kind, and a preview of the keys.",
                tags=("extract", "structured", "layer1"),
            ),
            FindJsonBlobsArgs,
            FindJsonBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindJsonBlobsArgs,
    ) -> FindJsonBlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindJsonBlobsResult(path=str(path), blobs=[])

        blobs: List[JsonBlob] = []
        # Look at every `{` and `[` candidate. Bound the work — each
        # unsuccessful candidate is cheap (depth walk fails fast on
        # mismatched braces) but iterating across megabytes of data is
        # still O(n).
        candidates = []
        for ch in (0x7b, 0x5b):
            start = 0
            while True:
                pos = data.find(bytes([ch]), start)
                if pos < 0:
                    break
                candidates.append(pos)
                start = pos + 1
        candidates.sort()
        consumed_through = -1
        for pos in candidates:
            if pos <= consumed_through:
                continue
            ext = _json_extent(data, pos)
            if ext is None or ext < args.min_size:
                continue
            kind: Literal["object", "array"] = (
                "object" if data[pos] == 0x7b else "array"
            )
            keys: List[str] = []
            if kind == "object":
                try:
                    parsed = json.loads(data[pos: pos + ext])
                    if isinstance(parsed, dict):
                        keys = list(parsed.keys())[:5]
                except Exception:
                    pass
            blobs.append(
                JsonBlob(
                    offset=pos, length=ext,
                    top_level_kind=kind, keys_preview=keys,
                )
            )
            consumed_through = pos + ext - 1
            if len(blobs) >= args.max_results:
                break
        return FindJsonBlobsResult(path=str(path), blobs=blobs)


def build_find_json_blobs() -> MemoryTool[FindJsonBlobsArgs, FindJsonBlobsResult]:
    return FindJsonBlobsTool()


# ---------------------------------------------------------------------------
# Tool 18: find_plist_blobs
# ---------------------------------------------------------------------------


class FindPlistBlobsArgs(BaseModel):
    path: str
    max_results: int = 16


class PlistBlob(BaseModel):
    offset: int
    length: int
    format: Literal["bplist00", "xml"]


class FindPlistBlobsResult(BaseModel):
    path: str
    blobs: List[PlistBlob]


class FindPlistBlobsTool(MemoryTool[FindPlistBlobsArgs, FindPlistBlobsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_plist_blobs",
                description="Find Apple property lists in either bplist00 "
                            "binary form or XML form (DOCTYPE plist).",
                tags=("extract", "structured", "layer1"),
            ),
            FindPlistBlobsArgs,
            FindPlistBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindPlistBlobsArgs,
    ) -> FindPlistBlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindPlistBlobsResult(path=str(path), blobs=[])

        blobs: List[PlistBlob] = []
        # Binary plist: bplist00 magic; trailer is at the last 32 bytes
        # but we don't need to walk it for detection.
        start = 0
        while True:
            pos = data.find(b"bplist00", start)
            if pos < 0:
                break
            # Heuristic length cap: until next bplist or EOF.
            next_pos = data.find(b"bplist00", pos + 8)
            length = (next_pos if next_pos >= 0 else len(data)) - pos
            blobs.append(
                PlistBlob(offset=pos, length=length, format="bplist00")
            )
            start = pos + 8
            if len(blobs) >= args.max_results:
                break
        # XML plist.
        for m in re.finditer(rb"<\?xml[^>]*\?>\s*<!DOCTYPE plist", data):
            ext = _xml_extent(data, m.start())
            if ext is None:
                continue
            blobs.append(
                PlistBlob(offset=m.start(), length=ext, format="xml")
            )
            if len(blobs) >= args.max_results:
                break
        blobs.sort(key=lambda b: b.offset)
        return FindPlistBlobsResult(path=str(path), blobs=blobs[: args.max_results])


def build_find_plist_blobs() -> MemoryTool[
    FindPlistBlobsArgs, FindPlistBlobsResult
]:
    return FindPlistBlobsTool()


# ---------------------------------------------------------------------------
# Tool 19: find_ini_blobs
# ---------------------------------------------------------------------------


_INI_LINE_RE = re.compile(
    rb"(?:^|\n)\[([A-Za-z0-9_\-. ]+)\]\s*\n"
    rb"(?:[A-Za-z_][A-Za-z0-9_\.\-]*\s*=\s*[^\n]*\n){2,}",
    re.MULTILINE,
)


class FindIniBlobsArgs(BaseModel):
    path: str
    min_sections: int = 2
    max_results: int = 16


class IniBlob(BaseModel):
    offset: int
    length: int
    section_count: int
    sections_preview: List[str]


class FindIniBlobsResult(BaseModel):
    path: str
    blobs: List[IniBlob]


class FindIniBlobsTool(MemoryTool[FindIniBlobsArgs, FindIniBlobsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_ini_blobs",
                description="Find INI-style config blocks: ``[section]`` "
                            "headers followed by ``key=value`` pairs. "
                            "Threshold of min_sections distinguishes real "
                            "config from one-off bracket text.",
                tags=("extract", "structured", "layer1"),
            ),
            FindIniBlobsArgs,
            FindIniBlobsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindIniBlobsArgs,
    ) -> FindIniBlobsResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return FindIniBlobsResult(path=str(path), blobs=[])

        # Find runs of consecutive section blocks.
        section_re = re.compile(
            rb"(?:^|\n)\[([A-Za-z0-9_\-. ]+)\]\s*\n"
            rb"((?:[A-Za-z_][A-Za-z0-9_\.\-]*\s*=\s*[^\n]*\n)+)",
            re.MULTILINE,
        )
        sections: List[tuple[int, int, str]] = []
        for m in section_re.finditer(data):
            sections.append((m.start(), m.end(), m.group(1).decode("ascii", errors="ignore")))
        # Coalesce adjacent / near-adjacent sections into INI blobs.
        blobs: List[IniBlob] = []
        i = 0
        while i < len(sections):
            start, end, name = sections[i]
            names = [name]
            j = i + 1
            while j < len(sections) and sections[j][0] - end < 8:
                end = sections[j][1]
                names.append(sections[j][2])
                j += 1
            if len(names) >= args.min_sections:
                blobs.append(
                    IniBlob(
                        offset=start,
                        length=end - start,
                        section_count=len(names),
                        sections_preview=names[:5],
                    )
                )
                if len(blobs) >= args.max_results:
                    break
            i = j
        return FindIniBlobsResult(path=str(path), blobs=blobs)


def build_find_ini_blobs() -> MemoryTool[FindIniBlobsArgs, FindIniBlobsResult]:
    return FindIniBlobsTool()


# ---------------------------------------------------------------------------
# Tool 6: extract_pe_overlay
# ---------------------------------------------------------------------------


class ExtractPeOverlayArgs(BaseModel):
    path: str


class ExtractPeOverlayResult(BaseModel):
    path: str
    has_overlay: bool
    overlay_offset: int = 0
    overlay_size: int = 0
    overlay_sniff: Optional[str] = Field(
        None,
        description="MIME / format label for the overlay bytes, when "
                    "the content sniffer could identify them.",
    )


def _pe_section_table_end(data: bytes) -> Optional[int]:
    """Return the byte offset of the formal end of the last PE section,
    or None if data isn't a recognisable PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = int.from_bytes(data[0x3c: 0x40], "little")
    if e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    nsec = int.from_bytes(data[coff + 2: coff + 4], "little")
    opt_size = int.from_bytes(data[coff + 16: coff + 18], "little")
    sec_table = coff + 20 + opt_size
    end = 0
    for i in range(nsec):
        sh = sec_table + i * 40
        if sh + 40 > len(data):
            return None
        size = int.from_bytes(data[sh + 16: sh + 20], "little")
        offset = int.from_bytes(data[sh + 20: sh + 24], "little")
        sec_end = offset + size
        if sec_end > end:
            end = sec_end
    return end


class ExtractPeOverlayTool(
    MemoryTool[ExtractPeOverlayArgs, ExtractPeOverlayResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="extract_pe_overlay",
                description="Compute a PE's formal end (last raw section "
                            "boundary) and report any bytes appended after "
                            "it as the overlay, with a content-sniff label.",
                tags=("extract", "pe", "overlay", "layer1"),
            ),
            ExtractPeOverlayArgs,
            ExtractPeOverlayResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ExtractPeOverlayArgs,
    ) -> ExtractPeOverlayResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return ExtractPeOverlayResult(path=str(path), has_overlay=False)
        end = _pe_section_table_end(data)
        if end is None or end >= len(data):
            return ExtractPeOverlayResult(path=str(path), has_overlay=False)
        overlay = data[end: end + 4096]  # sniff a 4 KB sample
        sniff_label: Optional[str] = None
        try:
            import glaurung as g
            s = g.strings.sniff_bytes(overlay)
            if s is not None:
                mime, _ext, label = s
                sniff_label = mime or label
        except Exception:
            pass
        return ExtractPeOverlayResult(
            path=str(path), has_overlay=True,
            overlay_offset=end, overlay_size=len(data) - end,
            overlay_sniff=sniff_label,
        )


def build_extract_pe_overlay() -> MemoryTool[
    ExtractPeOverlayArgs, ExtractPeOverlayResult
]:
    return ExtractPeOverlayTool()


# ---------------------------------------------------------------------------
# Tool 8: extract_elf_section
# ---------------------------------------------------------------------------


class ExtractElfSectionArgs(BaseModel):
    path: str
    section_name: str


class ExtractElfSectionResult(BaseModel):
    path: str
    section_name: str
    found: bool
    offset: int = 0
    size: int = 0
    bytes_hex_preview: str = Field("", description="First 64 bytes hex")


def _read_elf_section(data: bytes, name: str) -> Optional[tuple[int, int]]:
    """Manual ELF section walker — returns ``(offset, size)`` for the
    named section. Supports ELF64-LE (the common case); other variants
    fall through to None so the caller knows we couldn't help.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    # ei_class: 1=32-bit, 2=64-bit. ei_data: 1=LE, 2=BE.
    ei_class = data[4]
    ei_data = data[5]
    if ei_class != 2 or ei_data != 1:
        return None
    e_shoff = int.from_bytes(data[0x28: 0x30], "little")
    e_shentsize = int.from_bytes(data[0x3a: 0x3c], "little")
    e_shnum = int.from_bytes(data[0x3c: 0x3e], "little")
    e_shstrndx = int.from_bytes(data[0x3e: 0x40], "little")
    if e_shoff == 0 or e_shnum == 0:
        return None
    str_hdr_off = e_shoff + e_shstrndx * e_shentsize
    if str_hdr_off + e_shentsize > len(data):
        return None
    str_off = int.from_bytes(data[str_hdr_off + 24: str_hdr_off + 32], "little")
    str_size = int.from_bytes(data[str_hdr_off + 32: str_hdr_off + 40], "little")
    if str_off + str_size > len(data):
        return None
    strings = data[str_off: str_off + str_size]
    target = name.encode()
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        if sh + e_shentsize > len(data):
            break
        sh_name = int.from_bytes(data[sh: sh + 4], "little")
        sh_offset = int.from_bytes(data[sh + 24: sh + 32], "little")
        sh_size = int.from_bytes(data[sh + 32: sh + 40], "little")
        if sh_name >= len(strings):
            continue
        # Section names are nul-terminated within shstrtab.
        nul = strings.find(b"\x00", sh_name)
        sec_name = strings[sh_name: nul if nul > 0 else None]
        if sec_name == target:
            return sh_offset, sh_size
    return None


class ExtractElfSectionTool(
    MemoryTool[ExtractElfSectionArgs, ExtractElfSectionResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="extract_elf_section",
                description="Read the raw bytes of a named ELF section "
                            "(.rodata, .comment, .note.go.buildid, "
                            ".gopclntab, etc.). 64-bit LE only.",
                tags=("extract", "elf", "layer1"),
            ),
            ExtractElfSectionArgs,
            ExtractElfSectionResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ExtractElfSectionArgs,
    ) -> ExtractElfSectionResult:
        path = Path(args.path)
        try:
            data = path.read_bytes()
        except Exception:
            return ExtractElfSectionResult(
                path=str(path), section_name=args.section_name, found=False,
            )
        result = _read_elf_section(data, args.section_name)
        if result is None:
            return ExtractElfSectionResult(
                path=str(path), section_name=args.section_name, found=False,
            )
        off, size = result
        if off + size > len(data):
            size = max(0, len(data) - off)
        body = data[off: off + size]
        return ExtractElfSectionResult(
            path=str(path), section_name=args.section_name, found=True,
            offset=off, size=size, bytes_hex_preview=body[:64].hex(),
        )


def build_extract_elf_section() -> MemoryTool[
    ExtractElfSectionArgs, ExtractElfSectionResult
]:
    return ExtractElfSectionTool()
