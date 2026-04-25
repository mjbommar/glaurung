"""Tool 21: recursive-triage orchestrator.

The end-to-end driver that ties together Sprint 1 (containers),
Sprint 2 (encoded blobs), and Sprint 3 (structured / resource
content) into a single "what's actually inside this file?" walk.

Design:

1. Triage the input file. If it's a container archive, unpack
   recursively and recurse on each leaf.
2. If it's a known executable format (ELF / PE / Mach-O), tag it
   and stop the recursion at the executable boundary.
3. Otherwise, scan the body with all of:
   - find_embedded_executables (nested binaries)
   - find_compressed_blobs (gzip / zlib / bzip2 / xz / zstd)
   - find_base64_blobs (decode + sniff)
   - find_pem_blocks (keys / certs)
   - find_embedded_images
   - find_xml_blobs / find_json_blobs / find_plist_blobs / find_ini_blobs
   For every confirmed blob with a non-trivial decoded form, recurse
   on the decoded bytes (written to a temp file).
4. Bookkeep visited (size, sha-prefix) tuples to break cycles.
5. Bound by ``max_depth`` and ``max_total_bytes`` so a malicious
   input can't fork-bomb the analysis.

The output is a flat list of nodes with parent/child relationships,
deliberately simple to render or feed to a higher-level agent.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .extract_archive import (
    EnumerateArchiveTool, EnumerateArchiveArgs,
    ExtractArchiveAllTool, ExtractArchiveAllArgs,
    _peek_format,
)
from .find_embedded_executables import (
    FindEmbeddedExecutablesTool, FindEmbeddedExecutablesArgs,
)
from .find_encoded_blobs import (
    FindBase64BlobsTool, FindBase64BlobsArgs,
    FindCompressedBlobsTool, FindCompressedBlobsArgs,
    FindPemBlocksTool, FindPemBlocksArgs,
    _try_decompress,
)
from .find_structured_blobs import (
    FindEmbeddedImagesTool, FindEmbeddedImagesArgs,
    FindXmlBlobsTool, FindXmlBlobsArgs,
    FindJsonBlobsTool, FindJsonBlobsArgs,
    FindPlistBlobsTool, FindPlistBlobsArgs,
    FindIniBlobsTool, FindIniBlobsArgs,
)


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------


class TriageNode(BaseModel):
    """One step in the recursive-triage tree."""
    depth: int
    parent_id: Optional[int] = None
    node_id: int
    path: str = Field(..., description="Path on disk (may be a temp file)")
    size: int
    sniff_label: Optional[str] = Field(
        None, description="MIME / format identifier from sniff_bytes"
    )
    kind: str = Field(
        ...,
        description="archive | executable | image | xml | json | plist | "
                    "ini | pem | base64 | compressed | unknown",
    )
    extra: Dict[str, str] = Field(
        default_factory=dict,
        description="Per-kind metadata — e.g. archive format, exec format, "
                    "PEM type, root XML element.",
    )


class AnalyzeRecursivelyArgs(BaseModel):
    path: str
    out_dir: Optional[str] = Field(
        None,
        description="Where to write extracted blobs. None creates a temp "
                    "directory which the caller is responsible for cleaning "
                    "up via the result's `temp_root` path.",
    )
    max_depth: int = 4
    max_total_bytes: int = 256 * 1024 * 1024
    max_nodes: int = 200


class AnalyzeRecursivelyResult(BaseModel):
    root: str
    nodes: List[TriageNode]
    total_extracted_bytes: int
    truncated: bool = False
    temp_root: Optional[str] = Field(
        None, description="The directory used; caller may rmtree when done"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sniff(path: Path) -> Optional[str]:
    try:
        import glaurung as g
        head = path.read_bytes()[:4096]
        s = g.strings.sniff_bytes(head)
        if s is None:
            return None
        mime, _ext, label = s
        return mime or label or None
    except Exception:
        return None


def _is_executable(label: Optional[str]) -> bool:
    if not label:
        return False
    label = label.lower()
    return any(
        marker in label
        for marker in (
            "x-executable", "elf", "x-mach-binary", "x-msdownload",
            "vnd.microsoft.portable-executable",
        )
    )


def _digest(data: bytes) -> str:
    """Cycle-detection digest: hash a length-prefix + first 64 KB so
    files of the same size+prefix collide but files that differ only
    by a few trailing bytes do not.

    Without the size prefix, two ELFs with identical leading 64 KB
    (typical for hello-world programs from the same toolchain) would
    deduplicate, dropping one of them from the analysis tree.
    """
    h = hashlib.sha256()
    h.update(len(data).to_bytes(8, "little"))
    h.update(data[:65536])
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


class AnalyzeRecursivelyTool(
    MemoryTool[AnalyzeRecursivelyArgs, AnalyzeRecursivelyResult]
):
    """Recursive-triage driver: returns a tree of everything found in a file."""

    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="analyze_recursively",
                description="Triage a file and recursively unpack / decode "
                            "every container, encoded blob, and embedded "
                            "structured payload. Bounded by max_depth, "
                            "max_total_bytes, max_nodes.",
                tags=("extract", "recursive", "triage", "layer1"),
            ),
            AnalyzeRecursivelyArgs,
            AnalyzeRecursivelyResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: AnalyzeRecursivelyArgs,
    ) -> AnalyzeRecursivelyResult:
        out_root = (
            Path(args.out_dir) if args.out_dir
            else Path(tempfile.mkdtemp(prefix="glaurung_triage_"))
        )
        out_root.mkdir(parents=True, exist_ok=True)

        nodes: List[TriageNode] = []
        next_id = [0]
        seen: Set[str] = set()
        total_bytes = [0]
        truncated = [False]

        def _new_node(
            depth: int, parent_id: Optional[int], path: Path,
            kind: str, sniff_label: Optional[str], extra: Dict[str, str],
        ) -> Optional[TriageNode]:
            if len(nodes) >= args.max_nodes:
                truncated[0] = True
                return None
            node = TriageNode(
                depth=depth, parent_id=parent_id, node_id=next_id[0],
                path=str(path),
                size=path.stat().st_size if path.exists() else 0,
                sniff_label=sniff_label, kind=kind, extra=extra,
            )
            next_id[0] += 1
            nodes.append(node)
            return node

        # Worklist: (path, depth, parent_id, name_hint).
        work: List[tuple[Path, int, Optional[int], str]] = [
            (Path(args.path), 0, None, "_root")
        ]
        while work:
            cur, depth, parent_id, name_hint = work.pop(0)
            if depth > args.max_depth:
                truncated[0] = True
                continue
            if not cur.exists() or not cur.is_file():
                continue
            try:
                data = cur.read_bytes()
            except Exception:
                continue
            digest = _digest(data)
            if digest in seen:
                continue
            seen.add(digest)
            total_bytes[0] += len(data)
            if total_bytes[0] >= args.max_total_bytes:
                truncated[0] = True
                break

            sniff = _sniff(cur)
            fmt = _peek_format(cur)

            # 1. Container archives — unpack and queue children.
            if fmt != "unknown":
                node = _new_node(
                    depth, parent_id, cur, "archive", sniff,
                    {"format": fmt},
                )
                if node is None:
                    break
                sub_dir = out_root / f"node_{node.node_id}"
                inner = ExtractArchiveAllTool().run(
                    ctx, kb,
                    ExtractArchiveAllArgs(
                        path=str(cur), out_dir=str(sub_dir),
                        max_bytes=args.max_total_bytes - total_bytes[0],
                    ),
                )
                for e in inner.extracted:
                    work.append((Path(e.extracted_to), depth + 1, node.node_id, e.name))
                continue

            # 2. Executable — record but still scan the body, since
            # malware often appends payloads after a real ELF/PE.
            # The encoded-blob scanners (base64, compressed, PEM) are
            # cheap; the structured-blob scanners (xml/json/ini) are
            # disabled here to avoid false positives in symbol tables.
            is_exec = _is_executable(sniff)
            self_node = _new_node(
                depth, parent_id, cur,
                "executable" if is_exec else "unknown", sniff,
                {"format": (sniff or "").split(";")[0]} if is_exec else {},
            )
            if self_node is None:
                break

            # Embedded executables.
            for em in FindEmbeddedExecutablesTool().run(
                ctx, kb,
                FindEmbeddedExecutablesArgs(path=str(cur), skip_first_match=True),
            ).matches:
                _new_node(
                    depth + 1, self_node.node_id, cur, "executable_embedded",
                    None,
                    {"format": em.format, "offset": str(em.offset)},
                )

            # Compressed blobs — decode and recurse.
            for cb in FindCompressedBlobsTool().run(
                ctx, kb, FindCompressedBlobsArgs(path=str(cur), max_results=8),
            ).blobs:
                decoded = _try_decompress(data[cb.offset:], cb.format)
                if decoded is None or not decoded:
                    continue
                child_path = out_root / f"node_{self_node.node_id}_compressed_{cb.offset:x}.bin"
                child_path.write_bytes(decoded)
                work.append((child_path, depth + 1, self_node.node_id, child_path.name))

            # Base64 blobs — decode and recurse.
            for bb in FindBase64BlobsTool().run(
                ctx, kb, FindBase64BlobsArgs(path=str(cur), max_results=16, min_len=64),
            ).blobs:
                try:
                    raw = base64.b64decode(
                        data[bb.offset: bb.offset + bb.encoded_length],
                        validate=True,
                    )
                except Exception:
                    continue
                if not raw:
                    continue
                child_path = out_root / f"node_{self_node.node_id}_b64_{bb.offset:x}.bin"
                child_path.write_bytes(raw)
                work.append((child_path, depth + 1, self_node.node_id, child_path.name))

            # PEM blocks — record as leaves.
            for pb in FindPemBlocksTool().run(
                ctx, kb, FindPemBlocksArgs(path=str(cur)),
            ).blocks:
                _new_node(
                    depth + 1, self_node.node_id, cur, "pem", None,
                    {"pem_type": pb.pem_type, "offset": str(pb.offset)},
                )

            # Embedded images — only record entries that confirmed
            # via length-walk OR via the Rust content sniffer. A bare
            # magic match with no validation is too noisy (BM, RIFF
            # are common byte sequences in random data).
            for img in FindEmbeddedImagesTool().run(
                ctx, kb, FindEmbeddedImagesArgs(path=str(cur)),
            ).images:
                if img.length == 0 and not img.confirmed_via_sniff:
                    continue
                _new_node(
                    depth + 1, self_node.node_id, cur, "image", None,
                    {
                        "format": img.format,
                        "offset": str(img.offset),
                        "length": str(img.length),
                    },
                )

            # Structured-config blobs — only run on non-executables to
            # avoid drowning in symbol-table false positives.
            if not is_exec:
                for xml in FindXmlBlobsTool().run(
                    ctx, kb, FindXmlBlobsArgs(path=str(cur)),
                ).blobs:
                    _new_node(
                        depth + 1, self_node.node_id, cur, "xml", None,
                        {"root_element": xml.root_element, "offset": str(xml.offset)},
                    )
                for j in FindJsonBlobsTool().run(
                    ctx, kb, FindJsonBlobsArgs(path=str(cur)),
                ).blobs:
                    _new_node(
                        depth + 1, self_node.node_id, cur, "json", None,
                        {"top_level": j.top_level_kind, "offset": str(j.offset)},
                    )
                for p in FindPlistBlobsTool().run(
                    ctx, kb, FindPlistBlobsArgs(path=str(cur)),
                ).blobs:
                    _new_node(
                        depth + 1, self_node.node_id, cur, "plist", None,
                        {"format": p.format, "offset": str(p.offset)},
                    )
                for ini in FindIniBlobsTool().run(
                    ctx, kb, FindIniBlobsArgs(path=str(cur)),
                ).blobs:
                    _new_node(
                        depth + 1, self_node.node_id, cur, "ini", None,
                        {
                            "sections": str(ini.section_count),
                            "offset": str(ini.offset),
                        },
                    )

            # Update kind from "unknown" → "scanned" if we found something.
            children = [
                n for n in nodes if n.parent_id == self_node.node_id
            ]
            if children:
                # Mutate in-place — Pydantic models allow attribute assignment
                # by default.
                self_node.kind = "scanned"

        return AnalyzeRecursivelyResult(
            root=args.path,
            nodes=nodes,
            total_extracted_bytes=total_bytes[0],
            truncated=truncated[0],
            temp_root=str(out_root) if args.out_dir is None else None,
        )


def build_tool() -> MemoryTool[
    AnalyzeRecursivelyArgs, AnalyzeRecursivelyResult
]:
    return AnalyzeRecursivelyTool()
