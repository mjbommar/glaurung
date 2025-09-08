from __future__ import annotations

import hashlib
from pathlib import Path
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class FileHashArgs(BaseModel):
    algorithm: str = Field("sha256", pattern=r"^(md5|sha1|sha256)$")


class FileHashResult(BaseModel):
    algorithm: str
    hexdigest: str


class FileHashTool(MemoryTool[FileHashArgs, FileHashResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="hash_file",
                description="Compute and store file hash in the KB",
                tags=("kb", "hash"),
            ),
            FileHashArgs,
            FileHashResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: FileHashArgs
    ) -> FileHashResult:
        p = Path(ctx.file_path)
        h = hashlib.new(args.algorithm)
        with p.open("rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        digest = h.hexdigest()
        kb.add_node(
            Node(
                kind=NodeKind.hash,
                label=f"{args.algorithm}:{digest}",
                props={"algorithm": args.algorithm},
            )
        )
        return FileHashResult(algorithm=args.algorithm, hexdigest=digest)


def build_tool() -> MemoryTool[FileHashArgs, FileHashResult]:
    return FileHashTool()
