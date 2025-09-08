from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


def _gen_id() -> str:
    return uuid.uuid4().hex


class NodeKind(str, Enum):
    file = "file"
    artifact = "artifact"
    evidence = "evidence"
    function = "function"
    string = "string"
    import_sym = "import"
    note = "note"
    hash = "hash"
    ioc = "ioc"


class Node(BaseModel):
    id: str = Field(default_factory=_gen_id)
    kind: NodeKind
    label: str
    text: Optional[str] = None
    props: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class Edge(BaseModel):
    id: str = Field(default_factory=_gen_id)
    src: str
    dst: str
    kind: str
    props: Dict[str, Any] = Field(default_factory=dict)


class KBView(BaseModel):
    """A focused view of the KB for prompt/context construction."""

    nodes: List[Node]
    edges: List[Edge]
