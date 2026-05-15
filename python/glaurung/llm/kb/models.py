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
    java_archive = "java_archive"
    java_class = "java_class"
    java_method = "java_method"
    java_field = "java_field"
    java_resource = "java_resource"
    java_bytecode = "java_bytecode"
    java_cfg = "java_cfg"
    java_xref = "java_xref"
    java_mapping = "java_mapping"
    java_sensitive_sink = "java_sensitive_sink"
    java_entrypoint = "java_entrypoint"
    java_config_key = "java_config_key"
    java_secret = "java_secret"
    java_config_correlation = "java_config_correlation"
    java_risk_finding = "java_risk_finding"


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
