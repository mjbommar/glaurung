from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
import re


MemberKind = Literal["field", "method"]
MatchKind = Literal["official", "obfuscated", "none"]


@dataclass(frozen=True)
class ProguardMemberMapping:
    kind: MemberKind
    official_name: str
    obfuscated_name: str
    official_signature: str


@dataclass
class ProguardClassMapping:
    official_name: str
    obfuscated_name: str
    fields: list[ProguardMemberMapping] = field(default_factory=list)
    methods: list[ProguardMemberMapping] = field(default_factory=list)


@dataclass
class ProguardMappings:
    by_obfuscated: dict[str, ProguardClassMapping]
    by_official: dict[str, ProguardClassMapping]

    def lookup_class(self, name: str) -> tuple[ProguardClassMapping | None, MatchKind]:
        obfuscated = self.by_obfuscated.get(name) or self.by_obfuscated.get(
            name.replace("/", ".")
        )
        if obfuscated is not None:
            return obfuscated, "obfuscated"
        official = self.by_official.get(name) or self.by_official.get(
            name.replace("/", ".")
        )
        if official is not None:
            return official, "official"
        return None, "none"

    def obfuscated_descriptor_for(self, member: ProguardMemberMapping) -> str | None:
        return _descriptor_for(member, self, namespace="obfuscated")

    def official_descriptor_for(self, member: ProguardMemberMapping) -> str | None:
        return _descriptor_for(member, self, namespace="official")

    def matching_member_mappings(
        self,
        class_mapping: ProguardClassMapping,
        *,
        kind: MemberKind,
        obfuscated_name: str,
        descriptor: str,
    ) -> list[ProguardMemberMapping]:
        candidates = class_mapping.methods if kind == "method" else class_mapping.fields
        return [
            member
            for member in candidates
            if member.obfuscated_name == obfuscated_name
            and _member_descriptor_matches(member, descriptor, self)
        ]


def parse_proguard_mappings(path: Path) -> ProguardMappings:
    text = path.read_text(encoding="utf-8", errors="replace")
    first_line = _first_mapping_line(text)
    if first_line.startswith("tiny\t2\t"):
        return _parse_tiny_v2_mappings(text)
    if first_line.startswith("v1\t"):
        return _parse_tiny_v1_mappings(text)
    by_obfuscated: dict[str, ProguardClassMapping] = {}
    by_official: dict[str, ProguardClassMapping] = {}
    current: ProguardClassMapping | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line[0].isspace():
            current = _parse_class_line(raw_line)
            if current is not None:
                by_obfuscated[current.obfuscated_name] = current
                by_official[current.official_name] = current
            continue
        if current is None or " -> " not in raw_line:
            continue
        member = _parse_member_line(raw_line)
        if member is None:
            continue
        if member.kind == "method":
            current.methods.append(member)
        else:
            current.fields.append(member)
    return ProguardMappings(
        by_obfuscated=by_obfuscated,
        by_official=by_official,
    )


def _first_mapping_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return ""


def _parse_tiny_v2_mappings(text: str) -> ProguardMappings:
    by_obfuscated: dict[str, ProguardClassMapping] = {}
    by_official: dict[str, ProguardClassMapping] = {}
    current: ProguardClassMapping | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        parts = raw_line.split("\t")
        tag = parts[0]
        if tag == "c" and len(parts) >= 3:
            current = _add_tiny_class_mapping(
                by_obfuscated, by_official, parts[1], parts[2]
            )
            continue
        if current is None or len(parts) < 4:
            continue
        member_tag = parts[1] if parts[0] == "" else parts[0]
        offset = 1 if parts[0] == "" else 0
        if member_tag == "m" and len(parts) >= offset + 4:
            current.methods.append(
                ProguardMemberMapping(
                    kind="method",
                    official_name=parts[offset + 3],
                    obfuscated_name=parts[offset + 2],
                    official_signature=parts[offset + 1],
                )
            )
        elif member_tag == "f" and len(parts) >= offset + 4:
            current.fields.append(
                ProguardMemberMapping(
                    kind="field",
                    official_name=parts[offset + 3],
                    obfuscated_name=parts[offset + 2],
                    official_signature=parts[offset + 1],
                )
            )
    return ProguardMappings(by_obfuscated=by_obfuscated, by_official=by_official)


def _parse_tiny_v1_mappings(text: str) -> ProguardMappings:
    by_obfuscated: dict[str, ProguardClassMapping] = {}
    by_official: dict[str, ProguardClassMapping] = {}
    by_source: dict[str, ProguardClassMapping] = {}
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        parts = raw_line.split("\t")
        tag = parts[0]
        if tag == "CLASS" and len(parts) >= 3:
            mapping = _add_tiny_class_mapping(
                by_obfuscated,
                by_official,
                parts[1],
                parts[2],
            )
            by_source[parts[1]] = mapping
            continue
        if tag == "METHOD" and len(parts) >= 5:
            mapping = by_source.get(parts[1])
            if mapping is not None:
                mapping.methods.append(
                    ProguardMemberMapping(
                        kind="method",
                        official_name=parts[4],
                        obfuscated_name=parts[3],
                        official_signature=parts[2],
                    )
                )
        elif tag == "FIELD" and len(parts) >= 5:
            mapping = by_source.get(parts[1])
            if mapping is not None:
                mapping.fields.append(
                    ProguardMemberMapping(
                        kind="field",
                        official_name=parts[4],
                        obfuscated_name=parts[3],
                        official_signature=parts[2],
                    )
                )
    return ProguardMappings(by_obfuscated=by_obfuscated, by_official=by_official)


def _add_tiny_class_mapping(
    by_obfuscated: dict[str, ProguardClassMapping],
    by_official: dict[str, ProguardClassMapping],
    obfuscated_name: str,
    official_name: str,
) -> ProguardClassMapping:
    mapping = ProguardClassMapping(
        official_name=_tiny_external_name(official_name),
        obfuscated_name=_tiny_external_name(obfuscated_name),
    )
    by_obfuscated[mapping.obfuscated_name] = mapping
    by_official[mapping.official_name] = mapping
    return mapping


def _tiny_external_name(value: str) -> str:
    return value.replace("/", ".")


def _parse_class_line(line: str) -> ProguardClassMapping | None:
    if " -> " not in line or not line.rstrip().endswith(":"):
        return None
    official_name, obfuscated_name = line.rstrip(":").split(" -> ", 1)
    return ProguardClassMapping(
        official_name=official_name.strip(),
        obfuscated_name=obfuscated_name.strip(),
    )


def _parse_member_line(line: str) -> ProguardMemberMapping | None:
    lhs, obfuscated_name = line.rsplit(" -> ", 1)
    lhs = lhs.strip()
    obfuscated_name = obfuscated_name.strip()
    if not lhs or not obfuscated_name:
        return None
    if "(" in lhs and ")" in lhs:
        return ProguardMemberMapping(
            kind="method",
            official_name=_official_method_name(lhs),
            obfuscated_name=obfuscated_name,
            official_signature=lhs,
        )
    return ProguardMemberMapping(
        kind="field",
        official_name=_official_field_name(lhs),
        obfuscated_name=obfuscated_name,
        official_signature=lhs,
    )


def _official_method_name(lhs: str) -> str:
    before_args = lhs.split("(", 1)[0].strip()
    return before_args.split()[-1].rsplit(":", 1)[-1]


def _official_field_name(lhs: str) -> str:
    return lhs.strip().split()[-1]


def _descriptor_for(
    member: ProguardMemberMapping,
    mappings: ProguardMappings,
    *,
    namespace: Literal["official", "obfuscated"],
) -> str | None:
    signature = _strip_line_prefixes(member.official_signature)
    if member.kind == "field":
        parts = signature.rsplit(" ", 1)
        if len(parts) != 2:
            return None
        return _type_descriptor(parts[0], mappings, namespace=namespace)
    parsed = _parse_method_signature(signature)
    if parsed is None:
        return None
    return_type, _, parameter_types = parsed
    param_descriptors = [
        _type_descriptor(param, mappings, namespace=namespace)
        for param in parameter_types
    ]
    return_descriptor = _type_descriptor(return_type, mappings, namespace=namespace)
    if return_descriptor is None or any(desc is None for desc in param_descriptors):
        return None
    return f"({''.join(desc for desc in param_descriptors if desc is not None)}){return_descriptor}"


def _strip_line_prefixes(signature: str) -> str:
    return re.sub(r"^(?:\d+:)+", "", signature.strip())


def _parse_method_signature(signature: str) -> tuple[str, str, list[str]] | None:
    left, sep, right = signature.partition("(")
    if not sep:
        return None
    params_text, sep, _ = right.partition(")")
    if not sep:
        return None
    before_args = left.strip()
    parts = before_args.rsplit(" ", 1)
    if len(parts) != 2:
        return None
    return_type, method_name = parts
    params = [param.strip() for param in params_text.split(",") if param.strip()]
    return return_type, method_name, params


def _type_descriptor(
    type_name: str,
    mappings: ProguardMappings,
    *,
    namespace: Literal["official", "obfuscated"],
) -> str | None:
    name = _strip_generics(type_name.strip())
    if not name:
        return None
    array_depth = 0
    while name.endswith("[]"):
        array_depth += 1
        name = name[:-2]
    if name.endswith("..."):
        array_depth += 1
        name = name[:-3]
    primitive = {
        "byte": "B",
        "char": "C",
        "double": "D",
        "float": "F",
        "int": "I",
        "long": "J",
        "short": "S",
        "boolean": "Z",
        "void": "V",
    }.get(name)
    if primitive is not None:
        descriptor = primitive
    else:
        mapped = mappings.by_official.get(name)
        if namespace == "obfuscated" and mapped is not None:
            internal = mapped.obfuscated_name.replace(".", "/")
        else:
            internal = name.replace(".", "/")
        descriptor = f"L{internal};"
    return "[" * array_depth + descriptor


def _member_descriptor_matches(
    member: ProguardMemberMapping,
    descriptor: str,
    mappings: ProguardMappings,
) -> bool:
    expected = mappings.obfuscated_descriptor_for(member)
    if expected is None:
        return True
    return expected == descriptor


def _strip_generics(type_name: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in type_name:
        if ch == "<":
            depth += 1
            continue
        if ch == ">":
            depth = max(depth - 1, 0)
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)
