"""Java classfile / JAR triage CLI subcommand (#209).

`glaurung classfile <path>` parses a single `.class` and prints its
structured metadata. When given a `.jar`, walks every class entry
in the archive and prints a per-class summary.
"""

import argparse
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _format_access(flags: int, is_method: bool = False) -> str:
    """Render a JVM access_flags bitmap as Java-source-like keywords."""
    parts = []
    if flags & 0x0001:
        parts.append("public")
    if flags & 0x0002:
        parts.append("private")
    if flags & 0x0004:
        parts.append("protected")
    if flags & 0x0008:
        parts.append("static")
    if flags & 0x0010:
        parts.append("final")
    if is_method:
        if flags & 0x0020:
            parts.append("synchronized")
        if flags & 0x0100:
            parts.append("native")
        if flags & 0x0400:
            parts.append("abstract")
    if flags & 0x0200:
        parts.append("interface")
    if flags & 0x4000:
        parts.append("enum")
    return " ".join(parts) if parts else "package-private"


def _java_version_label(major: int) -> str:
    if major >= 49:
        return f"Java {major - 44} (classfile {major})"
    return f"classfile {major}"


def _render_class_summary(info: dict, formatter: BaseFormatter) -> None:
    formatter.output_plain(
        f"class {info['class_name']}  ({_java_version_label(info['major_version'])})"
    )
    if info["super_class"] and info["super_class"] != "java/lang/Object":
        formatter.output_plain(f"  extends {info['super_class']}")
    elif info["super_class"]:
        formatter.output_plain(f"  extends {info['super_class']}")
    if info["interfaces"]:
        formatter.output_plain(
            f"  implements {', '.join(info['interfaces'])}"
        )
    formatter.output_plain(f"  access: {_format_access(info['access_flags'])}")
    formatter.output_plain(f"  fields: {len(info['fields'])}")
    for f in info["fields"]:
        formatter.output_plain(
            f"    {_format_access(f['access_flags']):<24} {f['name']}: {f['descriptor']}"
        )
    formatter.output_plain(f"  methods: {len(info['methods'])}")
    for m in info["methods"]:
        formatter.output_plain(
            f"    {_format_access(m['access_flags'], is_method=True):<24} {m['name']}{m['descriptor']}"
        )


def _scan_jar(path: Path, formatter: BaseFormatter) -> int:
    """Walk a JAR archive and print every class it contains. Returns
    the number of classes successfully parsed."""
    parsed = 0
    with zipfile.ZipFile(path) as zf:
        names = sorted(n for n in zf.namelist() if n.endswith(".class"))
        formatter.output_plain(f"# {path.name}: {len(names)} class file(s)")
        for entry in names:
            data = zf.read(entry)
            tmp = Path(f"/tmp/_glaurung_classfile_{abs(hash(entry)):x}.class")
            tmp.write_bytes(data)
            try:
                info = g.analysis.parse_java_class_path(str(tmp))
                if info is None:
                    continue
                formatter.output_plain("")
                _render_class_summary(info, formatter)
                parsed += 1
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
    return parsed


class ClassfileCommand(BaseCommand):
    """Parse a Java .class file (or every class in a .jar)."""

    def get_name(self) -> str:
        return "classfile"

    def get_help(self) -> str:
        return "Parse a Java .class file or .jar and print methods/fields"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help=".class file or .jar archive")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        path = Path(args.path)
        if not path.exists():
            formatter.output_plain(f"Error: not found: {path}")
            return 2

        # JAR detection: any zipfile whose name ends in .jar (or which
        # zipfile.is_zipfile recognizes — covers .war / .ear / unnamed).
        if path.suffix.lower() in (".jar", ".war", ".ear") or zipfile.is_zipfile(path):
            try:
                count = _scan_jar(path, formatter)
            except zipfile.BadZipFile:
                formatter.output_plain(f"Error: not a valid archive: {path}")
                return 3
            formatter.output_plain(f"\n_parsed {count} class(es)_")
            return 0

        info = g.analysis.parse_java_class_path(str(path))
        if info is None:
            formatter.output_plain(f"Error: not a Java class file: {path}")
            return 4
        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(info)
            return 0
        _render_class_summary(info, formatter)
        return 0
