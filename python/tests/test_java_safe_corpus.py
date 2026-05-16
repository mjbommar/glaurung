from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _compile_modern_corpus(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for Java corpus fixtures")
    fixture = Path(__file__).parent / "fixtures" / "java" / "corpus" / "modern"
    source_root = fixture / "src" / "main" / "java"
    resource_root = fixture / "src" / "main" / "resources"
    out = tmp_path / "classes"
    out.mkdir()
    sources = sorted(str(path) for path in source_root.rglob("*.java"))
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), *sources],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "modern-corpus.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        for class_file in sorted(out.rglob("*.class")):
            zf.write(class_file, class_file.relative_to(out).as_posix())
        for resource in sorted(resource_root.rglob("*")):
            if resource.is_file():
                zf.write(resource, resource.relative_to(resource_root).as_posix())
    return jar


def test_java_safe_modern_corpus_exercises_records_modules_services(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _compile_modern_corpus(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), max_classes=16, max_entries=64),
    )

    kinds = {item.class_name: item.class_kind for item in result.classes}
    assert kinds["corpus/modern/Entry"] == "record"
    assert kinds["corpus/modern/Mode"] == "enum"
    assert result.module_info_present is True
    assert result.module_info is not None
    assert result.module_info.name == "corpus.modern"
    assert result.service_descriptor_count == 1
    assert result.service_descriptors[0].service_name == "corpus.modern.Plugin"
    assert result.service_descriptors[0].providers == ["corpus.modern.PluginImpl"]
