from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _write_misnamed_public_class(root: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java repair fixture")
    src = root / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source_path = src / "Wrong.java"
    source_path.write_text(
        """
package app;

public class Main {
    public String value() {
        return "repair-me";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (root / "sources.txt").write_text(
        "src/main/java/app/Wrong.java\n",
        encoding="utf-8",
    )
    (root / "javac.args").write_text(
        "--release\n17\n-d\nbuild/classes\n@sources.txt\n",
        encoding="utf-8",
    )
    return source_path


def _write_bad_inner_companion(root: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java repair fixture")
    src = root / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source_path = src / "Main$Nested.java"
    source_path.write_text(
        """
package app;

public static class Main.Nested {
    public int nestedValue() {
        return 7;
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (root / "sources.txt").write_text(
        "src/main/java/app/Main$Nested.java\n",
        encoding="utf-8",
    )
    (root / "javac.args").write_text(
        "--release\n17\n-d\nbuild/classes\n@sources.txt\n",
        encoding="utf-8",
    )
    return source_path


def _write_missing_local_dependency_project(root: Path, tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java repair fixture")
    dep_src = tmp_path / "dep-src"
    dep_classes = tmp_path / "dep-classes"
    dep_src.mkdir()
    dep_classes.mkdir()
    (dep_src / "Helper.java").write_text(
        """
package dep;

public class Helper {
    public static String value() {
        return "dep";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(dep_classes),
            str(dep_src / "Helper.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    libs = root / "libs"
    libs.mkdir(parents=True)
    with zipfile.ZipFile(libs / "dep.jar", "w") as zf:
        zf.write(dep_classes / "dep" / "Helper.class", "dep/Helper.class")

    src = root / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source_path = src / "UsesDep.java"
    source_path.write_text(
        """
package app;

import dep.Helper;

public class UsesDep {
    public String value() {
        return Helper.value();
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return source_path


def test_java_repair_decompiled_source_renames_public_type_file(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    source_path = _write_misnamed_public_class(project)
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is True
    assert result.iteration_count == 2
    assert result.repair_count == 1
    assert result.repairs[0].kind == "rename_public_type_file"
    assert result.repairs[0].file == "src/main/java/app/Wrong.java"
    assert result.repairs[0].new_file == "src/main/java/app/Main.java"
    assert not (project / "src" / "main" / "java" / "app" / "Wrong.java").exists()
    assert (project / "src" / "main" / "java" / "app" / "Main.java").is_file()
    assert (project / "sources.txt").read_text(
        encoding="utf-8"
    ).strip() == "src/main/java/app/Main.java"
    assert (project / "build" / "classes" / "app" / "Main.class").is_file()
    assert any(
        node.kind == NodeKind.java_repair_result
        and node.props.get("tool") == "java_repair_decompiled_source"
        for node in ctx.kb.nodes()
    )


def test_java_repair_decompiled_source_dry_run_does_not_rename(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    source_path = _write_misnamed_public_class(project)
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            source_project_root=str(project),
            java_release=17,
            dry_run=True,
        ),
    )

    assert result.success is False
    assert result.stop_reasons == ["dry_run"]
    assert result.repair_count == 0
    assert result.repairs[0].applied is False
    assert source_path.is_file()


def test_java_repair_decompiled_source_rewrites_inner_companion_declaration(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    source_path = _write_bad_inner_companion(project)
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is True
    assert result.iteration_count == 2
    assert result.repair_count == 1
    assert result.repairs[0].kind == "rewrite_inner_companion_declaration"
    repaired = source_path.read_text(encoding="utf-8")
    assert "public class Main$Nested" in repaired
    assert "static class Main.Nested" not in repaired
    assert (project / "build" / "classes" / "app" / "Main$Nested.class").is_file()


def test_java_repair_decompiled_source_adds_matching_local_classpath_jar(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    source_path = _write_missing_local_dependency_project(project, tmp_path)
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is True
    assert result.repair_count == 1
    assert result.repairs[0].kind == "add_local_classpath_jar"
    assert "libs/dep.jar" in (project / "javac.args").read_text(encoding="utf-8")
    assert (project / "build" / "classes" / "app" / "UsesDep.class").is_file()


def test_java_repair_decompiled_source_adds_unique_missing_import(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    src = project / "src" / "main" / "java"
    (src / "app").mkdir(parents=True)
    (src / "lib").mkdir(parents=True)
    (src / "app" / "Use.java").write_text(
        """
package app;

public class Use {
    private Helper helper;

    public Helper helper() {
        return helper;
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "lib" / "Helper.java").write_text(
        """
package lib;

public class Helper {
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(src / "app" / "Use.java")
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is True
    assert any(repair.kind == "add_missing_import" for repair in result.repairs)
    assert "import lib.Helper;" in (src / "app" / "Use.java").read_text(
        encoding="utf-8"
    )
    assert (project / "build" / "classes" / "app" / "Use.class").is_file()


def test_java_repair_decompiled_source_reports_ambiguous_missing_import(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    src = project / "src" / "main" / "java"
    (src / "app").mkdir(parents=True)
    (src / "lib1").mkdir(parents=True)
    (src / "lib2").mkdir(parents=True)
    (src / "app" / "Use.java").write_text(
        """
package app;

public class Use {
    private Helper helper;
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    for package in ("lib1", "lib2"):
        (src / package / "Helper.java").write_text(
            f"package {package};\n\npublic class Helper {{}}\n",
            encoding="utf-8",
        )
    ctx = _ctx(src / "app" / "Use.java")
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is False
    assert any(
        repair.kind == "ambiguous_missing_import" and not repair.applied
        for repair in result.repairs
    )
    assert "import lib1.Helper;" not in (src / "app" / "Use.java").read_text(
        encoding="utf-8"
    )


def test_java_repair_decompiled_source_writes_build_repair_plan_for_external_dep(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    src = project / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source = src / "UseExternal.java"
    source.write_text(
        """
package app;

import missing.lib.Helper;

public class UseExternal {
    private Helper helper;
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(source)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is False
    assert any(repair.kind == "write_build_repair_plan" for repair in result.repairs)
    plan = project / ".glaurung" / "build-repair-plan.json"
    assert plan.is_file()
    assert "missing.lib" in plan.read_text(encoding="utf-8")


def test_java_repair_decompiled_source_reports_signature_mismatch(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    src = project / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source = src / "BadCall.java"
    source.write_text(
        """
package app;

public class BadCall {
    public void target(String value) {}

    public void caller() {
        target(1);
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(source)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is False
    assert any(
        repair.kind == "report_signature_mismatch" and not repair.applied
        for repair in result.repairs
    )


def test_java_repair_decompiled_source_parameterizes_raw_foreach_iterable(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    src = project / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source = src / "RawLoop.java"
    source.write_text(
        """
package app;

import java.util.List;

public class RawLoop {
    public static final class Entry {
    }

    public void copy(Object input) {
        List entries = (List)input;
        for (Entry entry : entries) {
            entry.toString();
        }
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(source)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is True
    assert any(
        repair.kind == "parameterize_raw_iterable_for_each" and repair.applied
        for repair in result.repairs
    )
    repaired = source.read_text(encoding="utf-8")
    assert "List<Entry> entries = (List<Entry>)input;" in repaired
    assert (project / "build" / "classes" / "app" / "RawLoop.class").is_file()


def test_java_repair_decompiled_source_casts_generic_sneaky_throw(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_repair_decompiled_source import build_tool

    project = tmp_path / "project"
    src = project / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source = src / "Thrower.java"
    source.write_text(
        """
package app;

public class Thrower<T extends Throwable> {
    public void sneakyThrow(Throwable exception) throws T {
        throw exception;
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(source)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is True
    assert any(
        repair.kind == "cast_generic_sneaky_throw" and repair.applied
        for repair in result.repairs
    )
    repaired = source.read_text(encoding="utf-8")
    assert "throw (T)exception;" in repaired
    assert (project / "build" / "classes" / "app" / "Thrower.class").is_file()


def test_memory_agent_registers_java_repair_decompiled_source() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_repair_decompiled_source" in agent._function_toolset.tools
