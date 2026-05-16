from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import glaurung as g


def _compile_attribute_class(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    source = src / "AttributeFixture.java"
    source.write_text(
        """
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

enum AttributeMode {
    ALPHA,
    BETA
}

@Retention(RetentionPolicy.RUNTIME)
@interface AttributeTag {
    String value();
    Class<?> type() default String.class;
    AttributeMode mode() default AttributeMode.ALPHA;
    String[] flags() default {};
}

@AttributeTag(value = "class-level", type = Integer.class, mode = AttributeMode.BETA, flags = {"fast", "safe"})
public class AttributeFixture {
    @AttributeTag("method-level")
    public static int checked(String input) throws IOException {
        int base = input.length();
        if (base == 0) {
            throw new IOException("empty");
        }
        int total = base + 7;
        return total;
    }

    public static int guarded(String input) {
        try {
            return Integer.parseInt(input);
        } catch (NumberFormatException ex) {
            return -1;
        }
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "-g", "--release", "17", "-d", str(out), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return out / "AttributeFixture.class"


def _compile_structure_classes(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "structure-src"
    out = tmp_path / "structure-classes"
    src.mkdir()
    out.mkdir()
    source = src / "StructureFixture.java"
    source.write_text(
        """
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.RECORD_COMPONENT)
@interface ComponentTag {}

public class StructureFixture {
    public static class StaticInner {}
    public class MemberInner {}

    public void makeLocal() {
        class LocalThing {}
        new LocalThing();
    }
}

record StructureRecord(@ComponentTag String hash, long size) {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "-g", "--release", "17", "-d", str(out), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return out


def _compile_sealed_classes(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "sealed-src"
    out = tmp_path / "sealed-classes"
    src.mkdir()
    out.mkdir()
    source = src / "Shape.java"
    source.write_text(
        """
public sealed interface Shape permits Circle, Square {}

final class Circle implements Shape {}

non-sealed class Square implements Shape {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "-g", "--release", "17", "-d", str(out), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return out


def _compile_generic_class(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "generic-src"
    out = tmp_path / "generic-classes"
    src.mkdir()
    out.mkdir()
    source = src / "GenericFixture.java"
    source.write_text(
        """
import java.util.List;
import java.util.Map;

public class GenericFixture<T extends Number> {
    public List<String> names;

    public Map<String, T> lookup(List<T> values) {
        return Map.of();
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "-g", "--release", "17", "-d", str(out), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return out / "GenericFixture.class"


def _compile_parameter_metadata_classes(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "parameter-src"
    out = tmp_path / "parameter-classes"
    src.mkdir()
    out.mkdir()
    source = src / "ParameterFixture.java"
    source.write_text(
        """
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.METHOD})
@interface ParamTag {
    String value() default "fallback";
}

public class ParameterFixture {
    public void handle(@ParamTag("path") String path, int count) {}
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "-g",
            "-parameters",
            "--release",
            "17",
            "-d",
            str(out),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return out


def test_parse_java_class_recovers_source_exceptions_and_local_variables(
    tmp_path: Path,
) -> None:
    class_file = _compile_attribute_class(tmp_path)

    info = getattr(g, "analysis").parse_java_class_bytes(class_file.read_bytes())

    assert info is not None
    assert info["source_file"] == "AttributeFixture.java"
    checked = next(method for method in info["methods"] if method["name"] == "checked")
    assert checked["exceptions"] == ["java/io/IOException"]
    locals_by_name = {item["name"]: item for item in checked["code"]["local_variables"]}
    assert locals_by_name["input"]["descriptor"] == "Ljava/lang/String;"
    assert locals_by_name["input"]["index"] == 0
    assert locals_by_name["base"]["descriptor"] == "I"
    assert locals_by_name["total"]["descriptor"] == "I"


def test_parse_java_class_recovers_generic_signatures(tmp_path: Path) -> None:
    class_file = _compile_generic_class(tmp_path)

    info = getattr(g, "analysis").parse_java_class_bytes(class_file.read_bytes())

    assert info is not None
    assert info["signature"] == "<T:Ljava/lang/Number;>Ljava/lang/Object;"
    names = next(field for field in info["fields"] if field["name"] == "names")
    assert names["signature"] == "Ljava/util/List<Ljava/lang/String;>;"
    lookup = next(method for method in info["methods"] if method["name"] == "lookup")
    assert lookup["signature"] == (
        "(Ljava/util/List<TT;>;)Ljava/util/Map<Ljava/lang/String;TT;>;"
    )


def test_parse_java_class_recovers_parameter_metadata_and_annotation_defaults(
    tmp_path: Path,
) -> None:
    class_dir = _compile_parameter_metadata_classes(tmp_path)
    java_analysis = getattr(g, "analysis")

    fixture = java_analysis.parse_java_class_bytes(
        (class_dir / "ParameterFixture.class").read_bytes()
    )
    annotation = java_analysis.parse_java_class_bytes(
        (class_dir / "ParamTag.class").read_bytes()
    )

    assert fixture is not None
    handle = next(method for method in fixture["methods"] if method["name"] == "handle")
    assert handle["method_parameters"] == [
        {"name": "path", "access_flags": 0},
        {"name": "count", "access_flags": 0},
    ]
    assert len(handle["parameter_annotations"]) == 2
    assert handle["parameter_annotations"][0]["parameter_index"] == 0
    assert handle["parameter_annotations"][0]["annotations"][0]["descriptor"] == (
        "LParamTag;"
    )
    assert handle["parameter_annotations"][0]["annotations"][0]["elements"] == [
        {
            "name": "value",
            "value": {
                "tag": "s",
                "kind": "const",
                "value": "path",
            },
        }
    ]
    assert handle["parameter_annotations"][1] == {
        "parameter_index": 1,
        "annotations": [],
    }

    assert annotation is not None
    value = next(
        method for method in annotation["methods"] if method["name"] == "value"
    )
    assert value["annotation_default"] == {
        "tag": "s",
        "kind": "const",
        "value": "fallback",
    }


def test_parse_java_class_recovers_inner_record_and_nest_metadata(
    tmp_path: Path,
) -> None:
    class_dir = _compile_structure_classes(tmp_path)
    java_analysis = getattr(g, "analysis")

    outer = java_analysis.parse_java_class_bytes(
        (class_dir / "StructureFixture.class").read_bytes()
    )
    local = java_analysis.parse_java_class_bytes(
        (class_dir / "StructureFixture$1LocalThing.class").read_bytes()
    )
    record = java_analysis.parse_java_class_bytes(
        (class_dir / "StructureRecord.class").read_bytes()
    )

    assert outer is not None
    inner_classes = {
        (
            item["inner_class"],
            item.get("outer_class"),
            item.get("inner_name"),
        )
        for item in outer["inner_classes"]
    }
    assert (
        "StructureFixture$StaticInner",
        "StructureFixture",
        "StaticInner",
    ) in inner_classes
    assert (
        "StructureFixture$MemberInner",
        "StructureFixture",
        "MemberInner",
    ) in inner_classes
    assert any(
        inner_class.endswith("$1LocalThing")
        and outer_class is None
        and inner_name == "LocalThing"
        for inner_class, outer_class, inner_name in inner_classes
    )
    assert "StructureFixture$StaticInner" in outer["nest_members"]
    assert "StructureFixture$MemberInner" in outer["nest_members"]

    assert local is not None
    assert local["nest_host"] == "StructureFixture"
    assert local["enclosing_method"] == {
        "class_name": "StructureFixture",
        "method_name": "makeLocal",
        "method_descriptor": "()V",
    }

    assert record is not None
    assert record["super_class"] == "java/lang/Record"
    assert [item["name"] for item in record["record_components"]] == ["hash", "size"]
    assert record["record_components"][0]["descriptor"] == "Ljava/lang/String;"
    assert record["record_components"][0]["annotations"][0]["descriptor"] == (
        "LComponentTag;"
    )
    assert record["record_components"][1]["descriptor"] == "J"


def test_parse_java_class_recovers_permitted_subclasses(tmp_path: Path) -> None:
    class_dir = _compile_sealed_classes(tmp_path)
    java_analysis = getattr(g, "analysis")

    shape = java_analysis.parse_java_class_bytes(
        (class_dir / "Shape.class").read_bytes()
    )
    circle = java_analysis.parse_java_class_bytes(
        (class_dir / "Circle.class").read_bytes()
    )

    assert shape is not None
    assert shape["permitted_subclasses"] == ["Circle", "Square"]
    assert circle is not None
    assert circle["permitted_subclasses"] == []


def test_parse_java_class_recovers_exception_handlers(tmp_path: Path) -> None:
    class_file = _compile_attribute_class(tmp_path)

    info = getattr(g, "analysis").parse_java_class_bytes(class_file.read_bytes())

    assert info is not None
    guarded = next(method for method in info["methods"] if method["name"] == "guarded")
    code = guarded["code"]
    assert code["exception_table_len"] == 1
    assert code["stack_map_frame_count"] > 0
    assert len(code["exception_handlers"]) == 1
    handler = code["exception_handlers"][0]
    assert handler["catch_type"] == "java/lang/NumberFormatException"
    assert handler["start_pc"] == 0
    assert handler["end_pc"] > handler["start_pc"]
    assert handler["handler_pc"] >= handler["end_pc"]


def test_parse_java_class_recovers_runtime_visible_annotations(
    tmp_path: Path,
) -> None:
    class_file = _compile_attribute_class(tmp_path)

    info = getattr(g, "analysis").parse_java_class_bytes(class_file.read_bytes())

    assert info is not None
    class_tag = next(
        annotation
        for annotation in info["annotations"]
        if annotation["descriptor"] == "LAttributeTag;"
    )
    assert class_tag["visibility"] == "runtime_visible"
    elements = {item["name"]: item["value"] for item in class_tag["elements"]}
    assert elements["value"] == {
        "tag": "s",
        "kind": "const",
        "value": "class-level",
    }
    assert elements["type"] == {
        "tag": "c",
        "kind": "class",
        "value": "Ljava/lang/Integer;",
    }
    assert elements["mode"] == {
        "tag": "e",
        "kind": "enum",
        "type_name": "LAttributeMode;",
        "const_name": "BETA",
    }
    assert elements["flags"] == {
        "tag": "[",
        "kind": "array",
        "values": [
            {"tag": "s", "kind": "const", "value": "fast"},
            {"tag": "s", "kind": "const", "value": "safe"},
        ],
    }

    checked = next(method for method in info["methods"] if method["name"] == "checked")
    method_tag = next(
        annotation
        for annotation in checked["annotations"]
        if annotation["descriptor"] == "LAttributeTag;"
    )
    method_elements = {item["name"]: item["value"] for item in method_tag["elements"]}
    assert method_elements["value"]["value"] == "method-level"
