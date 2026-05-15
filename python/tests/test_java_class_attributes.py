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

public class AttributeFixture {
    public static int checked(String input) throws IOException {
        int base = input.length();
        if (base == 0) {
            throw new IOException("empty");
        }
        int total = base + 7;
        return total;
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


def test_parse_java_class_recovers_source_exceptions_and_local_variables(
    tmp_path: Path,
) -> None:
    class_file = _compile_attribute_class(tmp_path)

    info = g.analysis.parse_java_class_bytes(class_file.read_bytes())

    assert info is not None
    assert info["source_file"] == "AttributeFixture.java"
    checked = next(method for method in info["methods"] if method["name"] == "checked")
    assert checked["exceptions"] == ["java/io/IOException"]
    locals_by_name = {item["name"]: item for item in checked["code"]["local_variables"]}
    assert locals_by_name["input"]["descriptor"] == "Ljava/lang/String;"
    assert locals_by_name["input"]["index"] == 0
    assert locals_by_name["base"]["descriptor"] == "I"
    assert locals_by_name["total"]["descriptor"] == "I"
