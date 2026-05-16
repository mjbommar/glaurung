from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from _pytest.capture import CaptureFixture

from glaurung import cli


def _simple_recoverable_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java recovery fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "Main.java").write_text(
        """
package app;

public class Main {
    public String value() {
        return "daily-driver-cli";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "Main.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "simple-cli.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
    return jar


def test_java_recovery_report_cli_outputs_daily_markdown(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    jar = _simple_recoverable_jar(tmp_path)
    output = tmp_path / "cli-recovered"

    rc = cli.main(
        [
            "java-recovery-report",
            str(jar),
            "--output-root",
            str(output),
            "--java-release",
            "17",
            "--max-classes",
            "4",
            "--validate-profile",
            "compile_only",
        ]
    )

    assert rc == 0
    stdout = capsys.readouterr().out
    assert "# Java Recovery Report" in stdout
    assert "## Rollups" in stdout
    assert "## Commands" in stdout
    assert (output / ".glaurung" / "recovery-report.md").is_file()
    assert (output / ".glaurung" / "recovery-report.json").is_file()


def test_java_recovery_report_cli_outputs_structured_json(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    jar = _simple_recoverable_jar(tmp_path)
    output = tmp_path / "cli-json-recovered"

    rc = cli.main(
        [
            "java-recovery-report",
            str(jar),
            "--output-root",
            str(output),
            "--java-release",
            "17",
            "--max-classes",
            "4",
            "--validate-profile",
            "compile_only",
            "--json",
        ]
    )

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "clean"
    assert data["rollups"]["by_package"]["app"] == 1
    assert "recovery_result" not in data
