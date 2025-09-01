import json
from pathlib import Path

import pytest

import glaurung as g
from glaurung import cli as cli


def test_cli_triage_json_system_binary_ls(capsys):
    ls_path = Path("/usr/bin/ls")
    if not ls_path.exists():
        pytest.skip("/usr/bin/ls not found")

    # Run CLI with --json
    rc = cli.main(["triage", str(ls_path), "--json"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out
    # First line should be JSON for the artifact
    obj = json.loads(out.splitlines()[0])
    assert obj["path"] == str(ls_path)
    assert obj["size_bytes"] > 0
    assert isinstance(obj.get("verdicts"), list)


def test_cli_triage_pretty_bytes(capsys):
    data = b"\x7fELF" + b"\x00" * 64
    g.triage.analyze_bytes(data)
    # Write to a temp file and analyze via CLI
    tmp = Path.cwd() / "_tmp_elf.bin"
    try:
        tmp.write_bytes(data)
        rc = cli.main(["triage", str(tmp)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "path:" in out and str(tmp) in out
    finally:
        if tmp.exists():
            tmp.unlink()
