from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from source_cfg_unscored_coverage import FUNCTION_MARKER_RE, missing_source_inputs


def test_function_marker_inventory_excludes_prototypes() -> None:
    text = """\
// Function: real @ 0x10
int real(void) { extern int prototype(void); return prototype(); }
"""
    assert FUNCTION_MARKER_RE.findall(text) == ["real"]


def test_missing_source_inventory_requires_decompiled_c_but_not_source_cfg(
    tmp_path: Path,
) -> None:
    decompiled = tmp_path / "O0" / "p" / "decompiled"
    source_cfgs = tmp_path / "O0" / "p" / "source_cfgs"
    decompiled.mkdir(parents=True)
    source_cfgs.mkdir()
    (decompiled / "col_missing.c").write_text("// Function: f @ 0x1\nint f(void){}\n")
    (decompiled / "col_present.c").write_text("// Function: g @ 0x2\nint g(void){}\n")
    (source_cfgs / "present.json").write_text("{}")

    rows = missing_source_inputs(tmp_path, "col")

    assert [(opt, project, binary) for opt, project, binary, _ in rows] == [
        ("O0", "p", "missing")
    ]
