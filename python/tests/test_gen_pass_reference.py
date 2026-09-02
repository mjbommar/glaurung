"""`docs/reference/decompiler-passes.md` matches the pipeline it describes.

The pass list is the one decompiler fact that changes most often and that a
reader is most likely to take on trust. The document it lives in is generated
from `src/python_bindings/ir/pipeline.rs` and
`src/python_bindings/ir/decbench_render.rs`; this test regenerates it into a
temporary directory and diffs, so a pass added, removed, renamed or reordered
in Rust fails here rather than silently making the reference wrong.

The commit stamp in the header is excluded from the comparison. It records
when the file was regenerated, not what the pipeline does, and comparing it
would make this test fail on every commit that did not touch a pass.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "gen_pass_reference.py"
REFERENCE = ROOT / "docs" / "reference" / "decompiler-passes.md"


def _load_tool():
    spec = importlib.util.spec_from_file_location("gen_pass_reference", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen = _load_tool()


def test_the_committed_reference_matches_the_pipeline_source() -> None:
    """Regenerate from source and diff, ignoring the provenance line."""
    assert REFERENCE.is_file(), REFERENCE
    generated = gen.generate(ROOT, commit="test")
    assert gen.without_commit(REFERENCE.read_text()) == gen.without_commit(generated), (
        "docs/reference/decompiler-passes.md is stale.\n"
        "Run: uv run python tools/gen_pass_reference.py"
    )


def test_check_mode_agrees_with_the_committed_file(tmp_path: Path) -> None:
    """`--check` is the gate; it must pass on a tree nobody has edited."""
    executable = shutil.which("uv")
    argv = (
        [executable, "run", "python", str(TOOL), "--check"]
        if executable
        else [sys.executable, str(TOOL), "--check"]
    )
    result = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, env=_env(tmp_path)
    )
    assert result.returncode == 0, result.stderr


def test_writing_into_a_copied_tree_is_byte_stable(tmp_path: Path) -> None:
    """Two generations of the same source produce the same document."""
    first = gen.generate(ROOT, commit="fixed")
    second = gen.generate(ROOT, commit="fixed")
    assert first == second


def test_every_named_file_exists() -> None:
    """A pass row that cites a file must cite one that is there."""
    missing = []
    for line in gen.generate(ROOT, commit="test").splitlines():
        if not line.startswith("|"):
            continue
        for cell in line.split("|"):
            for token in cell.split(","):
                token = token.strip().strip("`")
                if token.startswith("src/") and not (ROOT / token).is_file():
                    missing.append(token)
    assert not missing, missing


def test_the_three_stages_are_present_and_ordered() -> None:
    """The document must not silently lose a whole chain.

    An earlier hand-written reference described only the AST pipeline and
    never mentioned the DecBench refine chain at all, which is the larger of
    the two and the one `--style decbench` actually runs.
    """
    text = gen.generate(ROOT, commit="test")
    stage1 = text.index("## Stage 1 -- LLIR preparation")
    stage2 = text.index("## Stage 2 -- the AST pass pipeline")
    stage3 = text.index("## Stage 3 -- the DecBench render chain")
    assert stage1 < stage2 < stage3
    for anchor in ("run_ast_passes", "prepare_llir_for_lowering", "ready_to_render"):
        assert anchor in text, anchor


def _env(tmp_path: Path) -> dict[str, str]:
    """A subprocess environment whose temporary files stay off `/tmp`."""
    import os

    env = dict(os.environ)
    env["TMPDIR"] = str(tmp_path)
    return env


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
