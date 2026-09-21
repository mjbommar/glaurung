"""Check the per-binary result artifacts a local DecBench replay writes.

The replay harness used to drop a timed-out binary entirely: `stats["timeout"]
+= 1; continue`, writing neither `.c` nor `.toml`. The binary then vanished
from the tree and `decbench_audit_full` reported an `evaluated binary set
mismatch` rather than a timeout, so a self-inflicted budget failure read as a
corrupt run. Upstream instead persists `failed_functions = ["all"]` with
`timeout = true`, which is what these tests pin.
"""

import importlib.util
import pathlib
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "decbench_tree_writer", ROOT / "tools" / "decbench_tree_writer.py"
)
assert SPEC is not None and SPEC.loader is not None
WRITER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRITER)


def _parse(text: str) -> dict:
    return tomllib.loads(text)


def test_success_toml_round_trips_and_keeps_the_published_field_names() -> None:
    text = WRITER.render_result_toml(
        binary="grep",
        decompiler="glaurung-abc1234",
        version="abc1234",
        total_time=1.25,
        functions={"main": ("0x1000", 42, 3), "helper": ("0x2000", 7, 0)},
        failed_functions=["absent"],
    )
    parsed = _parse(text)
    assert parsed["binary"] == "grep"
    assert parsed["decompiler"] == "glaurung-abc1234"
    assert parsed["version"] == "abc1234"
    assert parsed["timeout"] is False
    assert parsed["function_count"] == 2
    assert parsed["failed_functions"] == ["absent"]
    assert parsed["functions.main"]["address"] == "0x1000"
    assert parsed["functions.main"]["line_count"] == 42
    assert parsed["functions.main"]["gotos"] == 3
    assert parsed["functions.helper"]["bools"] == 0


def test_timeout_toml_declares_the_failure_rather_than_vanishing() -> None:
    text = WRITER.render_timeout_toml(
        binary="u-boot",
        decompiler="glaurung-abc1234",
        version="abc1234",
        total_time=3600.0,
        budget_seconds=3600,
    )
    parsed = _parse(text)
    assert parsed["timeout"] is True
    assert parsed["failed_functions"] == ["all"]
    assert parsed["function_count"] == 0
    assert parsed["budget_seconds"] == 3600
    assert parsed["binary"] == "u-boot"


def test_timeout_toml_emits_no_function_tables() -> None:
    """A timed-out binary produced no bodies, so it must claim none.

    A stub body would be worse than an omission: `return 0;` parses to a
    one-node CFG and scores GED-perfect, which is the published null baseline.
    """
    text = WRITER.render_timeout_toml(
        binary="u-boot",
        decompiler="glaurung-abc1234",
        version="abc1234",
        total_time=3600.0,
        budget_seconds=3600,
    )
    assert '["functions.' not in text
    assert _parse(text)["function_count"] == 0


def test_a_timed_out_binary_writes_no_c_artifact(tmp_path: pathlib.Path) -> None:
    """The audit is fail-closed on a `.c` with no markers; write none at all."""
    written = WRITER.write_timeout_result(
        directory=tmp_path,
        binary="u-boot",
        decompiler="glaurung-abc1234",
        version="abc1234",
        total_time=3600.0,
        budget_seconds=3600,
    )
    assert written.name == "glaurung-abc1234_u-boot.toml"
    assert written.exists()
    assert list(tmp_path.glob("*.c")) == []


def test_success_rejects_an_empty_function_set() -> None:
    """Zero functions is the timeout/failure shape, not a success shape."""
    with pytest.raises(WRITER.ResultError):
        WRITER.render_result_toml(
            binary="grep",
            decompiler="glaurung-abc1234",
            version="abc1234",
            total_time=1.0,
            functions={},
            failed_functions=[],
        )


def test_a_name_that_would_break_the_toml_is_rejected() -> None:
    with pytest.raises(WRITER.ResultError, match="unsafe"):
        WRITER.render_result_toml(
            binary="grep",
            decompiler="glaurung-abc1234",
            version="abc1234",
            total_time=1.0,
            functions={'we"ird': ("0x1000", 1, 0)},
            failed_functions=[],
        )
