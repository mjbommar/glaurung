"""Contracts for the blinded DecBench external-agentic runner."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "decbench_external_agentic.py"


@pytest.fixture(scope="module")
def runner():
    """Load the standalone runner as a module."""
    spec = importlib.util.spec_from_file_location("decbench_external_agentic", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Reduced verbatim record from the real bin_000.elf @ 0x8350 paid canary run.
# It intentionally preserves the observed CLI schema and stage provenance.
REAL_CANARY = {
    "entry_va": 0x8350,
    "c_prototype": "void sub_8350(int initreq_fd);",
    "role": "ioctl_handler",
    "fidelity": "tldr",
    "stages": {
        "infer_function_signature": {"source": "llm", "confidence": 0.93},
        "classify_function_role": {"source": "llm"},
        "layer0_prepass": {"source": "skipped"},
        "rewrite_function_idiomatic": {"source": "llm"},
    },
    "language": "c",
    "source": "void sub_8350(int initreq_fd)\n{\n    (void)initreq_fd;\n}\n",
}


def test_real_canary_payload_is_accepted(runner) -> None:
    accepted = runner.accept_payload(REAL_CANARY, requested_va=0x8350)

    assert accepted.identifier == "sub_8350"
    assert accepted.source.startswith("void sub_8350(")
    assert accepted.stage_sources == {
        "infer_function_signature": "llm",
        "classify_function_role": "llm",
        "rewrite_function_idiomatic": "llm",
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"entry_va": 0x8352}, "entry address"),
        ({"language": "rust"}, "language"),
        ({"source": "```c\nvoid sub_8350(void) {}\n```"}, "markdown"),
        (
            {
                "stages": {
                    **REAL_CANARY["stages"],
                    "rewrite_function_idiomatic": {"source": "heuristic"},
                }
            },
            "rewrite_function_idiomatic",
        ),
    ],
)
def test_payload_validation_fails_closed(runner, mutation, message: str) -> None:
    payload = {**REAL_CANARY, **mutation}

    with pytest.raises(runner.PayloadError, match=message):
        runner.accept_payload(payload, requested_va=0x8350)


def test_agentic_command_is_static_scoped_and_requires_llm(runner) -> None:
    command = runner.explain_command(
        Path("/kit/binaries/bin_000.elf"),
        0x8350,
        Path("/venv/bin/glaurung"),
        stage_timeout_ms=120_000,
    )

    assert command[:3] == [
        "/venv/bin/glaurung",
        "explain",
        "/kit/binaries/bin_000.elf",
    ]
    assert command[command.index("--func") + 1] == "0x8350"
    assert "--require-llm" in command
    assert "--no-layer0" in command
    assert command[command.index("--timeout-ms") + 1] == "120000"


def test_submission_uses_authoritative_target_address(runner) -> None:
    run = runner.FunctionRun.success(
        binary="bin_000.elf",
        requested_va=0x8350,
        accepted=runner.accept_payload(REAL_CANARY, requested_va=0x8350),
        elapsed_seconds=23.5,
    )

    submission, sources = runner.build_submission(
        [run], version="git-32a9a9b+openai:gpt-5.4-mini"
    )

    assert submission["results"]["bin_000.c"]["functions"] == {"sub_8350": "0x8350"}
    assert sources["bin_000.c"].startswith("#include <errno.h>\n")
    assert "#include <sys/stat.h>" in sources["bin_000.c"]
    assert "void sub_8350" in sources["bin_000.c"]
