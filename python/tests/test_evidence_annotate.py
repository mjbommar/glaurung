"""Tests for annotation evidence builders.

These are light-touch tests to ensure the API returns structured
evidence and basic fields are populated for a known sample.
"""

from pathlib import Path

import glaurung as g  # noqa: F401 - ensure native extension is importable

# Try to import LLM evidence module, skip tests if dependencies not available
try:
    from glaurung.llm.evidence import annotate_functions_path, AnnotateBudgets

    HAS_LLM_DEPS = True
except ImportError:
    HAS_LLM_DEPS = False
    annotate_functions_path = None
    AnnotateBudgets = None


def test_annotate_functions_path_go_sample():
    # Skip if LLM dependencies not available
    if not HAS_LLM_DEPS:
        return

    # Use a known present sample (Go linux/amd64)
    sample = Path("samples/binaries/platforms/linux/amd64/export/go/hello-go")
    if not sample.exists():
        # Skip if samples not present in this environment
        return

    # Check if sample is corrupted (contains text instead of binary)
    with open(sample, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {sample} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    ev = annotate_functions_path(str(sample), AnnotateBudgets(max_functions=3))
    # Basic structure checks
    assert ev.path.endswith("hello-go")
    assert ev.functions, "no functions annotated"
    # Symbols may be empty for static Go; still ensure dicts exist
    assert isinstance(ev.symbols.plt_map, dict)
    assert isinstance(ev.symbols.sym_va_map, dict)
    # Check each function evidence has counts and instruction list
    for f in ev.functions:
        assert f.entry_va > 0
        assert f.instructions, "no instructions captured"
        # provided count should match captured instructions
        if f.instruction_count_provided is not None:
            assert f.instruction_count_provided == len(f.instructions)


def test_annotate_functions_path_windows_iat_calls():
    # Skip if LLM dependencies not available
    if not HAS_LLM_DEPS:
        return

    # Use a Windows x86_64 sample (cross-built) with simple imports (printf/puts)
    sample = Path(
        "samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe"
    )
    if not sample.exists():
        return

    # Check if sample is corrupted (contains text instead of binary)
    with open(sample, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {sample} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    ev = annotate_functions_path(str(sample), AnnotateBudgets(max_functions=5))
    # We expect at least one call site to resolve via IAT
    names = []
    for f in ev.functions:
        for c in f.calls:
            if c.target_name:
                names.append(c.target_name.lower())
    # Look for common C runtime imports
    assert any(n for n in names if any(k in n for k in ("puts", "printf")))


def test_elf_got_map_and_arm64_evidence():
    # Skip if LLM dependencies not available
    if not HAS_LLM_DEPS:
        return

    # Validate ELF GOT mapping runs and ARM64 evidence captures functions
    arm_sample = Path(
        "samples/binaries/platforms/linux/amd64/cross/arm64/hello-arm64-gcc"
    )
    if not arm_sample.exists():
        return

    # Check if sample is corrupted (contains text instead of binary)
    with open(arm_sample, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {arm_sample} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    # GOT map should be callable and return a list (possibly empty)
    if hasattr(g, "analysis"):
        got = g.analysis.elf_got_map_path(str(arm_sample))
        assert isinstance(got, list)
    else:
        # Skip if analysis module not available
        return
    # Annotation should produce at least one function and instructions
    ev = annotate_functions_path(str(arm_sample), AnnotateBudgets(max_functions=3))
    assert ev.functions
    # Expect some hint or string for the hello sample
    saw_string = False
    saw_hint = False
    for f in ev.functions:
        if f.hints:
            saw_hint = True
        if f.strings:
            saw_string = True
    assert saw_hint or saw_string


def test_riscv64_and_armhf_annotation():
    # Skip if LLM dependencies not available
    if not HAS_LLM_DEPS:
        return

    # RISC-V sample
    riscv = Path(
        "samples/binaries/platforms/linux/amd64/cross/riscv64/hello-riscv64-gcc"
    )
    if riscv.exists():
        # Check if sample is corrupted (contains text instead of binary)
        with open(riscv, "rb") as f:
            data = f.read(16)
        if data.startswith(b"version https://"):
            raise RuntimeError(
                f"Sample {riscv} appears to be a Git LFS pointer file. "
                "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
            )
        ev = annotate_functions_path(str(riscv), AnnotateBudgets(max_functions=4))
        assert ev.functions
        # Expect some hints or strings for hello
        assert any(f.hints or f.strings for f in ev.functions)
    # ARMHF sample
    armhf = Path("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc")
    if armhf.exists():
        # Check if sample is corrupted (contains text instead of binary)
        with open(armhf, "rb") as f:
            data = f.read(16)
        if data.startswith(b"version https://"):
            raise RuntimeError(
                f"Sample {armhf} appears to be a Git LFS pointer file. "
                "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
            )
        ev = annotate_functions_path(str(armhf), AnnotateBudgets(max_functions=4))
        assert ev.functions
        assert any(f.hints or f.strings for f in ev.functions)
