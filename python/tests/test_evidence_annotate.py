"""Tests for annotation evidence builders.

These are light-touch tests to ensure the API returns structured
evidence and basic fields are populated for a known sample.
"""

from pathlib import Path

import glaurung as g  # noqa: F401 - ensure native extension is importable
from glaurung.llm.evidence import annotate_functions_path, AnnotateBudgets


def test_annotate_functions_path_go_sample():
    # Use a known present sample (Go linux/amd64)
    sample = Path("samples/binaries/platforms/linux/amd64/export/go/hello-go")
    if not sample.exists():
        # Skip if samples not present in this environment
        return
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
    # Use a Windows x86_64 sample (cross-built) with simple imports (printf/puts)
    sample = Path(
        "samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe"
    )
    if not sample.exists():
        return
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
    # Validate ELF GOT mapping runs and ARM64 evidence captures functions
    arm_sample = Path(
        "samples/binaries/platforms/linux/amd64/cross/arm64/hello-arm64-gcc"
    )
    if not arm_sample.exists():
        return
    # GOT map should be callable and return a list (possibly empty)
    got = g.analysis.elf_got_map_path(str(arm_sample))
    assert isinstance(got, list)
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
    # RISC-V sample
    riscv = Path(
        "samples/binaries/platforms/linux/amd64/cross/riscv64/hello-riscv64-gcc"
    )
    if riscv.exists():
        ev = annotate_functions_path(str(riscv), AnnotateBudgets(max_functions=4))
        assert ev.functions
        # Expect some hints or strings for hello
        assert any(f.hints or f.strings for f in ev.functions)
    # ARMHF sample
    armhf = Path("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc")
    if armhf.exists():
        ev = annotate_functions_path(str(armhf), AnnotateBudgets(max_functions=4))
        assert ev.functions
        assert any(f.hints or f.strings for f in ev.functions)
