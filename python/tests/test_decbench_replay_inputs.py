"""Check replay input preparation against compiler-produced ELF files."""

import importlib.util
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "decbench_inputs", ROOT / "tools" / "decbench_inputs.py"
)
assert SPEC is not None and SPEC.loader is not None
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)


def test_exact_binary_selection_rejects_prefix_collisions(
    tmp_path: pathlib.Path,
) -> None:
    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("clang is required for the real ELF fixture")
    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 0; }\n")
    wrong = tmp_path / "usart_irq.elf"
    subprocess.run([compiler, str(source), "-o", str(wrong)], check=True)
    assert INPUTS.find_binary(tmp_path, "usart") is None
    right = tmp_path / "usart.elf"
    shutil.copy2(wrong, right)
    assert INPUTS.find_binary(tmp_path, "usart") == right
    shutil.copy2(right, tmp_path / "usart.exe")
    with pytest.raises(RuntimeError, match="ambiguous"):
        INPUTS.find_binary(tmp_path, "usart")


@pytest.mark.parametrize("arm", [False, True])
def test_checked_strip_removes_debug_and_preserves_source(
    tmp_path: pathlib.Path, arm: bool
) -> None:
    compiler = shutil.which("clang")
    if compiler is None or shutil.which("llvm-strip") is None:
        pytest.skip("clang and llvm-strip are required")
    source = tmp_path / "entry.c"
    source.write_text("int entry(int value) { return value + 1; }\n")
    binary = tmp_path / "entry.elf"
    command = [compiler, "-g", "-nostdlib", "-fuse-ld=lld", "-Wl,-e,entry"]
    if arm:
        command.append("--target=armv7-none-eabi")
    subprocess.run([*command, str(source), "-o", str(binary)], check=True)
    original = binary.read_bytes()
    assert b".debug_info" in original
    stripped = tmp_path / "entry.stripped"
    receipt = INPUTS.strip_copy(binary, stripped)
    assert binary.read_bytes() == original
    sections = subprocess.run(
        ["readelf", "-SW", str(stripped)], capture_output=True, text=True, check=True
    ).stdout
    assert ".debug_info" not in sections and ".symtab" not in sections
    assert receipt["source_sha256"] != receipt["stripped_sha256"]
    assert INPUTS.normalise_address(binary, 0x10001) == (0x10000 if arm else 0x10001)


def test_checked_strip_preserves_pe_source_and_odd_addresses(
    tmp_path: pathlib.Path,
) -> None:
    # COFF validation reads the symbol table back with llvm-readobj.
    if shutil.which("llvm-readobj") is None:
        pytest.skip("llvm-readobj is required to validate a stripped PE")
    binary = ROOT / "tests" / "decbench_adapter" / "stdcall_symbols.dll"
    original = binary.read_bytes()
    stripped = tmp_path / "stdcall_symbols.dll"
    receipt = INPUTS.strip_copy(binary, stripped)
    assert binary.read_bytes() == original
    assert receipt["validation"] == "COFF: checked symbol count and debug sections"
    assert INPUTS.normalise_address(binary, 0x10001) == 0x10001
