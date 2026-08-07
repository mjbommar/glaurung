"""Real-binary coverage for CFG edges that survive region structuring."""

from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]


def _matching_brace(text: str, opening: int) -> int:
    """Return the closing brace paired with ``text[opening]``."""
    assert text[opening] == "{"
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unclosed brace at {opening}:\n{text}")


def test_switch_arms_reach_the_real_loop_latch(tmp_path: Path) -> None:
    """Every non-returning switch case must continue through the loop latch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "statemachine.c"
    binary = tmp_path / "statemachine-clang-O0.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["fsm"])
    assert code is not None
    assert "signed char local_1d;" in code, code
    assert "local_2c" not in code, code
    assert "local_4" not in code, code

    # The preferred recovery is a structured switch whose C `break`s flow to
    # one latch after the switch.  Requiring a particular number of gotos made
    # this regression test fail when the structurer improved.  Check the real
    # ownership invariant instead: all ordinary cases end inside the switch,
    # and the one counter increment is lexically after it but still in the loop.
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_line = code[code.rfind("\n", 0, switch_at) + 1 : switch_at]
    assert switch_line == "        ", (
        "the typed range proof should make the switch a direct loop-body statement",
        code,
    )
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2, 3):
        assert f"case {case}:" in switch_body, code
    assert switch_body.count("break;") >= 3, code

    # The terminating case is built with a borrowed view of the shared
    # epilogue. Its case-local setup still belongs to the switch; if ownership
    # is not committed, `build_full` appends that block after the function's
    # ordinary return as an unreachable assignment + goto. The final
    # substantive top-level statement must therefore remain the real return.
    function_open = code.find("{")
    function_close = _matching_brace(code, function_open)
    substantive = [
        line.strip()
        for line in code[function_open + 1 : function_close].splitlines()
        if line.strip() and not line.lstrip().startswith("//")
    ]
    assert substantive[-1].startswith("return "), code

    explicit_latch = re.search(
        r"(?m)^\s*([A-Za-z_]\w*)\s*=.*\(\1\s*\+\s*1\)",
        code[switch_close + 1 :],
    )
    for_latch = re.search(
        r"(?m)^\s*for\s*\([^;\n]*;[^;\n]*;\s*([A-Za-z_]\w*)\s*=.*"
        r"\(\1\s*\+\s*1\).*\)\s*\{",
        code[:switch_at],
    )
    for_increment = re.search(
        r"(?m)^\s*for\s*\([^;\n]*;[^;\n]*;\s*([A-Za-z_]\w*)\+\+\s*\)\s*\{",
        code[:switch_at],
    )
    assert (
        explicit_latch is not None or for_latch is not None or for_increment is not None
    ), code

    rebuilt = D.build_so(code, tmp_path, "dec_fsm", link_against=str(binary))
    assert rebuilt is not None, code

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "statemachine",
            "--function",
            "fsm",
            "--seed",
            "1234",
            "--fuzz",
            "24",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["fsm"]["status"] == "pass", results


def test_gcc_o0_state_dispatch_recovers_switch_and_round_trips(tmp_path: Path) -> None:
    """A label-based GCC dispatch ladder must become the source switch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "statemachine.c"
    binary = tmp_path / "statemachine-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["fsm"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2, 3):
        assert f"case {case}:" in switch_body, code

    assert D.build_so(code, tmp_path, "dec_fsm_gcc", link_against=str(binary))
    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "statemachine",
            "--function",
            "fsm",
            "--seed",
            "1234",
            "--fuzz",
            "24",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["fsm"]["status"] == "pass", results


def test_cross_block_table_base_recovers_clang_o2_switch(tmp_path: Path) -> None:
    """A table base materialized in the loop preheader must reach its dispatch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "statemachine.c"
    binary = tmp_path / "statemachine-clang-O2.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["fsm"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2, 3):
        assert f"case {case}:" in switch_body, code
    assert "unrecovered indirect jump" not in code, code
    assert "do {" in code, "the reducible state loop should remain structured"
    assert "while (1)" not in code, code
    assert "goto L_" not in code, code
    assert D.build_so(code, tmp_path, "dec_fsm_o2", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "statemachine",
            "--function",
            "fsm",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["fsm"]["status"] == "pass", results


def test_array_address_chain_folds_and_round_trips(tmp_path: Path) -> None:
    """Dead flag artifacts must not strand single-use array temporaries."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "arrays.c"
    binary = tmp_path / "arrays-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["sum_array"])
    assert code is not None
    assert "arg0[" in code and "local_4" in code, code
    assert "long var3;" not in code and "long var6;" not in code, code
    assert (
        D.build_so(code, tmp_path, "dec_sum_array", link_against=str(binary))
        is not None
    )

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "arrays",
            "--function",
            "sum_array",
            "--seed",
            "1234",
            "--fuzz",
            "24",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["sum_array"]["status"] == "pass", results


def test_clang_o2_vectorized_positive_sum_round_trips(tmp_path: Path) -> None:
    """SSE2 lane accumulation must survive into executable decompiled C."""
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / "13_loop_early_exit.c"
    binary = tmp_path / "13_loop_early_exit-clang-O2.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["sum_positive"])
    assert code is not None
    for mnemonic in ("pcmpgtd", "pand", "paddd", "pshufd", "movd"):
        assert f"asm: {mnemonic}" not in code, code

    rebuilt = D.build_so(
        code, tmp_path, "dec_sum_positive_clang_o2", link_against=str(binary)
    )
    assert rebuilt is not None, code
    original_lib = ctypes.CDLL(str(binary))
    rebuilt_lib = ctypes.CDLL(str(rebuilt))
    original = original_lib.sum_positive
    decompiled = rebuilt_lib.sum_positive
    for function in (original, decompiled):
        function.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        function.restype = ctypes.c_int
    values = (ctypes.c_int * 16)(
        3,
        6,
        -8,
        -5,
        -2,
        1,
        4,
        7,
        -7,
        -4,
        -1,
        2,
        5,
        8,
        -6,
        -3,
    )
    assert original(values, 10) == 21
    assert decompiled(values, 10) == original(values, 10)

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "13_loop_early_exit",
            "--function",
            "sum_positive",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["sum_positive"]["status"] == "pass", results


def test_clang_o2_vectorized_max_round_trips(tmp_path: Path) -> None:
    """PANDN/POR packed selects must preserve the winning signed lane value."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "arrays.c"
    binary = tmp_path / "arrays-clang-O2.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["max_array"])
    assert code is not None
    for mnemonic in ("pcmpgtd", "pand", "pandn", "por", "pshufd", "movd"):
        assert f"asm: {mnemonic}" not in code, code
    assert "? -1 : 0" not in code, (
        "packed compare masks are arithmetic 0/-1 values, not source-level branches",
        code,
    )

    rebuilt = D.build_so(
        code, tmp_path, "dec_max_array_clang_o2", link_against=str(binary)
    )
    assert rebuilt is not None, code
    original_lib = ctypes.CDLL(str(binary))
    rebuilt_lib = ctypes.CDLL(str(rebuilt))
    original = original_lib.max_array
    decompiled = rebuilt_lib.max_array
    for function in (original, decompiled):
        function.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        function.restype = ctypes.c_int

    vectors = [
        [-9, -8, -7, -6, -5, -4, -3, -2, -1],
        [5, 100, -30, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8],
        [-100, -42, -7, -9, -88, -1, -4, -6, -8, -3, -2, -11, -12, -13, -14, -15],
    ]
    for vector in vectors:
        values = (ctypes.c_int * len(vector))(*vector)
        expected = original(values, len(vector))
        assert expected == max(vector)
        assert decompiled(values, len(vector)) == expected, (vector, code)

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "arrays",
            "--function",
            "max_array",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["max_array"]["status"] == "pass", results


def test_clang_o2_vectorized_crc32_round_trips(tmp_path: Path) -> None:
    """Packed equality and read-only masks must remain executable C."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "checksum.c"
    binary = tmp_path / "checksum-clang-O2.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["crc32_step"])
    assert code is not None
    for mnemonic in ("pcmpeqd", "pand", "pshufd", "pxor", "movd"):
        assert f"asm: {mnemonic}" not in code, code
    assert "*(int *)(0x20" not in code, code
    assert D.build_so(code, tmp_path, "dec_crc32_clang_o2", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "checksum",
            "--function",
            "crc32_step",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["crc32_step"]["status"] == "pass", results


def test_clang_o0_variable_shift_counts_round_trip(tmp_path: Path) -> None:
    """Generated C must state x86's five-bit variable-count masking."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "arith.c"
    binary = tmp_path / "arith-clang-O0.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["shifts"])
    assert code is not None
    assert re.search(r"& (?:31|0x1f)", code), code
    assert D.build_so(code, tmp_path, "dec_shifts_clang_o0", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "arith",
            "--function",
            "shifts",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["shifts"]["status"] == "pass", results


def test_gcc_o2_packed_bubble_swap_round_trips(tmp_path: Path) -> None:
    """GCC's MOVQ/PSHUFD adjacent-i32 swap must preserve buffer effects."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "sort.c"
    binary = tmp_path / "sort-gcc-O2.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["bubble"])
    assert code is not None
    assert "asm: movq" not in code, code
    assert D.build_so(code, tmp_path, "dec_bubble_gcc_o2", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "sort",
            "--function",
            "bubble",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["bubble"]["status"] == "pass", results


@pytest.mark.parametrize("compiler", ["gcc", "clang"])  # ty: ignore[unresolved-attribute]
def test_o2_pointer_return_keeps_declared_dwarf_kind(
    tmp_path: Path, compiler: str
) -> None:
    """A named-struct pointer return must not be rendered as an integer."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "linkedlist.c"
    binary = tmp_path / f"linkedlist-{compiler}-O2.so"
    compiled = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["list_find"])
    sum_code = D.decompiled_c(str(binary), functions["list_sum"])
    assert code is not None
    assert sum_code is not None
    assert "typedef struct node" in code, code
    assert "struct node * next;" in code, code
    assert "int val;" in code, code
    assert re.search(r"node \* list_find\(node \* arg0, int arg1\)", code), code
    assert "->val" in code, code
    assert "->next" in code, code
    assert "+ 0x8" not in code, code
    # Clang shares its null-result setup between the entry guard and a loop
    # exit, then falls through to a separate `ret` block.  That two-block
    # epilogue is still a source-level `return NULL`, not a cross-region goto
    # into the other arm of an if/else.
    assert "goto " not in code, code
    assert not re.search(r"L_[0-9a-f]+:\s*;", code), code
    assert "return (node *)(0);" in code, code
    # Once the shared return is explicit, this is the canonical sentinel scan:
    # test the node pointer before dereferencing it, return on a matching field,
    # and advance otherwise.  Keeping the field comparison as the while guard
    # obscures both the null-termination condition and the early match return.
    assert re.search(r"while \(\(var\d+ != 0\)\)", code), code
    assert not re.search(r"\(long\)var\d+ != 0", code), code
    assert re.search(r"node \* var\d+;", code), code
    next_assignment = (
        r"(?:var\d+|ret) = "
        r"(?:var\d+|\(\(struct node \*\)var\d+\))->next;"
    )
    assert re.search(next_assignment, code), code
    # The cursor may stay split at a correctness-preserving phi boundary, but
    # every emitted cursor must retain the recovered node-pointer kind.
    assert sum_code.count("node * var") >= 1, sum_code
    assert re.search(next_assignment, sum_code), sum_code
    # The source loop is entry-guarded.  GCC and Clang rotate that guard into a
    # do/while latch, but the explicit pre-loop null return proves it is safe to
    # recover the source-level while without dereferencing a null node.
    assert "do {" not in sum_code, sum_code
    assert re.search(r"while \(\(var\d+ != 0\)\)", sum_code), sum_code
    assert not re.search(r"\(long\)var\d+ != 0", sum_code), sum_code
    # DecBench recompiles all functions from one binary as one translation
    # unit. Shared aggregate declarations therefore need an idempotent prelude,
    # not one unguarded definition per independently rendered function.
    rebuilt = D.build_so(
        f"{sum_code}\n{code}", tmp_path, f"dec_linkedlist_{compiler}_o2"
    )
    assert rebuilt is not None

    class Node(ctypes.Structure):
        pass

    node_pointer = ctypes.POINTER(Node)
    Node._fields_ = [("next", node_pointer), ("value", ctypes.c_int)]
    nodes = (Node * 4)()
    for index, value in enumerate((7, -3, 11, 5)):
        nodes[index].value = value
        nodes[index].next = (
            ctypes.pointer(nodes[index + 1]) if index < 3 else node_pointer()
        )
    head = ctypes.pointer(nodes[0])

    original = ctypes.CDLL(str(binary), mode=ctypes.RTLD_LOCAL)
    decompiled = ctypes.CDLL(str(rebuilt), mode=ctypes.RTLD_LOCAL)
    for library in (original, decompiled):
        library.list_find.argtypes = [node_pointer, ctypes.c_int]
        library.list_find.restype = ctypes.c_void_p
    for value in (7, -3, 11, 5, 99):
        assert original.list_find(head, value) == decompiled.list_find(head, value)


def test_clang_o0_linked_list_sum_round_trips_exact_instruction_bytes(
    tmp_path: Path,
) -> None:
    """Typed source expressions must not widen the original 32-bit loop body."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "linkedlist.c"
    original = tmp_path / "linkedlist-clang-O0.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(original),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(original))
    code = D.decompiled_c(str(original), functions["list_sum"])
    find_code = D.decompiled_c(str(original), functions["list_find"])
    assert code is not None
    assert find_code is not None
    assert "while ((arg0 != 0))" in code, code
    assert "(long)arg0" not in code, code
    assert "(unsigned long)((unsigned int)(arg0->val))" not in code, code
    assert "(unsigned long)((unsigned int)(arg0->val))" not in find_code, find_code
    assert "(unsigned long)((unsigned int)(arg1))" not in find_code, find_code

    recovered_source = tmp_path / "linkedlist-list_sum-recovered.c"
    recovered_source.write_text(code)
    recovered = tmp_path / "linkedlist-list_sum-recovered.so"
    rebuilt = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-w",
            "-o",
            str(recovered),
            str(recovered_source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rebuilt.returncode == 0, rebuilt.stderr

    def function_bytes(binary: Path, function: str) -> bytes:
        disassembly = subprocess.run(
            ["objdump", "-d", f"--disassemble={function}", str(binary)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        encoded = []
        for line in disassembly.splitlines():
            match = re.match(r"^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)", line)
            if match:
                encoded.extend(bytes.fromhex(match.group(1)))
        assert encoded, disassembly
        return bytes(encoded)

    assert function_bytes(recovered, "list_sum") == function_bytes(original, "list_sum")


def test_gcc_o0_comparison_tree_recovers_switch_and_round_trips(tmp_path: Path) -> None:
    """The reconstructed x86 signed-greater condition must remain switch-shaped."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "switch_jt.c"
    binary = tmp_path / "switch_jt-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dispatch"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in range(8):
        assert f"case {case}:" in switch_body, code
    assert "goto L_" not in code, code
    assert D.build_so(code, tmp_path, "dec_dispatch", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "switch_jt",
            "--function",
            "dispatch",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["dispatch"]["status"] == "pass", results


def test_clang_o0_range_default_recovers_direct_return_switch(
    tmp_path: Path,
) -> None:
    """Clang's range guard and result join must recover the source switch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "switch_jt.c"
    binary = tmp_path / "switch_jt-clang-O0.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dispatch"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in range(8):
        assert f"case {case}:" in switch_body, code
    assert "default:" in switch_body, code
    assert switch_body.count("return ") >= 9, code
    assert "break;" not in switch_body, code
    assert "if (" not in code[:switch_at], code
    assert D.build_so(code, tmp_path, "dec_dispatch_clang", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "switch_jt",
            "--function",
            "dispatch",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["dispatch"]["status"] == "pass", results


@pytest.mark.parametrize("compiler", ["gcc", "clang"])  # ty: ignore[unresolved-attribute]
def test_optimized_early_default_recovers_one_exhaustive_switch(
    tmp_path: Path, compiler: str
) -> None:
    """An optimized early default return must join the following switch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "switch_jt.c"
    binary = tmp_path / f"switch_jt-{compiler}-O2.so"
    compiled = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dispatch"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in range(8):
        assert f"case {case}:" in switch_body, code
    assert "default:" in switch_body, code
    assert switch_body.count("return ") >= 9, code
    assert "if (" not in code[:switch_at], code
    if compiler == "gcc":
        assert "long var0;" not in code, code
        assert "var0 =" not in code, code

    rebuilt = D.build_so(
        code,
        tmp_path,
        f"dec_dispatch_{compiler}_o2",
        link_against=str(binary),
    )
    assert rebuilt is not None, code

    # GCC can fragment the O2 DWARF signature beyond what the generic harness
    # currently reconstructs. Execute the known source prototype directly so
    # that missing debug metadata cannot turn this semantic check structural.
    original_lib = ctypes.CDLL(str(binary))
    rebuilt_lib = ctypes.CDLL(str(rebuilt))
    original_dispatch = original_lib.dispatch
    rebuilt_dispatch = rebuilt_lib.dispatch
    for function in [original_dispatch, rebuilt_dispatch]:
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
        function.restype = ctypes.c_int
    for op in range(-2, 10):
        for lhs, rhs in [(-9, -3), (-3, 9), (0, -1), (7, 5)]:
            assert rebuilt_dispatch(op, lhs, rhs) == original_dispatch(op, lhs, rhs)

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "switch_jt",
            "--function",
            "dispatch",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["dispatch"]["status"] in {"pass", "structural"}, results
