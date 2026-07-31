"""Round-trip coverage for address-taken stack objects.

These are real C++ binaries from the fixture corpus.  The O0 compiler output
passes frame-relative object addresses to constructors and destructors.  A
decompiler must materialise those addresses as C locals; rendering ``rbp - N``
reads an uninitialised C variable and makes execution depend on memory-layout
luck.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import fixture_harness as H  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_address_taken_cpp_stack_objects_round_trip(compiler: str) -> None:
    """Constructors and destructors must receive real local addresses."""
    observed = H.run_lanes(
        [
            (
                "10_cpp_runtime_shapes",
                compiler,
                "O0",
                ("cpp_ctor_dtor", "cpp_raii_guard"),
            )
        ],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed[f"10_cpp_runtime_shapes:{compiler}:O0"]
    assert lane == {
        "cpp_ctor_dtor": "pass",
        "cpp_raii_guard": "pass",
    }, lane

    binary = H.BUILD / f"10_cpp_runtime_shapes-{compiler}-O0.so"
    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["cpp_ctor_dtor"])
    assert code is not None
    storage = re.search(r"unsigned char local_20\[(\d+)\];", code)
    assert storage is not None, code
    assert int(storage.group(1)) >= 16, code


def test_indexed_stack_arrays_round_trip() -> None:
    """Indexed frame accesses must become real C stack objects, not raw rbp math."""
    observed = H.run_lanes(
        [("20_graph_bfs", "gcc", "O0", ("graph_bfs",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["20_graph_bfs:gcc:O0"]
    assert lane == {"graph_bfs": "pass"}, lane

    binary = H.BUILD / "20_graph_bfs-gcc-O0.so"
    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["graph_bfs"])
    assert code is not None
    assert "long rbp;" not in code, code
    assert "(rbp +" not in code, code
    assert len(re.findall(r"unsigned char local_[0-9a-f]+\[\d+\];", code)) >= 2, code


def test_moved_cpp_stack_object_keeps_readable_storage() -> None:
    """A moved-from object must still be read through its materialized bytes."""
    observed = H.run_lanes(
        [("10_cpp_runtime_shapes", "clang", "O0", ("cpp_move",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["10_cpp_runtime_shapes:clang:O0"]
    assert lane == {"cpp_move": "pass"}, lane


def test_simd_zeroed_indexed_stack_array_round_trip() -> None:
    """An optimized vector zero initializer must define every indexed byte."""
    observed = H.run_lanes(
        [("20_graph_bfs", "gcc", "O2", ("graph_bfs",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["20_graph_bfs:gcc:O2"]
    assert lane == {"graph_bfs": "pass"}, lane


def test_stack_array_base_copied_to_callee_saved_register_round_trip() -> None:
    """A late ``rbp = rsp`` array cursor must copy a real object address."""
    observed = H.run_lanes(
        [("21_graph_dfs", "gcc", "O2", ("graph_dfs",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["21_graph_dfs:gcc:O2"]
    assert lane == {"graph_dfs": "pass"}, lane


def test_omit_frame_pointer_callee_saves_do_not_become_source_state() -> None:
    """Balanced x86 save/restore slots must not leak ``rsp``/``rbp`` into C."""
    observed = H.run_lanes(
        [("23_topological_sort", "clang", "O2", ("topological_sort",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["23_topological_sort:clang:O2"]
    assert lane == {"topological_sort": "pass"}, lane

    binary = H.BUILD / "23_topological_sort-clang-O2.so"
    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["topological_sort"])
    assert code is not None
    assert "long rsp;" not in code, code
    assert "long rbp;" not in code, code
    assert "rsp =" not in code, code


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_dynamic_stack_buffer_passed_to_memcpy_round_trip(compiler: str) -> None:
    """A stack array slice passed to ``memcpy`` must retain object identity."""
    observed = H.run_lanes(
        [("24_merge_sort", compiler, "O2", ("merge_sort_i32",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed[f"24_merge_sort:{compiler}:O2"]
    assert lane == {"merge_sort_i32": "pass"}, lane
