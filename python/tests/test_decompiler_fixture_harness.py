"""The decompiler fixture harness must be FAIL-CLOSED and trustworthy.

These tests exercise the harness itself, not the decompiler: every failure mode
(missing dependency, compile failure, worker crash, timeout, decompile failure,
zero DWARF signatures, zero cases, a required function missing) must produce a
FAILURE, never a silent skip or a green 0/0 run. A harness that fails open is
worse than no harness — it hides regressions.
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import tempfile
from itertools import pairwise
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS = ROOT / "tools"
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import diff_decompile as D
import fixture_harness as H
import fixture_toolchain as TC
import manifest as M
import structural as S

# Portable scratch dir: whatever manifest.tmpdir() resolves (env-driven, with a
# system-tempfile fallback) — never a hardcoded machine path.
_td = D.M.tmpdir()
WORKDIR_KW = {"dir": _td} if _td else {}

_SO_KEEP = []  # keep NamedTemporaryFile handles alive for the test session


def _compile_so(
    c_src: str, tag: str, debug: bool = True, optimization: str = "O0"
) -> str:
    """Compile a snippet into a .so and return its path (kept for the run).

    Uses the pinned toolchain, like every other compile the gate performs — these
    reference binaries are compared against decompilations rebuilt by that same
    compiler, and the host is not assumed to ship a C compiler at all.
    """
    import os
    fd, path = tempfile.mkstemp(suffix=".so", prefix=f"h_{tag}_", **WORKDIR_KW)
    os.close(fd)
    src = path[:-3] + ".c"
    Path(src).write_text(c_src + "\n")
    argv = [
        "gcc",
        "-shared",
        "-fPIC",
        *(["-g"] if debug else []),
        f"-{optimization}",
        "-o",
        path,
        src,
    ]
    r = TC.run(argv)
    assert r.returncode == 0, r.stderr
    _SO_KEEP.append(path)
    return path


def _compile_cpp_so(
    cpp_src: str,
    tag: str,
    debug: bool = True,
    optimization: str = "O0",
    compiler: str = "g++",
) -> str:
    """Compile a C++ snippet with the same pinned toolchain as the corpus."""
    import os

    fd, path = tempfile.mkstemp(suffix=".so", prefix=f"h_{tag}_", **WORKDIR_KW)
    os.close(fd)
    src = path[:-3] + ".cpp"
    Path(src).write_text(cpp_src + "\n")
    argv = [
        compiler,
        "-shared",
        "-fPIC",
        *(["-g"] if debug else []),
        f"-{optimization}",
        "-o",
        path,
        src,
    ]
    result = TC.run(argv)
    assert result.returncode == 0, result.stderr
    _SO_KEEP.append(path)
    return path


def test_pyelftools_is_a_declared_dependency():
    # Fail-closed relies on the import at module load — verify it is a real dep,
    # not an undeclared global that silently disappears.
    import elftools  # noqa: F401


def test_every_declared_fixture_source_is_discovered():
    """The corpus size comes from the manifest, not a literal.

    A hardcoded count catches a source that silently disappeared, but it also
    fails whenever one is legitimately ADDED — which trains people to edit the
    guard instead of reading it, and is exactly how this test went red after
    `11_call_shapes` and `12_loop_rotation` landed. Comparing against
    REQUIRED_FUNCTIONS catches strictly more: a vanished source, a renamed one,
    and one added without being declared.
    """
    on_disk = {p.stem for p in SRC.glob("*.c")} | {p.stem for p in SRC.glob("*.cpp")}
    declared = set(M.REQUIRED_FUNCTIONS)
    assert on_disk == declared, (
        f"only on disk {sorted(on_disk - declared)}, "
        f"only declared {sorted(declared - on_disk)}"
    )


def test_zero_dwarf_signatures_is_an_error(tmp_path):
    # A stripped / DWARF-less binary must ERROR, never report a green empty run.
    so = _compile_so("int f(int a){return a;}", "nodwarf", debug=False)  # no -g
    results = D.run(so, "unused.c", "nope", seed=1, fuzz=1)
    assert "__error__" in results


def test_gcc_o2_signatures_follow_concrete_abstract_origins() -> None:
    """Optimized GCC keeps code ranges and source prototypes on separate DIEs."""
    binary = _compile_so(
        "long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }\n"
        "long ackermann(long m, long n) {\n"
        "  if (m == 0) return n + 1;\n"
        "  if (n == 0) return ackermann(m - 1, 1);\n"
        "  return ackermann(m - 1, ackermann(m, n - 1));\n"
        "}",
        "gcc_o2_abstract_origin",
        optimization="O2",
    )

    recovered = {signature["name"]: signature for signature in D.signatures(binary)}

    assert recovered["fib"]["params"] == [{"k": "int", "w": 4, "s": True}]
    assert recovered["fib"]["ret"] == {"k": "int", "w": 8, "s": True}
    assert recovered["ackermann"]["params"] == [
        {"k": "int", "w": 8, "s": True},
        {"k": "int", "w": 8, "s": True},
    ]


def test_batch_decompile_returns_every_requested_real_function():
    """One native analysis must produce every requested fixture function.

    This is a real compiled shared object, not a stubbed API response: the fast
    harness path must cross ELF discovery, CFG recovery, lifting, and DecBench C
    rendering before it is allowed to replace one CLI process per function.
    """
    so = _compile_so(
        "__attribute__((noinline)) int batch_add(int a){return a+3;}\n"
        "__attribute__((noinline)) int batch_mul(int a){return a*5;}",
        "batch_decompile",
    )
    exported = D.exported_functions(so)
    requested = [exported["batch_add"], exported["batch_mul"]]

    recovered = D.decompiled_many_c(so, requested)

    assert set(recovered) == set(requested)
    assert "batch_add(" in recovered[exported["batch_add"]]
    assert "batch_mul(" in recovered[exported["batch_mul"]]


def test_round_trip_includes_a_referenced_local_static_callee() -> None:
    """A correct caller must not fail merely because its callee is local.

    Linking the standalone decompiled caller against the original shared object
    supplies exported siblings, but ELF local symbols are not visible to the
    dynamic linker. The harness must include Glaurung's decompilation of that
    exact local callee so the differential reaches behavior instead of crashing
    at ``dlopen`` with ``undefined symbol``.
    """
    binary = _compile_so(
        "static __attribute__((noinline)) int local_step(int x) {\n"
        "    return (x * 5 + 1) & 7;\n"
        "}\n"
        "int calls_local_step(int x) {\n"
        "    int total = 0;\n"
        "    for (int i = 0; i < 8; i++) { x = local_step(x); total += x; }\n"
        "    return total;\n"
        "}",
        "local_static_callee",
    )
    signature = next(
        sig for sig in D.signatures(binary) if sig["name"] == "calls_local_step"
    )
    caller = D.decompiled_c(binary, signature["va"])
    assert caller is not None
    assert "local_step(" in caller

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        result = D.run_function(
            signature,
            "fx",
            binary,
            Path(td),
            seed=1234,
            fuzz=24,
        )
    assert result["status"] == "pass", result


def test_round_trip_resolves_a_sanitized_clang_lambda_symbol() -> None:
    """Clang's local lambda symbol contains ``$``, which C cannot spell.

    The decompiler sanitizes that byte at the call site. Local-callee closure
    must resolve the sanitized identifier back to the unique raw ELF symbol,
    include its body under the called name, and reach an exact behavioral diff.
    """
    binary = _compile_cpp_so(
        'extern "C" int calls_local_clang_lambda(int x) {\n'
        "    auto add_x = [x](int y) { return x + y; };\n"
        "    return add_x(37);\n"
        "}",
        "local_clang_lambda",
        compiler="clang++",
    )
    local_symbols = D.defined_functions(binary)
    assert any("$" in symbol for symbol in local_symbols)
    signature = next(
        sig for sig in D.signatures(binary) if sig["name"] == "calls_local_clang_lambda"
    )
    caller = D.decompiled_c(binary, signature["va"])
    assert caller is not None
    called = D._EXTERN_FUNCTION_DECL.search(caller)
    assert called is not None
    assert "$" not in called.group("name")

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        result = D.run_function(
            signature,
            "fx",
            binary,
            Path(td),
            seed=1234,
            fuzz=24,
        )
    assert result["status"] == "pass", result


def test_recompiled_cpp_throwing_callee_loads_its_runtime(tmp_path: Path) -> None:
    """Included local C++ callees retain source exception semantics and runtime.

    This exercises the real C++ compiler, ELF typeinfo relocation, decompiler,
    local-callee closure, source-level ``throw``, C++ rebuild, and dynamic loader.
    """
    binary = _compile_cpp_so(
        "static __attribute__((noinline)) int may_throw(int x) {\n"
        "    if (x < 0) throw -x;\n"
        "    return x + 5;\n"
        "}\n"
        'extern "C" int calls_throwing_helper(int x) { return may_throw(x); }',
        "cpp_abi_runtime",
    )
    signature = next(
        sig for sig in D.signatures(binary) if sig["name"] == "calls_throwing_helper"
    )
    caller = D.decompiled_c(binary, signature["va"])
    assert caller is not None
    closed = D.include_referenced_local_callees(binary, caller)
    assert "throw (int)" in closed
    assert "__cxa_throw" not in closed

    rebuilt = D.build_so(
        closed,
        tmp_path,
        "cpp_abi_runtime",
        link_against=binary,
    )

    assert rebuilt is not None
    ctypes.CDLL(str(rebuilt))


def test_recompiled_typed_try_catch_uses_cpp_and_preserves_c_abi(
    tmp_path: Path,
) -> None:
    """Recovered C++ syntax must execute through the ordinary round-trip gate."""
    rebuilt = D.build_so(
        "int recovered_try(int x) {\n"
        "    try { if (x < 0) throw -x; return x + 7; }\n"
        "    catch (int e) { return 90 - e; }\n"
        "}",
        tmp_path,
        "typed_try_catch",
    )

    assert rebuilt is not None
    library = ctypes.CDLL(str(rebuilt))
    function = library.recovered_try
    function.argtypes = [ctypes.c_int]
    function.restype = ctypes.c_int
    assert function(5) == 12
    assert function(-8) == 82


def test_cfg_owns_lsda_only_cpp_landing_pad_blocks() -> None:
    """A C++ catch handler is function code even without a normal branch to it."""
    binary = _compile_cpp_so(
        "static __attribute__((noinline)) int may_throw(int x) {\n"
        "    if (x < 0) throw -x;\n"
        "    return x + 5;\n"
        "}\n"
        'extern "C" int catches_int(int x) {\n'
        "    try { return may_throw(x) + 30; }\n"
        "    catch (int e) { return 90 - e; }\n"
        "}",
        "cpp_landing_pad_cfg",
    )

    functions, _callgraph = D.g.analysis.analyze_functions_path(binary)
    function = next(fn for fn in functions if fn.name == "catches_int")
    owned_end = max(
        chunk.start.value + chunk.size for chunk in function.all_ranges()
    )
    recovered_end = max(block.end_address.value for block in function.basic_blocks)
    ordered_blocks = sorted(
        function.basic_blocks, key=lambda block: block.start_address.value
    )

    assert function.has_flag(0x4), "LSDA-owned handlers must set HAS_EH"
    assert recovered_end == owned_end, "the handler tail must not be omitted from the CFG"
    assert all(
        left.end_address.value <= right.start_address.value
        for left, right in pairwise(ordered_blocks)
    ), "landing-pad discovery must not create overlapping basic blocks"


def test_round_trip_rebinds_a_demangled_local_cpp_callee() -> None:
    """The included definition must retain the caller's exact C identifier.

    Glaurung renders a local C++ helper definition with its readable demangled
    name, while the wrapper's direct call retains the unique mangled ELF symbol.
    Merely prepending the helper therefore leaves the called symbol undefined.
    The harness must rebind that exact helper definition before recompilation so
    this real source-to-binary-to-C-to-binary comparison reaches behavior.
    """
    binary = _compile_cpp_so(
        "static __attribute__((noinline)) int local_cpp_step(int x) {\n"
        "    return (x * 9) - 17;\n"
        "}\n"
        'extern "C" int calls_local_cpp_step(int x) {\n'
        "    return local_cpp_step(x) + 23;\n"
        "}",
        "local_cpp_callee",
    )
    signature = next(
        sig for sig in D.signatures(binary) if sig["name"] == "calls_local_cpp_step"
    )
    caller = D.decompiled_c(binary, signature["va"])
    assert caller is not None
    assert "_ZL14local_cpp_stepi(" in caller

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        result = D.run_function(
            signature,
            "fx",
            binary,
            Path(td),
            seed=1234,
            fuzz=24,
        )
    assert result["status"] == "pass", result


def test_real_optimized_shared_store_and_return_keeps_declared_output_contract():
    """Debug contracts disambiguate optimized store-only and returned values.

    At ``-O2`` both functions can leave the computed value in the ABI return
    register while storing it through ``out``.  Machine-code liveness therefore
    cannot soundly distinguish them.  A real DWARF function prototype can: the
    first result is ``int`` and the second is truly ``void``.  The decompiler
    must preserve that authoritative distinction and emit recompilable C.
    """
    binary = _compile_so(
        "__attribute__((noinline)) int store_and_return(int *out, int value) {\n"
        "    int result = value + 700;\n"
        "    *out = result;\n"
        "    return result;\n"
        "}\n"
        "__attribute__((noinline)) void store_only(int *out, int value) {\n"
        "    *out = value + 700;\n"
        "}",
        "shared_store_return",
        optimization="O2",
    )
    exported = D.exported_functions(binary)
    recovered_by_va = D.decompiled_many_c(
        binary, [exported["store_and_return"], exported["store_only"]]
    )
    recovered = {
        function: recovered_by_va[exported[function]]
        for function in ("store_and_return", "store_only")
    }

    assert recovered["store_and_return"] is not None
    assert recovered["store_only"] is not None
    assert recovered["store_and_return"].startswith("int store_and_return(")
    assert recovered["store_only"].startswith("void store_only(")

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "shared_store_return.c"
        output_path = Path(td) / "shared_store_return.so"
        source_path.write_text(
            D.PRELUDE
            + "\n"
            + recovered["store_and_return"]
            + "\n"
            + recovered["store_only"]
            + "\n"
        )
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-std=gnu11",
                "-Werror",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, (
        f"{rebuilt.stderr}\n{recovered['store_and_return']}\n{recovered['store_only']}"
    )


def test_real_indirect_call_output_has_a_concrete_call_site_prototype():
    """An unknown call target still needs a concrete call-site prototype.

    GCC 15 defaults to C23, where ``f()`` means zero parameters rather than an
    unspecified parameter list.  The pinned GCC 11 lane diagnoses the same
    semantic defect under ``-Wstrict-prototypes``.  This crosses the real
    pipeline from the existing function-pointer fixture through native
    decompilation and back through the compiler; a text-only assertion would
    not prove that the emitted declarator is accepted as a real prototype.
    """
    source = (SRC / "08_indirect_dispatch.c").read_text()
    binary = _compile_so(source, "indirect_call_c23")
    apply_va = D.exported_functions(binary)["apply"]
    decompiled = D.decompiled_c(binary, apply_va)
    assert decompiled is not None

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "indirect_call.c"
        output_path = Path(td) / "indirect_call.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Wstrict-prototypes",
                "-Werror",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_noreturn_import_terminates_the_recovered_function():
    """A known non-returning call must not fall through into its neighbour.

    Optimized ELF functions commonly end in ``exit`` without a machine ``ret``.
    If CFG discovery treats every call as returning, its linear sweep crosses
    alignment and decodes the next function as part of the caller.  That is not
    merely cosmetic: the neighbour's register writes then poison call-site and
    return-type recovery.  Compile and strip a real shared object so only the
    dynamic imports/exports remain, reproducing the blinded DecBench boundary.
    """
    source = (
        "#include <stdlib.h>\n"
        "__attribute__((noinline)) unsigned long fail_then_exit(int fail) {\n"
        "    if (!fail) return 0x1234567887654321ul;\n"
        "    exit(7);\n"
        "}\n"
        "__attribute__((noinline)) int adjacent_after_exit(int value) {\n"
        "    return value + 17;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "noreturn_boundary.c"
        binary_path = Path(td) / "noreturn_boundary.so"
        source_path.write_text(source)
        built = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-fno-reorder-functions",
                "-fno-toplevel-reorder",
                "-falign-functions=16",
                "-o",
                str(binary_path),
                str(source_path),
            ]
        )
        assert built.returncode == 0, built.stderr
        stripped = TC.run(["strip", "--strip-all", str(binary_path)])
        assert stripped.returncode == 0, stripped.stderr

        functions = D.exported_functions(str(binary_path))
        assert functions["fail_then_exit"] < functions["adjacent_after_exit"]
        decompiled = D.decompiled_c(str(binary_path), functions["fail_then_exit"])

    assert decompiled is not None
    assert "exit(" in decompiled, decompiled
    assert "__attribute__((noreturn))" in decompiled, (
        "standalone C must preserve the same noreturn contract used by CFG discovery:\n"
        f"{decompiled}"
    )
    assert "+ 17" not in decompiled, (
        "CFG discovery crossed a known noreturn import into the adjacent function:\n"
        f"{decompiled}"
    )


def test_real_stripped_elf_tail_wrapper_does_not_absorb_its_local_callee():
    """A sibling call must preserve the stripped ELF function boundary.

    GCC lowers the wrapper's returned call to an unconditional direct jump.  The
    target is local and therefore has no surviving symbol after ``strip --all``,
    but CET's landing pad plus the target prologue are strong machine-level entry
    evidence.  Treating the jump as an ordinary CFG edge imports the complete
    worker into this 25-byte wrapper -- exactly the blinded DecBench libedit
    failure -- rather than recovering a small anonymous tail call.
    """
    source = (
        "#include <stdio.h>\n"
        "struct tail_state { unsigned long values[32]; unsigned long patlen; };\n"
        "static __attribute__((noinline)) long tail_worker(\n"
        "    struct tail_state *state, int command);\n"
        "__attribute__((noinline, visibility(\"default\")))\n"
        "long reset_then_tail(struct tail_state *state) {\n"
        "    state->patlen = 0;\n"
        "    return tail_worker(state, 24);\n"
        "}\n"
        "static __attribute__((noinline)) long tail_worker(\n"
        "    struct tail_state *state, int command) {\n"
        "    char text[128];\n"
        "    int count = snprintf(text, sizeof(text), \"%lu:%d\",\n"
        "                         state->values[0], command);\n"
        "    for (int i = 1; i < 32; ++i)\n"
        "        state->values[i] += (unsigned char)text[i & 7] + command;\n"
        "    return count + (long)state->values[31];\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "elf_tail_boundary.c"
        binary_path = Path(td) / "elf_tail_boundary.so"
        source_path.write_text(source)
        built = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-fcf-protection=branch",
                "-fno-reorder-functions",
                "-fno-toplevel-reorder",
                "-falign-functions=16",
                "-o",
                str(binary_path),
                str(source_path),
            ]
        )
        assert built.returncode == 0, built.stderr
        stripped = TC.run(["strip", "--strip-all", str(binary_path)])
        assert stripped.returncode == 0, stripped.stderr

        functions = D.exported_functions(str(binary_path))
        wrapper_va = functions["reset_then_tail"]
        assert "tail_worker" not in functions
        decompiled = D.decompiled_c(str(binary_path), wrapper_va)
        assert decompiled is not None

        assert "snprintf" not in decompiled, (
            "the anonymous worker body was absorbed into the tail wrapper:\n"
            f"{decompiled}"
        )
        assert "sub_" in decompiled, (
            "the preserved anonymous tail target was not rendered as a call:\n"
            f"{decompiled}"
        )
        assert "24" in decompiled, (
            "the sibling-call command argument was lost before tail recovery:\n"
            f"{decompiled}"
        )

        rebuilt_path = Path(td) / "elf_tail_boundary_rebuilt.so"
        recovered_path = Path(td) / "elf_tail_boundary_recovered.c"
        recovered_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-std=gnu11",
                "-Werror",
                "-o",
                str(rebuilt_path),
                str(recovered_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_noreturn_guard_preserves_machine_fallthrough_order():
    """A terminal guard must not make the hot fallthrough become its body.

    At ``-O0`` GCC lays this function out as a conditional branch over the
    lexical fallthrough containing ``exit``.  Both successors terminate, so a
    structurer that chooses its one-arm ``if`` from successor-vector order can
    invert the presentation into ``if (success) { strncpy; return; } exit;``.
    Compile and strip the real shared object, then require the emitted C to keep
    the terminal guard before the normal fallthrough and round-trip through GCC.
    """
    source = (
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "__attribute__((noinline)) void copy_bounded(char *dst, const char *src) {\n"
        "    unsigned long size = strlen(src);\n"
        "    if (size > 1024) exit(7);\n"
        "    strncpy(dst, src, 1024);\n"
        "    dst[1024] = 0;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "noreturn_fallthrough.c"
        binary_path = Path(td) / "noreturn_fallthrough.so"
        source_path.write_text(source)
        built = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-fno-reorder-functions",
                "-fno-toplevel-reorder",
                "-o",
                str(binary_path),
                str(source_path),
            ]
        )
        assert built.returncode == 0, built.stderr
        stripped = TC.run(["strip", "--strip-all", str(binary_path)])
        assert stripped.returncode == 0, stripped.stderr

        function_va = D.exported_functions(str(binary_path))["copy_bounded"]
        decompiled = D.decompiled_c(str(binary_path), function_va)
        assert decompiled is not None

        definition = decompiled.rfind("copy_bounded(")
        body_start = decompiled.find("{", definition)
        body = decompiled[body_start:]
        # Use the final occurrence so the standalone extern declarations do
        # not masquerade as the actual call-site order under test.
        guard = body.find("if (")
        exit_call = body.rfind("exit(")
        guard_close = body.find("}", exit_call)
        copy_call = body.rfind("strncpy(")
        assert min(guard, exit_call, guard_close, copy_call) >= 0, decompiled
        assert guard < exit_call < guard_close < copy_call, (
            "the terminal machine fallthrough became the trailing path:\n"
            f"{decompiled}"
        )

        rebuilt_path = Path(td) / "noreturn_fallthrough_rebuilt.so"
        recovered_path = Path(td) / "noreturn_fallthrough_recovered.c"
        recovered_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Werror",
                "-o",
                str(rebuilt_path),
                str(recovered_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_guarded_call_result_survives_a_noreturn_alternative():
    """A call value returned on the only returning path is a real output trial.

    A zero check is an additional use of the call result, but it does not make
    that result incidental when the zero arm terminates in ``exit`` and the
    other arm reaches the machine return unchanged.  Strip the local callee name
    to exercise the same unknown-call contract as the blinded `xquote` sample.
    """
    source = (
        "#include <stdlib.h>\n"
        "__attribute__((noinline)) static unsigned long local_factory(int fail) {\n"
        "    return fail ? 0ul : 0x1234567887654321ul;\n"
        "}\n"
        "__attribute__((noinline)) unsigned long guarded_call_result(int fail) {\n"
        "    unsigned long value = local_factory(fail);\n"
        "    if (value != 0) return value;\n"
        "    exit(7);\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "guarded_call_result.c"
        binary_path = Path(td) / "guarded_call_result.so"
        source_path.write_text(source)
        built = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-fno-reorder-functions",
                "-fno-toplevel-reorder",
                "-falign-functions=16",
                "-o",
                str(binary_path),
                str(source_path),
            ]
        )
        assert built.returncode == 0, built.stderr
        stripped = TC.run(["strip", "--strip-all", str(binary_path)])
        assert stripped.returncode == 0, stripped.stderr

        function_va = D.exported_functions(str(binary_path))["guarded_call_result"]
        decompiled = D.decompiled_c(str(binary_path), function_va)

    assert decompiled is not None
    assert not decompiled.startswith("void guarded_call_result("), decompiled
    assert "return ret;" in decompiled, decompiled


def test_real_named_call_output_declares_its_recovered_callee_prototype():
    """A resolved project-local call must not depend on implicit C declarations.

    Glaurung already recovers the callee name and the call-site argument values,
    but emitting only ``project_transform(arg0)`` leaves an invalid C23
    translation unit when the caller is decompiled on its own.  Exercise the
    real ELF symbol-resolution and AST pipeline, then make the compiler enforce
    that the recovered named call carries a concrete declaration.
    """
    binary = _compile_so(
        "__attribute__((noinline)) long project_transform(long value) {\n"
        "    return value * 3 + 1;\n"
        "}\n"
        "__attribute__((noinline)) long call_project_transform(long value) {\n"
        "    return project_transform(value) + 7;\n"
        "}",
        "named_call_prototype",
    )
    caller_va = D.exported_functions(binary)["call_project_transform"]
    decompiled = D.decompiled_c(binary, caller_va)
    assert decompiled is not None
    assert "project_transform(" in decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "named_call_prototype.c"
        output_path = Path(td) / "named_call_prototype.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Werror=implicit-function-declaration",
                "-Wstrict-prototypes",
                "-Werror=strict-prototypes",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_known_memcpy_output_declares_a_self_contained_library_prototype():
    """An authoritative library contract must survive into standalone C.

    The call-contract pass already uses ``memcpy``'s real arity and result type,
    but the renderer used to suppress its declaration and still cast the length
    through the header-only spelling ``size_t``.  Compile a real imported call,
    decompile it without source headers, and require the emitted unit itself to
    carry every type and declaration needed by strict C11 recompilation.
    """
    binary = _compile_so(
        "#include <string.h>\n"
        "__attribute__((noinline)) void *copy_known_bytes(\n"
        "    void *dst, const void *src, unsigned long count) {\n"
        "    return memcpy(dst, src, count);\n"
        "}",
        "known_memcpy_prototype",
    )
    function_va = D.exported_functions(binary)["copy_known_bytes"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert "memcpy(" in decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "known_memcpy_prototype.c"
        output_path = Path(td) / "known_memcpy_prototype.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Werror=implicit-function-declaration",
                "-Werror=int-conversion",
                "-Wstrict-prototypes",
                "-Werror=strict-prototypes",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_pointer_literal_to_machine_word_is_an_explicit_conversion():
    """Pointer-shaped constants need an explicit machine-word boundary.

    Optimized binaries routinely materialize a string address in a register
    whose surrounding value contract remains an integer machine word.  The C
    renderer must preserve both facts: keep the recovered string literal, but
    state the pointer-to-word conversion instead of relying on an invalid
    implicit assignment.  This is a real ELF round trip and the strict compile
    matches the diagnostic that blocked blinded DecBench functions.
    """
    binary = _compile_so(
        '__attribute__((noinline)) long literal_address_word(void) {\n'
        '    return (long)"glaurung-pointer-word";\n'
        "}",
        "pointer_literal_word",
        optimization="O2",
    )
    function_va = D.exported_functions(binary)["literal_address_word"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert '"glaurung-pointer-word"' in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "pointer_literal_word.c"
        output_path = Path(td) / "pointer_literal_word.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-std=gnu11",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_stack_object_initialization_remains_a_memory_store():
    """Address-taken stack arrays must not become assignable C pointers.

    Stack-object recovery declares complete byte arrays.  A later store through
    that object's address must therefore remain a memory store; spelling it as
    ``stack_N = value`` asks C to assign to an array and DecBench's fixup can
    only make that compile by degrading the array into a pointer.  Cross a real
    ELF call boundary so the object is genuinely address-taken.
    """
    binary = _compile_so(
        "struct pair { int first; int second; };\n"
        "extern void consume_pair(struct pair *);\n"
        "__attribute__((noinline)) int build_stack_pair(int value) {\n"
        "    struct pair local;\n"
        "    local.first = 5;\n"
        "    local.second = value;\n"
        "    consume_pair(&local);\n"
        "    return local.first;\n"
        "}",
        "stack_object_store",
    )
    function_va = D.exported_functions(binary)["build_stack_pair"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert "unsigned char local_" in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "stack_object_store.c"
        output_path = Path(td) / "stack_object_store.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_stack_pointer_arithmetic_store_has_an_integer_boundary():
    """Pointer arithmetic stored through an integer slot needs a value cast."""
    binary = _compile_so(
        "extern void consume_bytes(void *);\n"
        "__attribute__((noinline)) void store_advanced_stack_address(void) {\n"
        "    unsigned char local[4];\n"
        "    consume_bytes(local);\n"
        "    *(int *)local = (int)(long)(local + 1);\n"
        "    consume_bytes(local);\n"
        "}",
        "stack_pointer_arithmetic_store",
    )
    function_va = D.exported_functions(binary)["store_advanced_stack_address"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert "unsigned char local_" in decompiled, decompiled
    assert " + 1" in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "stack_pointer_arithmetic_store.c"
        output_path = Path(td) / "stack_pointer_arithmetic_store.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu2x",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_pointer_parameter_arithmetic_has_a_pointer_boundary():
    """Reassigning a pointer parameter must cast integer address arithmetic back."""
    binary = _compile_so(
        "__attribute__((noinline)) char advance_pointer(char *cursor, long amount) {\n"
        "    cursor += amount;\n"
        "    return *cursor;\n"
        "}",
        "pointer_parameter_arithmetic",
    )
    function_va = D.exported_functions(binary)["advance_pointer"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert "advance_pointer(char * arg0" in decompiled, decompiled
    assert "arg0 = (char *)" in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "pointer_parameter_arithmetic.c"
        output_path = Path(td) / "pointer_parameter_arithmetic.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu2x",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_pointer_literal_store_uses_the_memory_value_width():
    """A pointer literal stored into a machine word needs a value cast."""
    binary = _compile_so(
        "long stored_pointer_word;\n"
        "__attribute__((noinline)) void store_pointer_word(void) {\n"
        '    stored_pointer_word = (long)"glaurung-store-word";\n'
        "}",
        "pointer_literal_store",
        optimization="O2",
    )
    function_va = D.exported_functions(binary)["store_pointer_word"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert '"glaurung-store-word"' in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "pointer_literal_store.c"
        output_path = Path(td) / "pointer_literal_store.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-std=gnu11",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_pointer_word_select_converts_each_conditional_arm():
    """An outer cast cannot repair incompatible C conditional operands."""
    binary = _compile_so(
        "__attribute__((noinline)) long select_pointer_word(int choose, long fallback) {\n"
        '    return choose ? (long)"glaurung-select-word" : fallback;\n'
        "}",
        "pointer_word_select",
        optimization="O2",
    )
    function_va = D.exported_functions(binary)["select_pointer_word"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert '"glaurung-select-word"' in decompiled, decompiled
    assert " ? " in decompiled, decompiled
    assert (
        '(long)("glaurung-select-word")' in decompiled
        or '(long int)("glaurung-select-word")' in decompiled
    ), decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "pointer_word_select.c"
        output_path = Path(td) / "pointer_word_select.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-std=gnu2x",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_pointer_word_select_call_converts_each_conditional_arm():
    """Call-parameter casts cannot repair incompatible conditional operands."""
    binary = _compile_so(
        "#include <stdlib.h>\n"
        "__attribute__((noinline)) void free_selected_word(int choose, long fallback) {\n"
        '    free((void *)(choose ? (long)"glaurung-call-select" : fallback));\n'
        "}",
        "pointer_word_select_call",
        optimization="O2",
    )
    function_va = D.exported_functions(binary)["free_selected_word"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert '"glaurung-call-select"' in decompiled, decompiled
    assert " ? " in decompiled, decompiled
    assert '(void *)("glaurung-call-select")' in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "pointer_word_select_call.c"
        output_path = Path(td) / "pointer_word_select_call.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O2",
                "-std=gnu2x",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_mixed_arity_known_calls_keep_callee_and_callsite_prototypes():
    """A callee declaration and one incomplete machine call are distinct facts.

    The first ``free`` call has an explicit SysV argument-register definition;
    the second is a real direct machine call with no reaching ``rdi`` setup. A
    function-wide prototype cannot describe both. The standalone C must retain
    ``free``'s authoritative declaration and put the recovered zero-argument
    signature on only the incomplete call site, as a function-pointer cast.

    The assembly is compiled into a real ELF and is deliberately never run: its
    purpose is to preserve the malformed call boundary found in blinded binaries
    without asking the C compiler to repair it before decompilation.
    """
    binary = _compile_so(
        "#include <stdlib.h>\n"
        "__asm__(\n"
        '    \".text\\n\"\n'
        '    \".globl mixed_free_calls\\n\"\n'
        '    \".type mixed_free_calls,@function\\n\"\n'
        '    \"mixed_free_calls:\\n\"\n'
        '    \"push %rbp\\n\"\n'
        '    \"mov %rsp,%rbp\\n\"\n'
        '    \"sub $16,%rsp\\n\"\n'
        '    \"mov %rdi,-8(%rbp)\\n\"\n'
        '    \"mov -8(%rbp),%rdi\\n\"\n'
        '    \"call free@PLT\\n\"\n'
        '    \"call free@PLT\\n\"\n'
        '    \"leave\\n\"\n'
        '    \"ret\\n\"\n'
        '    \".size mixed_free_calls,.-mixed_free_calls\\n\"\n'
        ");",
        "mixed_arity_free",
    )
    function_va = D.exported_functions(binary)["mixed_free_calls"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert "extern void free(void *);" in decompiled, decompiled
    assert "((void (*)(void))free)();" in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "mixed_arity_free.c"
        output_path = Path(td) / "mixed_arity_free.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Werror=implicit-function-declaration",
                "-Wstrict-prototypes",
                "-Werror=strict-prototypes",
                "-Werror=int-conversion",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_incomplete_recursive_call_uses_current_function_prototype():
    """A recursive target uses the function definition plus a per-call spec.

    There is no external declaration to consult here. The first recursive call
    carries the incoming SysV argument; the second has no reaching argument
    setup. The emitted function definition is the callee prototype, while only
    the incomplete call is expressed through its exact recovered pointer type.
    """
    binary = _compile_so(
        "__asm__(\n"
        '    ".text\\n"\n'
        '    ".globl mixed_recursive_calls\\n"\n'
        '    ".type mixed_recursive_calls,@function\\n"\n'
        '    "mixed_recursive_calls:\\n"\n'
        '    "push %rbp\\n"\n'
        '    "mov %rsp,%rbp\\n"\n'
        '    "sub $16,%rsp\\n"\n'
        '    "mov %rdi,-8(%rbp)\\n"\n'
        '    "mov -8(%rbp),%rdi\\n"\n'
        '    "call mixed_recursive_calls\\n"\n'
        '    "call mixed_recursive_calls\\n"\n'
        '    "leave\\n"\n'
        '    "ret\\n"\n'
        '    ".size mixed_recursive_calls,.-mixed_recursive_calls\\n"\n'
        ");",
        "mixed_arity_recursive",
    )
    function_va = D.exported_functions(binary)["mixed_recursive_calls"]
    decompiled = D.decompiled_c(binary, function_va)
    assert decompiled is not None
    assert "mixed_recursive_calls(long arg0)" in decompiled, decompiled
    assert "((long (*)(void))mixed_recursive_calls)()" in decompiled, decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "mixed_arity_recursive.c"
        output_path = Path(td) / "mixed_arity_recursive.so"
        source_path.write_text(D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Wstrict-prototypes",
                "-Werror=strict-prototypes",
                "-Werror=implicit-function-declaration",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_void_libc_call_is_not_rendered_as_a_value():
    """A declared-void library call must not acquire a synthetic result.

    Return-register liveness alone is insufficient: on SysV AMD64, a later
    load into RAX after ``perror`` used to make the call look value-producing.
    This compiles a real ELF import, crosses symbol resolution and the native
    AST pipeline, then asks the C compiler to enforce the system declaration.
    """
    binary = _compile_so(
        "#include <stdio.h>\n"
        "__attribute__((noinline)) int report_and_test(const char *s) {\n"
        "    perror(s);\n"
        "    return s != 0;\n"
        "}",
        "void_libc_call",
    )
    report_va = D.exported_functions(binary)["report_and_test"]
    decompiled = D.decompiled_c(binary, report_va)
    assert decompiled is not None
    assert "perror(" in decompiled

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        source_path = Path(td) / "void_libc_call.c"
        output_path = Path(td) / "void_libc_call.so"
        source_path.write_text("#include <stdio.h>\n" + D.PRELUDE + "\n" + decompiled + "\n")
        rebuilt = TC.run(
            [
                "gcc",
                "-shared",
                "-fPIC",
                "-O0",
                "-std=gnu11",
                "-Werror",
                "-o",
                str(output_path),
                str(source_path),
            ]
        )

    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_real_pointer_locals_keep_value_identity_across_round_trip():
    """Pointer-producing definitions must type their exact high variables.

    A value-numbered ``varN`` is one recovered value, not the physical register
    that happened to carry it.  Declaring every such local as ``long`` loses
    that identity for both a known pointer-returning call and a literal address.
    Compile a real ELF containing both shapes, decompile each exported function,
    and let the system ``getenv`` declaration plus ``-Werror`` enforce the
    source-level pointer contract on the round trip.
    """
    binary = _compile_so(
        "#include <stdlib.h>\n"
        "__attribute__((noinline)) char *lookup_path(void) {\n"
        "    char *value = getenv(\"PATH\");\n"
        "    return value;\n"
        "}\n"
        "__attribute__((noinline)) const char *literal_path(void) {\n"
        "    const char *value = \"/tmp/fallback\";\n"
        "    return value;\n"
        "}",
        "pointer_high_variables",
    )
    exported = D.exported_functions(binary)

    for function in ("lookup_path", "literal_path"):
        decompiled = D.decompiled_c(binary, exported[function])
        assert decompiled is not None

        with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
            source_path = Path(td) / f"{function}.c"
            output_path = Path(td) / f"{function}.so"
            source_path.write_text(
                "#include <stdlib.h>\n" + D.PRELUDE + "\n" + decompiled + "\n"
            )
            rebuilt = TC.run(
                [
                    "gcc",
                    "-shared",
                    "-fPIC",
                    "-O0",
                    "-std=gnu11",
                    "-Werror",
                    "-o",
                    str(output_path),
                    str(source_path),
                ]
            )

        assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{decompiled}"


def test_compile_failure_of_decompilation_is_fail(monkeypatch, tmp_path):
    # If the decompiled C does not compile, the function FAILS (not skip).
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int f(int arg0){ this is not c }")
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "fail" and "compile" in r["detail"]


def test_decompile_failure_is_fail(monkeypatch, tmp_path):
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: None)
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "fail" and "decompile" in r["detail"]


def test_worker_crash_is_fail(monkeypatch, tmp_path):
    # A decompilation that segfaults must not crash the caller: the worker dies
    # in its own process and the parent reports a FAIL.
    sig = {"name": "boom", "va": 0, "params": [], "ret": "int"}
    # Compile a real original + a decompilation that dereferences null on call.
    orig_so = _compile_so("int boom(void){return 1;}", "boom")
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int boom(void){ int*p=0; return *p; }")
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", orig_so, Path(td), seed=1, fuzz=1)
    assert r["status"] == "fail", r
    assert "on []" in r["detail"], r


def test_a_nonterminating_decompilation_is_a_divergence_not_a_timeout(monkeypatch):
    """The original returns; ours loops forever. That is the most severe kind of
    behavioural difference and must be reported as a FAIL against that function —
    not as a worker `timeout`, which would say "the machine was too slow" and be
    refused from the baseline as infrastructure. It also has to be bounded per CALL:
    a per-function timeout lets one hung call burn the whole budget (raising it from
    60s to 180s turned a 8-minute matrix into a 40-minute one).
    """
    orig = _compile_so("int spin(int a){ return a; }", "term")
    monkeypatch.setattr(
        D, "decompiled_c",
        lambda *_a, **_k: "int spin(int a){ volatile int i=1; while(i){ i++; if(i==0) i=1; } return a; }")
    sig = {"name": "spin", "va": 0, "params": ["int"], "ret": "int"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        import time
        t0 = time.time()
        r = D.run_function(sig, "fx", orig, Path(td), seed=1, fuzz=1)
        elapsed = time.time() - t0
    assert r["status"] == "fail", r
    assert "did not terminate" in r["detail"], r
    assert "on [" in r["detail"], r
    assert elapsed < D.WORKER_TIMEOUT_S, (
        f"non-termination must be caught by the per-call budget "
        f"({D.DECOMPILED_CALL_BUDGET_S}s), not the worker timeout: took {elapsed:.1f}s"
    )


def test_worker_nonzero_exit_is_fail(tmp_path):
    # Directly: a malformed worker spec makes the worker raise -> nonzero exit ->
    # the parent's subprocess check must treat it as a failure.
    spec = tmp_path / "bad.json"
    spec.write_text("{ not json")
    r = subprocess.run([sys.executable, str(TOOLS / "diff_decompile.py"), "--worker", str(spec)],
                       capture_output=True, text=True, check=False)
    assert r.returncode != 0


def test_skip_exec_is_structural_not_pass(monkeypatch, tmp_path):
    # A function the manifest marks skip_exec is reported `structural`, a distinct
    # status the structural lane must check — never a silent pass.
    sig = {"name": "apply", "va": 0, "params": ["int", "int"], "ret": "int"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "08_indirect_dispatch", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "structural"


def test_recovered_cpp_stack_objects_are_not_quarantined():
    """Constructor and RAII O0 lanes must execute on both pinned compilers."""
    for function in ("cpp_ctor_dtor", "cpp_raii_guard"):
        override = M.OVERRIDES.get(("10_cpp_runtime_shapes", function), {})
        assert "skip_exec" not in override
        assert "skip_exec_lanes" not in override


def test_no_executable_cases_is_not_a_pass(monkeypatch, tmp_path):
    # Zero generated cases is an infra failure (distinct `nocases` status so
    # --write-baseline refuses it), never a silent pass.
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int f(int arg0){return arg0;}")
    monkeypatch.setattr(D, "make_vectors", lambda *_a, **_k: [])
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "nocases" and "case" in r["detail"]


def test_required_missing_function_is_fail():
    # Fixture 01 really has these; delete-simulate via a fixture with a bogus
    # requirement by checking the presence logic directly.
    assert "cmp_signed" in D.M.REQUIRED_FUNCTIONS["01_conditional_polarity"]


def test_void_signature_is_a_distinct_structural_contract():
    assert S.has_void_signature("void tick(void) { return; }")
    assert not S.has_void_signature("int tick(void) { return 0; }")


def test_vector_generation_is_reproducible_across_processes():
    # Python's hash(str) is per-process randomized; the fuzz seed must NOT depend
    # on it, or a CI lane on another machine exercises different inputs. Two fresh
    # interpreters must produce byte-identical vectors.
    prog = (
        "import sys;sys.path.insert(0,'tools');sys.path.insert(0,'tests/decompiler_fixtures');"
        "import json,diff_decompile as D;"
        "print(json.dumps(D.make_vectors({'name':'vec_sum','params':['ptr','int'],'ret':'int'},"
        "{'len_args':[1]},1,6)))"
    )
    outs = [
        subprocess.run([sys.executable, "-c", prog], cwd=ROOT, capture_output=True,
                       text=True, check=True).stdout
        for _ in range(2)
    ]
    assert outs[0] == outs[1], "fuzz vectors differ across processes (non-deterministic seed)"


def test_stable_seed_is_independent_of_python_hash_randomization():
    # Directly: the seed helper must not use the randomized builtin hash().
    assert D._stable_seed("vec_sum", 1) == D._stable_seed("vec_sum", 1)
    assert D._stable_seed("a", 1) != D._stable_seed("b", 1)


def test_tmpdir_is_portable_and_falls_back(monkeypatch):
    # No env + no /nas4 path -> None (system tempfile default), never a crash.
    monkeypatch.delenv("GLAURUNG_FIXTURE_TMPDIR", raising=False)
    monkeypatch.delenv("TMPDIR", raising=False)
    assert D.M.tmpdir() is None
    # A bogus override is ignored (missing/unwritable), not trusted.
    monkeypatch.setenv("GLAURUNG_FIXTURE_TMPDIR", "/no/such/dir/xyz")
    assert D.M.tmpdir() is None
    # A real writable override is honored.
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("GLAURUNG_FIXTURE_TMPDIR", td)
        assert D.M.tmpdir() == td


def test_harness_runs_without_the_nas_scratch_path(monkeypatch):
    # Prove run_function works when /nas4/.../rdtmp does not exist: point the
    # scratch dir at a plain system tempdir and execute a trivially-correct
    # decompilation end to end.
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int f(int arg0){return arg0;}")
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    with tempfile.TemporaryDirectory() as bwd:
        # a real original .so so the worker has something to call
        src = Path(bwd) / "o.c"
        src.write_text("int f(int a){return a;}\n")
        orig = Path(bwd) / "o.so"
        r = TC.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(orig), str(src)])
        assert r.returncode == 0, r.stderr
        r = D.run_function(sig, "fx", str(orig), Path(bwd), seed=1, fuzz=2)
    assert r["status"] == "pass", r


def test_wrong_high_32_bits_of_a_64bit_return_fails(monkeypatch):
    # A 64-bit return whose high half the decompilation drops must FAIL — only
    # possible if the return width is modeled as 8 bytes, not truncated to int.
    orig = _compile_so("long f(long a){ return a; }", "hi")
    monkeypatch.setattr(D, "decompiled_c",
                        lambda *_a, **_k: "long f(long a){ return a & 0xFFFFFFFF; }")
    sig = {"name": "f", "va": 0, "params": ["long"], "ret": "long"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", orig, Path(td), seed=1, fuzz=2)
    assert r["status"] == "fail", r


def test_wrong_sign_extension_fails(monkeypatch):
    # orig sign-extends a 32-bit arg into a 64-bit return; the decompilation
    # zero-extends. On a negative input the two differ only in the high 32 bits.
    orig = _compile_so("long f(int a){ return a; }", "sx")
    monkeypatch.setattr(D, "decompiled_c",
                        lambda *_a, **_k: "long f(int a){ return (unsigned int)a; }")
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "long"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", orig, Path(td), seed=1, fuzz=2)
    assert r["status"] == "fail", r


def test_signatures_recover_width_and_signedness():
    # DWARF recovery must carry width + signedness, not collapse to int.
    so = _compile_so(
        "long g(unsigned char b, int i, long l, const unsigned char* p){"
        " (void)b;(void)i;(void)l;return p?p[0]:0; }", "sg")
    sigs = {s["name"]: s for s in D.signatures(so)}
    g = sigs["g"]
    assert D._as_desc(g["ret"]) == {"k": "int", "w": 8, "s": True}
    ps = [D._as_desc(p) for p in g["params"]]
    assert ps[0] == {"k": "int", "w": 1, "s": False}          # unsigned char
    assert ps[1] == {"k": "int", "w": 4, "s": True}           # int
    assert ps[2] == {"k": "int", "w": 8, "s": True}           # long
    assert ps[3]["k"] == "ptr" and ps[3]["pw"] == 1 and ps[3]["const"] is True


def test_struct_signatures_are_executed_at_the_real_sysv_abi(monkeypatch):
    """A two-int struct is one SysV INTEGER eightbyte.

    The original is called with its DWARF aggregate type while the decompiled C
    intentionally uses the ABI-compatible packed `long` representation Glaurung
    emits. Both the by-value and pointer-to-struct functions must run through the
    differential; neither may fall back to a structural/non-executed verdict.
    """
    orig = _compile_so(
        "struct pt { int x, y; };"
        "long dist2(struct pt a, struct pt b){"
        " long dx=(long)a.x-b.x,dy=(long)a.y-b.y;return dx*dx+dy*dy;}"
        "int rect_area(const struct pt *p){"
        " return (p[1].x-p[0].x)*(p[1].y-p[0].y);}",
        "struct_abi",
    )
    sigs = {s["name"]: s for s in D.signatures(orig)}

    dist = sigs["dist2"]
    assert [p["k"] for p in dist["params"]] == ["struct", "struct"]
    assert dist["params"][0]["w"] == 8
    assert [(f["off"], f["t"]["w"]) for f in dist["params"][0]["fields"]] == [
        (0, 4),
        (4, 4),
    ]
    rect = sigs["rect_area"]
    assert rect["params"][0]["k"] == "ptr"
    assert rect["params"][0]["p"]["k"] == "struct"

    recovered = {
        "dist2": (
            "long dist2(long a,long b){"
            "long dx=(int)(unsigned int)a-(int)(unsigned int)b;"
            "long dy=(int)((unsigned long)a>>32)-(int)((unsigned long)b>>32);"
            "return dx*dx+dy*dy;}"
        ),
        "rect_area": (
            "int rect_area(const int *p){"
            "return (p[2]-p[0])*(p[3]-p[1]);}"
        ),
    }
    monkeypatch.setattr(D, "decompiled_c", lambda _b, va: recovered[next(
        name for name, sig in sigs.items() if sig["va"] == va
    )])

    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        for sig in (dist, rect):
            result = D.run_function(sig, "fx", orig, Path(td), seed=7, fuzz=12)
            assert result["status"] == "pass", (sig["name"], result)


def test_exit_code_distinguishes_infra_from_semantic():
    assert D.exit_code({"f": {"status": "pass"}}) == 0
    assert D.exit_code({"f": {"status": "structural"}}) == 0
    assert D.exit_code({"f": {"status": "fail"}}) == 1
    assert D.exit_code({"f": {"status": "missing"}}) == 2
    assert D.exit_code({"f": {"status": "nocases"}}) == 2
    # A timeout is infrastructure (machine too slow), never a semantic verdict.
    assert D.exit_code({"f": {"status": "timeout"}}) == 2
    assert D.exit_code({"__error__": "no dwarf"}) == 2


def test_recompile_prelude_accepts_ghidra_scalar_dialect(tmp_path):
    rebuilt = D.build_so(
        "uint32_t dialect_identity(uint value, uint4 other) { "
        "int4 signed_other = (int4)other; "
        "while (true) { return value + signed_other; } }",
        tmp_path,
        "ghidra_scalar_dialect",
    )

    assert rebuilt is not None


def test_injected_backend_named_struct_is_rebuilt_from_dwarf(monkeypatch):
    original = _compile_so(
        "typedef struct { int value; } NamedNode; "
        "int named_read(const NamedNode *nodes, int index) { "
        "if (!nodes || index < 0 || index >= 16) return -1; "
        "return nodes[index].value; }",
        "named_struct",
    )
    address = D.exported_functions(original)["named_read"]
    monkeypatch.setattr(
        D,
        "decompiled_many_c",
        lambda *_args, **_kwargs: pytest.fail(
            "Glaurung must not run for injected code"
        ),
    )

    results = D.run(
        original,
        str(SRC / "01_conditional_polarity.c"),
        "fx",
        seed=1234,
        fuzz=8,
        only={"named_read"},
        decompiled_by_va={
            address: (
                "int named_read(NamedNode *nodes, int index) { "
                "if (!nodes || index < 0 || index >= 16) return -1; "
                "return nodes[index].value; }"
            )
        },
    )

    assert results == {"named_read": {"status": "pass", "detail": "18 cases"}}


def test_run_uses_injected_backend_source_without_invoking_glaurung(monkeypatch):
    original = _compile_so(
        "static __attribute__((noinline)) int injected_helper(int value) { "
        "return value + 1; } "
        "int injected(int value) { return injected_helper(value); }",
        "injected",
    )
    address = D.exported_functions(original)["injected"]
    helper_address = D.defined_functions(original)["injected_helper"]
    monkeypatch.setattr(
        D,
        "decompiled_many_c",
        lambda *_args, **_kwargs: pytest.fail(
            "Glaurung must not run for injected code"
        ),
    )
    monkeypatch.setattr(
        D,
        "decompiled_c",
        lambda *_args, **_kwargs: pytest.fail(
            "Glaurung must not run for an injected helper"
        ),
    )

    results = D.run(
        original,
        str(SRC / "01_conditional_polarity.c"),
        "fx",
        seed=1234,
        fuzz=8,
        only={"injected"},
        decompiled_by_va={
            address: (
                "int injected(int value) { return injected_helper(value); }"
            ),
            helper_address: (
                "int injected_helper(int value)\n\n{ return value + 1; }"
            ),
        },
    )

    assert results == {"injected": {"status": "pass", "detail": "18 cases"}}


def test_recompile_failure_reports_the_compiler_diagnostic(tmp_path):
    rebuilt, diagnostic = D.build_so_with_diagnostic(
        "int invalid_backend_output(void) { return this is not C; }",
        tmp_path,
        "invalid_backend_output",
    )

    assert rebuilt is None
    assert "error:" in diagnostic
    assert "this" in diagnostic


def test_json_mode_returns_two_on_infra(tmp_path):
    # A stripped binary -> no DWARF -> __error__ -> nonzero (infra) exit.
    src = tmp_path / "x.c"
    src.write_text("int f(int a){return a;}\n")
    so = _compile_so("int f(int a){return a;}", "jsoninfra", debug=False)  # no -g
    r = subprocess.run([sys.executable, str(TOOLS / "diff_decompile.py"), str(so), str(src), "--json"],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 2, r.stderr


def test_write_baseline_refuses_lane_errors_and_infra_statuses():
    good = {"01:gcc:O0": {"cmp_signed": "pass", "sc_and": "fail"}}
    assert H.baseline_problems(good) == []
    bad_lane = {"01:gcc:O0": {"__lane__": "compile-failed: boom"}}
    assert H.baseline_problems(bad_lane), "must refuse a compile-failed lane"
    env_ok = {"10:clang:O0": {"__lane__": "env-missing"}}
    assert H.baseline_problems(env_ok) == [], "declared env-missing lanes are allowed"
    bad_status = {"09:gcc:O0": {"tick": "structural", "read_be16": "missing"}}
    assert H.baseline_problems(bad_status), "must refuse a missing required function"
    nocases = {"x:gcc:O0": {"f": "nocases"}}
    assert H.baseline_problems(nocases), "must refuse a zero-case function"
    timeout = {"x:gcc:O0": {"f": "timeout"}}
    assert H.baseline_problems(timeout), (
        "must refuse a timeout — recording it would bake machine speed into the "
        "baseline"
    )


def test_schema_requires_all_ten_fixtures():
    # A baseline covering only some fixtures is rejected.
    partial = {"01_conditional_polarity:gcc:O0": {"cmp_signed": "pass"}}
    assert H.schema_problems(partial, [("gcc", "O0")]), "must require all ten fixtures"


def test_a_pinned_argument_never_takes_another_value():
    # `arg_values` exists so a guard parameter cannot send execution down an
    # unbounded path: guarded_spin's `spin` must be 0 in EVERY vector, boundary
    # sweep and seeded fuzz alike. Driven nonzero it ran a volatile loop to 32-bit
    # wraparound, which passed on a fast machine and timed out on a CI runner.
    sig = {"name": "guarded_spin", "va": 0, "params": ["int", "int"], "ret": "int"}
    ov = D.M.override("06_calling_conventions", "guarded_spin")
    assert ov.get("arg_values") == {0: [0]}, "the guard must be declared pinned"
    vecs = D.make_vectors(sig, ov, seed=1234, fuzz=12)
    assert vecs, "vectors must still be generated"
    assert {v[0] for v in vecs} == {0}, f"spin escaped its pinned value: {vecs}"
    # The other argument is untouched: still swept and fuzzed.
    assert len({v[1] for v in vecs}) > 3


def test_fact_mod_contract_exercises_remainder_without_unbounded_recursion():
    sig = {"name": "fact_mod", "va": 0, "params": ["int"], "ret": "int"}
    ov = D.M.override("06_calling_conventions", "fact_mod")
    allowed = ov.get("arg_values", {}).get(0, [])
    assert {0, 1, 2, 3, 5, 10, 100, 1000} <= set(allowed), (
        "fact_mod must exercise base cases, recursive unrolling, and many modular "
        "reductions"
    )
    assert max(allowed) <= 1000, (
        "the source is linearly recursive; an INT_MAX boundary measures stack "
        "exhaustion rather than decompiler semantics"
    )
    vectors = D.make_vectors(sig, ov, seed=1234, fuzz=12)
    assert vectors
    assert {vector[0] for vector in vectors} <= set(allowed)


def test_pinned_arguments_are_reproducible():
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    ov = {"arg_values": {0: [3, 4]}}
    a = D.make_vectors(sig, ov, seed=7, fuzz=8)
    b = D.make_vectors(sig, ov, seed=7, fuzz=8)
    assert a == b
    assert {v[0] for v in a} <= {3, 4}


def test_an_invalid_pinned_argument_is_rejected():
    # A manifest that pins a parameter but declares no value (or pins something
    # that is not a scalar, or does not exist) would silently generate vectors that
    # do not exercise what it claims. Fail closed on all three.
    sig = {"name": "f", "va": 0, "params": ["int", "ptr"], "ret": "int"}
    for bad, why in [
        ({0: []}, "empty value list"),
        ({5: [0]}, "index out of range"),
        ({1: [0]}, "pins a pointer parameter"),
    ]:
        try:
            D.make_vectors(sig, {"arg_values": bad}, seed=1, fuzz=2)
        except ValueError:
            continue
        raise AssertionError(f"arg_values {bad!r} must be rejected ({why})")


def test_length_args_are_clamped_to_buffer():
    # A scalar flagged as a length must never exceed the allocated buffer, so a
    # boundary like INT_MAX cannot drive an out-of-bounds ctypes write.
    sig = {"name": "vec_sum", "va": 0, "params": ["ptr", "int"], "ret": "int"}
    ov = D.M.override("09_memory_effects", "vec_sum")
    vecs = D.make_vectors(sig, ov, seed=1, fuzz=4)
    ptr_len = ov.get("ptr_len", D.M.DEFAULT_PTR_LEN)
    for v in vecs:
        assert 0 <= v[1] <= ptr_len, f"length arg {v[1]} not clamped to {ptr_len}"
        assert isinstance(v[0], list) and len(v[0]) == ptr_len


# ---------------------------------------------------------------------------
# Both baseline writers must refuse an undeclared fixture
# ---------------------------------------------------------------------------


def test_both_baseline_writers_reject_an_undeclared_fixture(tmp_path, monkeypatch):
    """A fixture on disk with no REQUIRED_FUNCTIONS entry must stop BOTH refreshers.

    This is a regression test for an asymmetry, not for a missing check. Adding
    `13_loop_early_exit.c` without declaring it made `fixture_harness.py
    --write-baseline` refuse — correctly — while `gen_structural_baseline.py`, run in
    the same command, wrote `structural_baseline.json` anyway. The two baselines then
    disagreed about which fixtures exist, and the undeclared one's structural state
    was silently blessed while its execution state was simply absent.

    The check now lives in `manifest.assert_fixtures_declared`, which both writers
    call. A guard only one writer honours is not a guard.
    """
    import manifest as MM

    # A source file on disk that nothing declares.
    stray = MM.FIXTURE_SRC / "99_undeclared_probe.c"
    stray.write_text("int probe(void) { return 0; }\n")
    try:
        with pytest.raises(AssertionError) as ei:
            MM.assert_fixtures_declared()
        assert "99_undeclared_probe" in str(ei.value), (
            f"the failure must name the offending fixture, got: {ei.value}"
        )
    finally:
        stray.unlink()

    # ...and the declared-but-missing direction, which is how a rename loses its
    # contract: the fixture keeps its baseline entries under the old name.
    monkeypatch.setitem(MM.REQUIRED_FUNCTIONS, "98_declared_but_absent", ["nope"])
    with pytest.raises(AssertionError) as ei:
        MM.assert_fixtures_declared()
    assert "98_declared_but_absent" in str(ei.value)


def test_both_writers_actually_call_the_shared_precondition():
    """Guard against the check drifting back into only one writer.

    Asserting on source text is blunt, but the failure being prevented is precisely
    that one writer stops calling it — which no behavioural test of the OTHER writer
    can catch.
    """
    for tool in ("fixture_harness.py", "gen_structural_baseline.py"):
        text = (TOOLS / tool).read_text()
        assert "assert_fixtures_declared()" in text, (
            f"{tool} no longer calls the shared fixture-declaration precondition; "
            f"an undeclared fixture would land in one baseline and not the other"
        )
