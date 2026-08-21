"""Regression tests for extbench cross-binary aggregation."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_analyze_module():
    path = Path(__file__).parents[2] / "tools" / "extbench" / "analyze.py"
    spec = importlib.util.spec_from_file_location("extbench_analyze", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_callcheck_module():
    path = Path(__file__).parents[2] / "tools" / "extbench" / "callcheck.py"
    spec = importlib.util.spec_from_file_location("extbench_callcheck", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agg_micro_averages_function_metrics_but_not_binary_timings() -> None:
    """A small binary must not outweigh nine functions from a large binary."""
    analyze = _load_analyze_module()
    per_tag = {
        "one_function": {
            "tools": {
                "glaurung": {
                    "n_targets": 1,
                    "produced": 1,
                    "mean_decls": 100.0,
                    "n_produced_metrics": 1,
                    "argc_exact_rate": 0.0,
                    "n_argc_scored": 1,
                    "n_argc_exact": 0,
                    "recall_fde": 1.0,
                    "n_fde": 1,
                    "n_fde_found": 1,
                    "total_s": 2.0,
                }
            }
        },
        "nine_functions": {
            "tools": {
                "glaurung": {
                    "n_targets": 9,
                    "produced": 9,
                    "mean_decls": 0.0,
                    "n_produced_metrics": 9,
                    "argc_exact_rate": 1.0,
                    "n_argc_scored": 9,
                    "n_argc_exact": 9,
                    "recall_fde": 0.0,
                    "n_fde": 9,
                    "n_fde_found": 0,
                    "total_s": 4.0,
                }
            }
        },
    }

    row = analyze.agg(per_tag, list(per_tag))["glaurung"]

    assert row["success_rate"] == 1.0
    assert row["mean_decls"] == 10.0
    assert row["argc_exact_rate"] == 0.9
    assert row["recall_fde"] == 0.1
    assert row["total_s"] == 3.0


def test_objdump_command_disables_implicit_debuginfod_network_access() -> None:
    """A local call probe must not block on an ambient debuginfod service."""
    callcheck = _load_callcheck_module()

    x64 = callcheck.objdump_command(Path("/bin/true"), "x64")
    aarch64 = callcheck.objdump_command(Path("/bin/true"), "AArch64")

    assert x64 == ["objdump", "-d", "/bin/true"]
    assert aarch64 == ["aarch64-linux-gnu-objdump", "-d", "/bin/true"]


def test_call_probe_indexes_each_emitted_va_once() -> None:
    """Duplicate tool rows cannot inflate the call-quality denominator."""
    callcheck = _load_callcheck_module()
    functions = [
        {"va": 0x1000, "code": "first();"},
        {"va": 0x1000, "code": "duplicate();"},
        {"va": 0x2000, "code": "second();"},
        {"va": 0x3000, "code": ""},
    ]

    indexed = callcheck.index_function_code(functions)

    assert indexed == {0x1000: "first();", 0x2000: "second();"}


def test_call_probe_uses_the_same_even_stride_as_the_tool_run() -> None:
    """Whole-image tools must be restricted to the shared target sample."""
    callcheck = _load_callcheck_module()
    entries = [{"va": va, "size": 1} for va in range(10)]

    sampled = callcheck.sample_entries(entries, 3)

    assert [entry["va"] for entry in sampled] == [0, 3, 6]


def test_call_probe_resolves_versioned_got_imports() -> None:
    """Indirect imported calls are real calls, not decompiler inventions."""
    callcheck = _load_callcheck_module()
    relocations = """
0000000000009fa8 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.34
0000000000009fe8 R_X86_64_GLOB_DAT  __cxa_finalize@GLIBC_2.2.5
"""

    parsed = callcheck.parse_dynamic_relocations(relocations)

    assert parsed == {0x9FA8: "__libc_start_main", 0x9FE8: "__cxa_finalize"}
    assert (
        callcheck.indirect_import_target(
            " 3adf: ff 15 c3 64 00 00 call *0x64c3(%rip) # 9fa8 <nearest+0x1>",
            parsed,
        )
        == "__libc_start_main"
    )


# --- the declaration count must count declarations ---------------------------


def test_a_goto_is_not_a_declaration():
    """`DECL_RE` had no keyword exclusion in the type position.

    `goto L_36afd;` is two identifiers and a semicolon, which is exactly the
    shape of `long var4;`, so every `goto` was counted as a declaration — and
    so was every `return ret;`.

    That is not a rounding error. On the extbench Tier B corpus the reported
    46.34 declarations per function is 14.73 gotos and 0.72 returns on top of
    31.11 real ones: **32% of the published figure**. Worse, it scales with
    goto density, so it inflated whichever tool emits the most gotos hardest —
    which is ours, at 8.63 per 100 lines against Ghidra's 3.18. Every
    declaration comparison made before 2026-08-21 is affected.
    """
    analyze = _load_analyze_module()
    body = "\n".join(
        [
            "    long var4;",
            "    unsigned int var9;",
            "    char *name;",
            "    int table[8];",
            "    goto L_36afd;",
            "    return ret;",
            "    break;",
            "    continue;",
            "    foo(bar);",
        ]
    )
    found = analyze.DECL_RE.findall(body)
    assert len(found) == 4, (
        f"expected the four real declarations, got {len(found)}: {found}"
    )


def test_the_keyword_exclusion_did_not_break_real_declarations():
    """The guard sits in the type position, so a *variable* named `gotor` or a
    type whose name merely starts with a keyword must still count."""
    analyze = _load_analyze_module()
    for line in (
        "    long gotor;",
        "    int returns;",
        "    breakpoint_t bp;",
        "    default_handler_t handler;",
    ):
        assert len(analyze.DECL_RE.findall(line)) == 1, (
            f"the keyword exclusion swallowed a real declaration: {line!r}"
        )
