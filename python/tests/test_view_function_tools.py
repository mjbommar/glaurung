from pathlib import Path
import pytest
import glaurung as g


@pytest.mark.skipif(
    not Path(
        "../samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0"
    ).exists(),
    reason="sample binary not present",
)
def test_trace_main_printf_hello():
    # Skip if LLM dependencies not available
    try:
        from glaurung.llm.context import MemoryContext, Budgets
        from glaurung.llm.kb.adapters import import_triage
        from glaurung.llm.tools.list_functions import build_tool as build_list_functions
        from glaurung.llm.tools.view_function import build_tool as build_view_function
        from glaurung.llm.tools.view_symbols import build_tool as build_view_symbols
        from glaurung.llm.tools.map_elf_plt import build_tool as build_map_elf_plt
    except ImportError:
        pytest.skip("LLM dependencies not available")

    sample = Path(
        "../samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0"
    )

    # Check if sample is corrupted (contains text instead of binary)
    with open(sample, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {sample} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    art = g.triage.analyze_path(str(sample), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(sample), artifact=art, budgets=Budgets(max_functions=32)
    )
    import_triage(ctx.kb, art, str(sample))

    # Enumerate functions
    lf = build_list_functions()
    lres = lf.run(ctx, ctx.kb, lf.input_model(max_functions=32))
    assert lres.functions, "no functions"  # sanity
    main = next((f for f in lres.functions if f.name == "main"), lres.functions[0])

    # Symbols/PLT available
    vs = build_view_symbols()
    vs.run(ctx, ctx.kb, vs.input_model())
    pe = build_map_elf_plt()
    pe.run(ctx, ctx.kb, pe.input_model())

    # View function and extract calls/strings
    vf = build_view_function()
    vres = vf.run(ctx, ctx.kb, vf.input_model(va=main.entry_va, max_instructions=128))
    # Expect at least one printf-like call or a constant string
    calls = [c.target_name.lower() for c in vres.calls if c.target_name]
    stexts = [s.text.lower() for s in vres.strings]
    assert any("printf" in c or "puts" in c for c in calls) or any(
        "hello" in s for s in stexts
    )
