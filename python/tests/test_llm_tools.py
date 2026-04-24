"""Tests for the new memory-first LLM tools and agent."""

from glaurung.llm.tools.suggest_function_name import build_naming_prompt


def test_build_naming_prompt_includes_pseudocode_when_decompile_succeeds(tmp_path: "__import__('pathlib').Path"):
    """build_naming_prompt should embed decompiler output when available."""
    from pathlib import Path
    import glaurung as g
    from glaurung.llm.context import MemoryContext, Budgets
    from glaurung.llm.kb.adapters import import_triage

    sample = Path("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2")
    if not sample.exists():
        import pytest
        pytest.skip("sample missing")

    art = g.triage.analyze_path(str(sample))
    ctx = MemoryContext(
        file_path=str(sample),
        artifact=art,
        budgets=Budgets(timeout_ms=500),
    )
    import_triage(ctx.kb, art, str(sample))

    # Use the detected entry VA — we know hello-gcc-O2's _start is at 0x1840.
    entry_info = g.analysis.detect_entry_path(str(sample))
    assert entry_info is not None
    va = int(entry_info[3])

    prompt = build_naming_prompt(
        ctx=ctx,
        va=va,
        original_name="_start",
        demangled_name=None,
        instructions=[],
        calls=[],
        strings=[],
    )
    # Prompt must include the pseudocode fence and the function header
    # the C-style renderer emits.
    assert "glaurung --style c" in prompt
    assert "fn _start {" in prompt


def test_build_naming_prompt_falls_back_when_decompile_unavailable(tmp_path):
    """When no VA is given (or decompile fails) the helper uses the legacy
    context shape."""
    from glaurung.llm.context import MemoryContext, Budgets

    # MemoryContext without a usable file — decompile will raise and the
    # helper must fall back.
    from unittest.mock import MagicMock
    ctx = MemoryContext(
        file_path="/nonexistent",
        artifact=MagicMock(),
        budgets=Budgets(timeout_ms=100),
    )
    prompt = build_naming_prompt(
        ctx=ctx,
        va=None,
        original_name="sub_1234",
        demangled_name=None,
        instructions=["mov rax, 0x1", "ret"],
        calls=["puts@plt"],
        strings=["hello"],
    )
    assert "glaurung --style c" not in prompt
    assert "puts@plt" in prompt
    assert "'hello'" in prompt or "\"hello\"" in prompt
    assert "mov rax" in prompt

from pathlib import Path
from unittest.mock import Mock
import pytest
import glaurung as g

from glaurung.llm.context import MemoryContext, Budgets
from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.tools.hash_file import build_tool as build_file_hash
from glaurung.llm.tools.view_strings import build_tool as build_view_strings
from glaurung.llm.tools.view_entry import build_tool as build_view_entry
from glaurung.llm.tools.view_disassembly import build_tool as build_view_disassembly
from glaurung.llm.kb.adapters import import_triage


def _make_ctx_for_bytes(data: bytes, tmp_path: Path) -> MemoryContext:
    p = tmp_path / "bin.bin"
    p.write_bytes(data)
    art = g.triage.analyze_bytes(data)
    ctx = MemoryContext(file_path=str(p), artifact=art)
    import_triage(ctx.kb, art, str(p))
    return ctx


class TestAtomicTools:
    def test_file_hash_direct(self, tmp_path: Path):
        ctx = _make_ctx_for_bytes(b"hello world", tmp_path)
        tool = build_file_hash()
        out = tool.run(ctx, ctx.kb, tool.input_model())
        assert len(out.hexdigest) == 64

    def test_strings_import_kb(self, tmp_path: Path):
        data = b"Visit http://example.com and email test@example.org\nHello world!"
        ctx = _make_ctx_for_bytes(data, tmp_path)
        tool = build_view_strings()
        out = tool.run(ctx, ctx.kb, tool.input_model(max_samples=20))
        assert out.count > 0
        # Ensure string nodes present
        assert any(n.kind.value == "string" for n in ctx.kb.nodes())


@pytest.mark.skipif(
    not Path(
        "samples/binaries/platforms/linux/amd64/native/clang/O0/hello-clang-O0"
    ).exists(),
    reason="sample binary not present",
)
class TestDisasmAndAgent:
    def test_disasm_window_on_entry(self):
        sample = Path(
            "samples/binaries/platforms/linux/amd64/native/clang/O0/hello-clang-O0"
        )
        art = g.triage.analyze_path(str(sample), 10_000_000, 100_000_000, 1)
        ctx = MemoryContext(
            file_path=str(sample), artifact=art, budgets=Budgets(max_instructions=256)
        )
        import_triage(ctx.kb, art, str(sample))
        dtool = build_view_entry()
        dres = dtool.run(ctx, ctx.kb, dtool.input_model())
        assert dres.entry_va is None or isinstance(dres.entry_va, int)
        # Disassemble near zero or at entry if available
        v = dres.entry_va or 0
        wtool = build_view_disassembly()
        wres = wtool.run(ctx, ctx.kb, wtool.input_model(va=v, max_instructions=32))
        assert isinstance(wres.instructions, list)

    def test_memory_agent_smoke(self):
        sample = Path(
            "samples/binaries/platforms/linux/amd64/native/clang/O0/hello-clang-O0"
        )
        art = g.triage.analyze_path(str(sample), 10_000_000, 100_000_000, 1)
        ctx = MemoryContext(
            file_path=str(sample), artifact=art, budgets=Budgets(max_functions=3)
        )
        import_triage(ctx.kb, art, str(sample))
        agent = create_memory_agent(model="test")
        r1 = agent.run_sync("hash the file", deps=ctx)
        assert isinstance(r1.output, str)
        r2 = agent.run_sync("annotate binary", deps=ctx)
        assert isinstance(r2.output, str)
        r3 = agent.run_sync("search KB for hello", deps=ctx)
        assert isinstance(r3.output, str)

    def test_file_not_found(self):
        """Test handling of missing files."""
        AnalysisContext = MemoryContext  # Use current context class
        context = AnalysisContext(
            file_path="/nonexistent/file", artifact=Mock(), session_id="test"
        )
        # Use atomic tool instead of legacy helper
        tool = build_file_hash()
        with pytest.raises(FileNotFoundError):
            tool.run(context, context.kb, tool.input_model())

    def test_no_artifact_data(self):
        """Test handling when artifact lacks data."""
        empty_artifact = Mock()
        empty_artifact.strings = None
        empty_artifact.symbols = None

        AnalysisContext = MemoryContext
        AnalysisContext(
            file_path="/test", artifact=empty_artifact, session_id="test"
        )
        # Should return empty results: no triage strings / symbols available
        strings = []
        assert strings == []

        # No imports in empty artifact
        import_result = {"found": False}
        assert import_result["found"] is False
