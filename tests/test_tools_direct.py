from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.file_hash import build_tool as build_file_hash
from glaurung.llm.tools.annotate_binary import build_tool as build_annotate
from glaurung.llm.tools.kb_search import build_tool as build_kb_search


def test_direct_tools_end_to_end():
    sample = Path("samples/binaries/platforms/linux/amd64/native/clang/O0/hello-clang-O0")
    assert sample.exists(), "sample binary missing"

    art = g.triage.analyze_path(str(sample), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(sample), artifact=art, session_id="t2")
    import_triage(ctx.kb, art, str(sample))

    # hash
    hash_tool = build_file_hash()
    hres = hash_tool.run(ctx, ctx.kb, hash_tool.input_model())
    assert hres.hexdigest and len(hres.hexdigest) in (32, 40, 64)

    # annotate
    ann_tool = build_annotate()
    ares = ann_tool.run(ctx, ctx.kb, ann_tool.input_model())
    assert ares.function_count >= 0

    # search
    s_tool = build_kb_search()
    sres = s_tool.run(ctx, ctx.kb, s_tool.input_model(query="hello", k=10))
    assert isinstance(sres.hits, list)

