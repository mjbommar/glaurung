from __future__ import annotations

from typing import Literal

from pydantic_ai import Agent, RunContext

from ..context import MemoryContext
from ..tools.annotate_binary import build_tool as build_annotate, AnnotateResult
from ..tools.search_kb import build_tool as build_kb_search, KBSearchResult
from ..tools.kb_add_note import build_tool as build_add_note, AddNoteResult
from ..tools.hash_file import build_tool as build_file_hash, FileHashResult
from ..tools.import_triage import build_tool as build_import_triage, TriageImportResult
from ..tools.view_entry import build_tool as build_view_entry, DetectEntryResult
from ..tools.view_symbols import build_tool as build_view_symbols, SymbolsListResult
from ..tools.map_elf_plt import build_tool as build_map_elf_plt, ElfPltMapResult
from ..tools.map_elf_got import build_tool as build_map_elf_got, ElfGotMapResult
from ..tools.map_pe_iat import build_tool as build_map_pe_iat, PeIatMapResult
from ..tools.view_disassembly import (
    build_tool as build_view_disassembly,
    DisasmWindowResult,
)
from ..tools.view_hex import build_tool as build_view_hex, BytesViewResult
from ..tools.view_entropy import build_tool as build_view_entropy, EntropyCalcResult
from ..tools.search_symbols import (
    build_tool as build_search_symbols,
    SymbolsSearchResult,
)
from ..tools.search_strings import (
    build_tool as build_search_strings,
    StringsSearchResult,
)
from ..tools.view_strings import build_tool as build_view_strings, StringsImportResult
from ..tools.list_functions import (
    build_tool as build_list_functions,
    ListFunctionsResult,
)
from ..tools.map_symbol_addresses import (
    build_tool as build_map_symbol_addresses,
    MapSymbolAddressesResult,
)
from ..tools.view_function import build_tool as build_view_function, ViewFunctionResult
from ..tools.suggest_function_name import (
    build_tool as build_name_function,
    SuggestFunctionNameResult,
)
from .memory_foundation import create_foundation_agent


def create_memory_agent(model: str | None = None) -> Agent[MemoryContext, str]:
    agent = create_foundation_agent(model=model)

    # Wrapper functions expose clear schemas and call atomic tools

    async def hash_file(
        ctx: RunContext,
        algorithm: Literal["md5", "sha1", "sha256"] = "sha256",
    ) -> FileHashResult:
        tool = build_file_hash()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model(algorithm=algorithm))

    async def annotate_binary(
        ctx: RunContext,
        max_functions: int = 5,
        snippet_max_instructions: int = 120,
        full_function_instr_threshold: int = 200,
    ) -> AnnotateResult:
        tool = build_annotate()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                max_functions=max_functions,
                snippet_max_instructions=snippet_max_instructions,
                full_function_instr_threshold=full_function_instr_threshold,
            ),
        )

    async def search_kb(
        ctx: RunContext,
        query: str,
        k: int = 10,
    ) -> KBSearchResult:
        tool = build_kb_search()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model(query=query, k=k))

    async def kb_add_note(
        ctx: RunContext,
        text: str,
        tags: list[str] | None = None,
    ) -> AddNoteResult:
        tool = build_add_note()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(text=text, tags=tags or [])
        )

    async def import_triage(
        ctx: RunContext,
        path: str | None = None,
        max_read_bytes: int | None = None,
        max_file_size: int | None = None,
        max_depth: int = 1,
    ) -> TriageImportResult:
        tool = build_import_triage()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                path=path,
                max_read_bytes=max_read_bytes,
                max_file_size=max_file_size,
                max_depth=max_depth,
            ),
        )

    async def view_entry(ctx: RunContext) -> DetectEntryResult:
        tool = build_view_entry()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def view_symbols(ctx: RunContext) -> SymbolsListResult:
        tool = build_view_symbols()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def map_elf_plt(ctx: RunContext) -> ElfPltMapResult:
        tool = build_map_elf_plt()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def map_elf_got(ctx: RunContext) -> ElfGotMapResult:
        tool = build_map_elf_got()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def map_pe_iat(ctx: RunContext) -> PeIatMapResult:
        tool = build_map_pe_iat()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def view_disassembly(
        ctx: RunContext,
        va: int,
        window_bytes: int | None = None,
        max_instructions: int | None = None,
    ) -> DisasmWindowResult:
        tool = build_view_disassembly()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                va=va, window_bytes=window_bytes, max_instructions=max_instructions
            ),
        )

    async def view_strings(
        ctx: RunContext, max_samples: int = 200
    ) -> StringsImportResult:
        tool = build_view_strings()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(max_samples=max_samples)
        )

    async def view_hex(
        ctx: RunContext,
        va: int | None = None,
        file_offset: int | None = None,
        length: int = 64,
    ) -> BytesViewResult:
        tool = build_view_hex()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(va=va, file_offset=file_offset, length=length),
        )

    async def view_entropy(
        ctx: RunContext,
        va: int | None = None,
        file_offset: int | None = None,
        length: int = 4096,
    ) -> EntropyCalcResult:
        tool = build_view_entropy()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(va=va, file_offset=file_offset, length=length),
        )

    async def search_symbols(
        ctx: RunContext,
        query: str,
        where: list[str] | None = None,
        case_sensitive: bool = False,
        regex: bool = False,
        demangle: bool = True,
        max_results: int | None = None,
    ) -> SymbolsSearchResult:
        tool = build_search_symbols()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                query=query,
                where=where or ["all", "imports", "exports"],
                case_sensitive=case_sensitive,
                regex=regex,
                demangle=demangle,
                max_results=max_results,
            ),
        )

    async def name_function(
        ctx: RunContext,
        va: int,
        original_name: str | None = None,
        max_instructions: int = 64,
        use_llm: bool = True,
    ) -> SuggestFunctionNameResult:
        tool = build_name_function()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                va=va,
                original_name=original_name,
                max_instructions=max_instructions,
                use_llm=use_llm,
            ),
        )

    async def list_functions(
        ctx: RunContext, max_functions: int | None = None
    ) -> ListFunctionsResult:
        tool = build_list_functions()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(max_functions=max_functions)
        )

    async def map_symbol_addresses(ctx: RunContext) -> MapSymbolAddressesResult:
        tool = build_map_symbol_addresses()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def view_function(
        ctx: RunContext,
        va: int,
        window_bytes: int | None = None,
        max_instructions: int | None = None,
    ) -> ViewFunctionResult:
        tool = build_view_function()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                va=va, window_bytes=window_bytes, max_instructions=max_instructions
            ),
        )

    async def search_strings(
        ctx: RunContext,
        query: str,
        case_sensitive: bool = False,
        regex: bool = False,
        encodings: list[str] | None = None,
        min_length: int = 4,
        max_results: int | None = None,
        max_scan_bytes: int | None = None,
    ) -> StringsSearchResult:
        tool = build_search_strings()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                query=query,
                case_sensitive=case_sensitive,
                regex=regex,
                encodings=encodings or ["ascii", "utf16le", "utf16be"],
                min_length=min_length,
                max_results=max_results,
                max_scan_bytes=max_scan_bytes,
            ),
        )

    # Register canonical, human-friendly names only
    agent.tool(hash_file, name="hash_file")
    agent.tool(annotate_binary, name="annotate_binary")
    agent.tool(search_kb, name="search_kb")
    agent.tool(kb_add_note, name="kb_add_note")
    agent.tool(import_triage, name="import_triage")
    agent.tool(view_entry, name="view_entry")
    agent.tool(view_symbols, name="view_symbols")
    agent.tool(search_symbols, name="search_symbols")
    agent.tool(view_strings, name="view_strings")
    agent.tool(search_strings, name="search_strings")
    agent.tool(view_hex, name="view_hex")
    agent.tool(view_disassembly, name="view_disassembly")
    agent.tool(view_entropy, name="view_entropy")
    agent.tool(map_elf_plt, name="map_elf_plt")
    agent.tool(map_elf_got, name="map_elf_got")
    agent.tool(map_pe_iat, name="map_pe_iat")
    agent.tool(name_function, name="name_function")
    agent.tool(list_functions, name="list_functions")
    agent.tool(map_symbol_addresses, name="map_symbol_addresses")
    agent.tool(view_function, name="view_function")

    return agent
