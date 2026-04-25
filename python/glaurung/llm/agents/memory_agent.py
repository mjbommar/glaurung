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
from ..tools.decompile_function import (
    build_tool as build_decompile_function,
    DecompileFunctionResult,
)
from ..tools.xrefs import (
    build_xrefs_to as build_list_xrefs_to,
    build_xrefs_from as build_list_xrefs_from,
    XrefResult,
)
from ..tools.list_calls import (
    build_tool as build_list_calls,
    ListCallsResult,
)
from ..tools.get_string_xrefs import (
    build_tool as build_get_string_xrefs,
    StringXrefsResult,
)
from ..tools.rename_in_kb import (
    build_tool as build_rename_in_kb,
    RenameInKBResult,
)
from ..tools.scan_until_byte import (
    build_tool as build_scan_until_byte,
    ScanUntilByteResult,
)
from ..tools.search_byte_pattern import (
    build_tool as build_search_byte_pattern,
    SearchBytePatternResult,
)
from ..tools.list_suspicious_imports import (
    build_tool as build_list_suspicious_imports,
    SuspiciousImportsResult,
)
from ..tools.identify_compiler_and_runtime import (
    build_tool as build_identify_compiler,
    IdentifyCompilerResult,
)
from ..tools.detect_crypto_usage import (
    build_tool as build_detect_crypto,
    DetectCryptoResult,
)
from ..tools.diff_functions import (
    build_tool as build_diff_functions,
    DiffFunctionsResult,
)
from ..tools.propose_types_for_function import (
    build_tool as build_propose_types,
    ProposeTypesResult,
)
from ..tools.extract_archive import (
    build_enumerate_archive,
    EnumerateArchiveResult,
    build_extract_archive_entry,
    ExtractArchiveEntryResult,
    build_extract_archive_all,
    ExtractArchiveAllResult,
    build_recursive_unpack,
    RecursiveUnpackResult,
)
from ..tools.find_embedded_executables import (
    build_tool as build_find_embedded_executables,
    FindEmbeddedExecutablesResult,
)
from ..tools.find_encoded_blobs import (
    build_find_base64_blobs, FindBase64BlobsResult,
    build_find_hex_blobs, FindHexBlobsResult,
    build_find_pem_blocks, FindPemBlocksResult,
    build_try_xor_brute, TryXorBruteResult,
    build_scan_xor_encoded_strings, ScanXorEncodedStringsResult,
    build_find_compressed_blobs, FindCompressedBlobsResult,
)
from ..tools.find_structured_blobs import (
    build_find_embedded_images, FindEmbeddedImagesResult,
    build_find_xml_blobs, FindXmlBlobsResult,
    build_find_json_blobs, FindJsonBlobsResult,
    build_find_plist_blobs, FindPlistBlobsResult,
    build_find_ini_blobs, FindIniBlobsResult,
    build_extract_pe_overlay, ExtractPeOverlayResult,
    build_extract_elf_section, ExtractElfSectionResult,
)
from ..tools.analyze_recursively import (
    build_tool as build_analyze_recursively,
    AnalyzeRecursivelyResult,
)
from .memory_foundation import create_foundation_agent


def register_analysis_tools(agent: Agent) -> Agent:
    """Register glaurung's memory/analysis tools onto an existing Agent.

    Pulled out of :func:`create_memory_agent` so specialised agents
    (FunctionExplainAgent, VulnerabilityHuntAgent, …) can reuse the
    exact same tool surface while supplying their own system prompt
    and output schema.
    """
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

    async def decompile_function(
        ctx: RunContext, va: int, style: str = "c", timeout_ms: int = 500
    ) -> DecompileFunctionResult:
        tool = build_decompile_function()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(va=va, style=style, timeout_ms=timeout_ms),
        )

    async def list_xrefs_to(
        ctx: RunContext, va: int, max_results: int = 32
    ) -> XrefResult:
        tool = build_list_xrefs_to()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(va=va, max_results=max_results)
        )

    async def list_xrefs_from(
        ctx: RunContext, va: int, max_results: int = 32
    ) -> XrefResult:
        tool = build_list_xrefs_from()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(va=va, max_results=max_results)
        )

    async def list_calls_from_function(
        ctx: RunContext, func_va: int, max_results: int = 64
    ) -> ListCallsResult:
        tool = build_list_calls()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(func_va=func_va, max_results=max_results),
        )

    async def get_string_xrefs(
        ctx: RunContext,
        query: str,
        case_sensitive: bool = False,
        regex: bool = False,
        max_functions: int = 64,
    ) -> StringXrefsResult:
        tool = build_get_string_xrefs()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                query=query,
                case_sensitive=case_sensitive,
                regex=regex,
                max_functions=max_functions,
            ),
        )

    async def rename_in_kb(
        ctx: RunContext,
        entry_va: int,
        new_name: str,
        rationale: str | None = None,
    ) -> RenameInKBResult:
        tool = build_rename_in_kb()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                entry_va=entry_va, new_name=new_name, rationale=rationale
            ),
        )

    async def search_byte_pattern(
        ctx: RunContext,
        pattern: str,
        max_results: int = 64,
        resolve_va: bool = True,
    ) -> SearchBytePatternResult:
        tool = build_search_byte_pattern()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                pattern=pattern, max_results=max_results, resolve_va=resolve_va
            ),
        )

    async def kickoff_analysis(
        ctx: RunContext,
        max_functions: int = 64,
        analyze_packed: bool = False,
    ) -> dict:
        """Run the canonical first-touch pipeline on the binary in
        scope: detect_packer + triage + analyze_functions + index +
        demangle + per-function stack-frame discovery + type
        propagation + auto-struct recovery. Returns a structured
        summary suitable for the agent's opening message. Idempotent
        when re-run on the same KB."""
        from glaurung.llm.kb.kickoff import kickoff_analysis as _kickoff
        from dataclasses import asdict
        # Best-effort: route through the context's persistent KB if
        # available, else run with a tmp DB.
        db_path = getattr(ctx.deps, "db_path", None)
        summary = _kickoff(
            str(ctx.deps.file_path),
            db_path=db_path,
            max_functions_for_kb_lift=max_functions,
            skip_if_packed=not analyze_packed,
        )
        return asdict(summary)

    async def scan_until_byte(
        ctx: RunContext,
        va: int | None = None,
        file_offset: int | None = None,
        sentinels: list[int] | None = None,
        max_scan_bytes: int = 4096,
        include_sentinel: bool = False,
    ) -> ScanUntilByteResult:
        tool = build_scan_until_byte()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                va=va,
                file_offset=file_offset,
                sentinels=sentinels if sentinels is not None else [0x00],
                max_scan_bytes=max_scan_bytes,
                include_sentinel=include_sentinel,
            ),
        )

    async def list_suspicious_imports(
        ctx: RunContext, include_util: bool = False
    ) -> SuspiciousImportsResult:
        tool = build_list_suspicious_imports()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(include_util=include_util)
        )

    async def identify_compiler_and_runtime(
        ctx: RunContext,
    ) -> IdentifyCompilerResult:
        tool = build_identify_compiler()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def detect_crypto_usage(ctx: RunContext) -> DetectCryptoResult:
        tool = build_detect_crypto()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model())

    async def diff_functions(
        ctx: RunContext,
        va_a: int,
        va_b: int,
        path_a: str | None = None,
        path_b: str | None = None,
        style: str = "c",
    ) -> DiffFunctionsResult:
        tool = build_diff_functions()
        return tool.run(
            ctx.deps,
            ctx.deps.kb,
            tool.input_model(
                va_a=va_a, va_b=va_b, path_a=path_a, path_b=path_b, style=style
            ),
        )

    async def propose_types_for_function(
        ctx: RunContext, va: int, use_llm: bool = True
    ) -> ProposeTypesResult:
        tool = build_propose_types()
        return tool.run(
            ctx.deps, ctx.deps.kb, tool.input_model(va=va, use_llm=use_llm)
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
    # Tier-1 analysis additions (xrefs / decompile / pattern-hunt / rename / triage)
    agent.tool(decompile_function, name="decompile_function")
    agent.tool(list_xrefs_to, name="list_xrefs_to")
    agent.tool(list_xrefs_from, name="list_xrefs_from")
    agent.tool(list_calls_from_function, name="list_calls_from_function")
    agent.tool(get_string_xrefs, name="get_string_xrefs")
    agent.tool(rename_in_kb, name="rename_in_kb")
    agent.tool(search_byte_pattern, name="search_byte_pattern")
    agent.tool(scan_until_byte, name="scan_until_byte")
    agent.tool(kickoff_analysis, name="kickoff_analysis")
    agent.tool(list_suspicious_imports, name="list_suspicious_imports")
    agent.tool(identify_compiler_and_runtime, name="identify_compiler_and_runtime")
    agent.tool(detect_crypto_usage, name="detect_crypto_usage")
    agent.tool(diff_functions, name="diff_functions")
    agent.tool(propose_types_for_function, name="propose_types_for_function")

    # Embedded-content tools (Sprint 1) — archive extraction + magic scan.
    async def enumerate_archive(
        ctx: RunContext, path: str
    ) -> EnumerateArchiveResult:
        tool = build_enumerate_archive()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model(path=path))

    async def extract_archive_entry(
        ctx: RunContext,
        path: str,
        entry_name: str,
        out_path: str | None = None,
    ) -> ExtractArchiveEntryResult:
        tool = build_extract_archive_entry()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, entry_name=entry_name, out_path=out_path),
        )

    async def extract_archive_all(
        ctx: RunContext,
        path: str,
        out_dir: str,
        max_files: int = 64,
        max_bytes: int = 256 * 1024 * 1024,
    ) -> ExtractArchiveAllResult:
        tool = build_extract_archive_all()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, out_dir=out_dir,
                max_files=max_files, max_bytes=max_bytes,
            ),
        )

    async def recursive_unpack(
        ctx: RunContext,
        path: str,
        out_dir: str,
        max_depth: int = 4,
        max_total_bytes: int = 256 * 1024 * 1024,
    ) -> RecursiveUnpackResult:
        tool = build_recursive_unpack()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, out_dir=out_dir,
                max_depth=max_depth, max_total_bytes=max_total_bytes,
            ),
        )

    async def find_embedded_executables(
        ctx: RunContext,
        path: str,
        skip_first_match: bool = True,
        max_results: int = 64,
    ) -> FindEmbeddedExecutablesResult:
        tool = build_find_embedded_executables()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, skip_first_match=skip_first_match,
                max_results=max_results,
            ),
        )

    agent.tool(enumerate_archive, name="enumerate_archive")
    agent.tool(extract_archive_entry, name="extract_archive_entry")
    agent.tool(extract_archive_all, name="extract_archive_all")
    agent.tool(recursive_unpack, name="recursive_unpack")
    agent.tool(find_embedded_executables, name="find_embedded_executables")

    # Embedded-content Sprint 2 — encoded-blob detection
    async def find_base64_blobs(
        ctx: RunContext, path: str, min_len: int = 32, max_results: int = 64,
    ) -> FindBase64BlobsResult:
        tool = build_find_base64_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, min_len=min_len, max_results=max_results),
        )

    async def find_hex_blobs(
        ctx: RunContext, path: str, min_bytes: int = 64, max_results: int = 32,
    ) -> FindHexBlobsResult:
        tool = build_find_hex_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, min_bytes=min_bytes, max_results=max_results),
        )

    async def find_pem_blocks(
        ctx: RunContext, path: str, max_results: int = 32,
    ) -> FindPemBlocksResult:
        tool = build_find_pem_blocks()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, max_results=max_results),
        )

    async def try_xor_brute(
        ctx: RunContext, path: str, offset: int = 0,
        length: int = 256, top_k: int = 3,
    ) -> TryXorBruteResult:
        tool = build_try_xor_brute()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, offset=offset, length=length, top_k=top_k,
            ),
        )

    async def scan_xor_encoded_strings(
        ctx: RunContext, path: str, window: int = 32,
        stride: int = 8, min_score: float = 0.06, max_results: int = 32,
    ) -> ScanXorEncodedStringsResult:
        tool = build_scan_xor_encoded_strings()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, window=window, stride=stride,
                min_score=min_score, max_results=max_results,
            ),
        )

    async def find_compressed_blobs(
        ctx: RunContext, path: str, max_results: int = 32, probe_bytes: int = 4096,
    ) -> FindCompressedBlobsResult:
        tool = build_find_compressed_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, max_results=max_results, probe_bytes=probe_bytes,
            ),
        )

    agent.tool(find_base64_blobs, name="find_base64_blobs")
    agent.tool(find_hex_blobs, name="find_hex_blobs")
    agent.tool(find_pem_blocks, name="find_pem_blocks")
    agent.tool(try_xor_brute, name="try_xor_brute")
    agent.tool(scan_xor_encoded_strings, name="scan_xor_encoded_strings")
    agent.tool(find_compressed_blobs, name="find_compressed_blobs")

    # Embedded-content Sprint 3 — structured-blob + resource extraction
    async def find_embedded_images(
        ctx: RunContext, path: str, max_results: int = 32,
    ) -> FindEmbeddedImagesResult:
        tool = build_find_embedded_images()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, max_results=max_results),
        )

    async def find_xml_blobs(
        ctx: RunContext, path: str, max_results: int = 16,
    ) -> FindXmlBlobsResult:
        tool = build_find_xml_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, max_results=max_results),
        )

    async def find_json_blobs(
        ctx: RunContext, path: str, min_size: int = 64, max_results: int = 16,
    ) -> FindJsonBlobsResult:
        tool = build_find_json_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, min_size=min_size, max_results=max_results),
        )

    async def find_plist_blobs(
        ctx: RunContext, path: str, max_results: int = 16,
    ) -> FindPlistBlobsResult:
        tool = build_find_plist_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, max_results=max_results),
        )

    async def find_ini_blobs(
        ctx: RunContext, path: str, min_sections: int = 2, max_results: int = 16,
    ) -> FindIniBlobsResult:
        tool = build_find_ini_blobs()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, min_sections=min_sections, max_results=max_results,
            ),
        )

    async def extract_pe_overlay(
        ctx: RunContext, path: str,
    ) -> ExtractPeOverlayResult:
        tool = build_extract_pe_overlay()
        return tool.run(ctx.deps, ctx.deps.kb, tool.input_model(path=path))

    async def extract_elf_section(
        ctx: RunContext, path: str, section_name: str,
    ) -> ExtractElfSectionResult:
        tool = build_extract_elf_section()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(path=path, section_name=section_name),
        )

    agent.tool(find_embedded_images, name="find_embedded_images")
    agent.tool(find_xml_blobs, name="find_xml_blobs")
    agent.tool(find_json_blobs, name="find_json_blobs")
    agent.tool(find_plist_blobs, name="find_plist_blobs")
    agent.tool(find_ini_blobs, name="find_ini_blobs")
    agent.tool(extract_pe_overlay, name="extract_pe_overlay")
    agent.tool(extract_elf_section, name="extract_elf_section")

    # Embedded-content Sprint 4 — recursive triage orchestrator. Composes
    # every sprint 1-3 scanner into one "what's actually inside this file?"
    # walk, returning a tree of triage nodes.
    async def analyze_recursively(
        ctx: RunContext,
        path: str,
        out_dir: str | None = None,
        max_depth: int = 4,
        max_total_bytes: int = 256 * 1024 * 1024,
        max_nodes: int = 200,
    ) -> AnalyzeRecursivelyResult:
        tool = build_analyze_recursively()
        return tool.run(
            ctx.deps, ctx.deps.kb,
            tool.input_model(
                path=path, out_dir=out_dir,
                max_depth=max_depth, max_total_bytes=max_total_bytes,
                max_nodes=max_nodes,
            ),
        )

    agent.tool(analyze_recursively, name="analyze_recursively")

    return agent


def create_memory_agent(model: str | None = None) -> Agent[MemoryContext, str]:
    """Foundation string-output agent with every analysis tool registered."""
    agent = create_foundation_agent(model=model)
    return register_analysis_tools(agent)
