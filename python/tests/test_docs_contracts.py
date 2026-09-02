"""Behavioral contracts that Phase 5b reference docs depend on.

`docs/development/docs-audit-2026-09-02/contract-assertions.md` rescued a
minority of genuinely behavioral claims from ten tests deleted from
`test_verify_tutorial.py` in Phase 1. Those old tests pinned literal prose
(banner text, refresh dates, commit SHAs); the point of the rewrite is that a
maintained document states a fact and a test checks the underlying CODE fact,
not the document's wording. See plan principle 3.10.

Each test below asserts a fact about the code that a `docs/reference/*.md`
file this phase owns depends on. When the code changes in a way that breaks
one of these, the test fails and the doc must be updated in the same change
-- the doc is not re-checked by parsing its own prose except where the claim
is genuinely about the doc's own content (e.g. "does not mention gpt-4").

A `PENDING` list of contracts whose target document is still being written by
another phase is at the bottom of this file, as comments only, per the task
brief -- Phase 8 enables them once those docs land.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PY = ROOT / "python" / "glaurung"
TOOLS = PY / "llm" / "tools"
DOCS_REF = ROOT / "docs" / "reference"


def _read(path: Path) -> str:
    assert path.exists(), f"missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# reference/disassembly.md  (contracts C1, C2, C31)
# ---------------------------------------------------------------------------


def test_disasm_comments_flag_is_a_no_op() -> None:
    """C1: `--comments` currently adds no annotations.

    `_get_instruction_comment` is the hook `--comments` calls; it is a
    literal `return None`. If this ever returns something, disassembly.md's
    "currently does not add annotations" sentence becomes false.
    """
    src = _read(PY / "cli" / "commands" / "disasm.py")
    m = re.search(
        r"def _get_instruction_comment\(.*?\n(?:.*\n)*?\s*return (\w+)",
        src,
    )
    assert m is not None, "_get_instruction_comment not found in disasm.py"
    assert m.group(1) == "None", (
        "_get_instruction_comment no longer returns None -- "
        "docs/reference/disassembly.md's --comments claim needs updating"
    )


def test_disasm_engine_field_ignores_backend_selection() -> None:
    """C2 (JSON field half): `engine` in JSON output is not backend provenance.

    disassembly.md says the JSON `engine` field reports `iced-x86` for `auto`
    even when Capstone was actually selected. That is this exact expression.
    """
    src = _read(PY / "cli" / "commands" / "disasm.py")
    assert '"engine": args.engine if args.engine != "auto" else "iced-x86"' in src


def test_disasm_mapped_va_path_has_no_engine_or_arch_parameter() -> None:
    """C2 (wiring half): the mapped-VA path used for entry/--addr does not
    accept `--engine`/`--arch`. disassemble_window_at's signature is the
    proof: no engine/arch parameter for `--engine`/`--arch` to reach.
    """
    stub = _read(PY / "_native" / "disasm.pyi")
    m = re.search(r"def disassemble_window_at\(([^)]*)\)", stub)
    assert m is not None
    params = m.group(1)
    assert "engine" not in params
    assert "arch" not in params


def test_disasm_default_resource_bounds() -> None:
    """disassembly.md's stated defaults: 8192 / 2048 / 5000."""
    src = _read(PY / "cli" / "commands" / "disasm.py")
    assert '"--window-bytes"' in src
    assert "default=8192" in src
    assert "default=2048" in src
    assert "default=5_000" in src


def test_disasm_engine_registry_backend_split() -> None:
    """disassembly.md's engine table: iced for x86/x86-64, Capstone for the
    rest of the listed architectures.
    """
    src = _read(SRC / "disasm" / "registry.rs")
    m = re.search(
        r"Architecture::X86 \| Architecture::X86_64 => Some\(Backend::Iced",
        src,
    )
    assert m is not None
    m2 = re.search(
        r"Architecture::ARM\s*\n\s*\| Architecture::ARM64\s*\n\s*"
        r"\| Architecture::MIPS\s*\n\s*\| Architecture::MIPS64\s*\n\s*"
        r"\| Architecture::PPC\s*\n\s*\| Architecture::PPC64\s*\n\s*"
        r"\| Architecture::RISCV\s*\n\s*\| Architecture::RISCV64",
        src,
    )
    assert m2 is not None, "Capstone architecture list drifted from the doc's list"


def test_disassembly_doc_carries_no_survey_material() -> None:
    """C31: disassembly.md does not carry the deleted 2025 competitor survey."""
    text = _read(DOCS_REF / "disassembly.md")
    assert "zydis" not in text.lower()
    assert "quantum" not in text.lower()


# ---------------------------------------------------------------------------
# reference/language-detection.md  (contract C3)
# ---------------------------------------------------------------------------


def test_language_detection_is_not_a_cli_command() -> None:
    """C3: language/compiler detection is not a standalone CLI command."""
    src = _read(PY / "cli" / "main.py")
    m = re.search(r"_REGISTRY:\s*dict.*?=\s*\{(.*?)\n\}", src, re.S)
    assert m is not None, "could not locate _REGISTRY in cli/main.py"
    assert "language" not in m.group(1)


def test_language_detection_public_surface() -> None:
    """language-detection.md names these functions and the enum shape."""
    src = _read(SRC / "triage" / "compiler_detection.rs")
    assert "pub fn detect_language_and_compiler(" in src
    assert "pub fn detect_language_and_compiler_with_path(" in src
    enum_match = re.search(r"pub enum SourceLanguage \{(.*?)\n\}", src, re.S)
    assert enum_match is not None
    variants = [
        line.strip().rstrip(",")
        for line in enum_match.group(1).splitlines()
        if line.strip() and not line.strip().startswith("//")
    ]
    # 20 named languages + Unknown, per the doc's "20 ... and Unknown" claim.
    assert len(variants) == 21, variants
    assert variants[-1] == "Unknown"


def test_language_detection_rust_tests_exist() -> None:
    assert (ROOT / "tests" / "compiler_detection_test.rs").exists()
    assert (ROOT / "tests" / "compiler_detection_comprehensive.rs").exists()


# ---------------------------------------------------------------------------
# reference/packer-config.md  (contract C29)
# ---------------------------------------------------------------------------


def test_packer_config_defaults() -> None:
    """packer-config.md's documented PackerConfig defaults."""
    src = _read(SRC / "triage" / "config.rs")
    assert "scan_limit: 524288" in src
    assert "upx_detection_weight: 0.6" in src
    assert "upx_version_weight: 0.2" in src
    assert "packer_signal_weight: 0.30" in src


def test_packer_config_examples_use_the_public_module() -> None:
    """C29: examples import `from glaurung import triage`, the public surface."""
    text = _read(DOCS_REF / "packer-config.md")
    assert "from glaurung import triage" in text


# ---------------------------------------------------------------------------
# reference/similarity.md  (contract C28)
# ---------------------------------------------------------------------------


def test_similarity_ctph_size_breakpoints() -> None:
    """similarity.md's size -> (window, digest bytes, precision) table."""
    src = _read(SRC / "python_bindings" / "similarity.rs")
    m = re.search(
        r"if length < 16 \* 1024 \{\s*\(8, 4, 8\)\s*\}\s*else if length < 1 \* 1024 \* 1024 \{\s*"
        r"\(16, 5, 16\)\s*\}\s*else \{\s*\(32, 6, 16\)\s*\}",
        src,
    )
    assert m is not None, "ctph_recommended_params breakpoints drifted"


def test_similarity_doc_uses_real_corpus_binary() -> None:
    """C28: similarity examples use a real corpus binary, no digest_list API."""
    text = _read(DOCS_REF / "similarity.md")
    assert "hello-gcc-O2" in text or "hello-clang-O2" in text
    assert "digest_list" not in text


# ---------------------------------------------------------------------------
# reference/windows-analysis-config.md  (contract C25)
# ---------------------------------------------------------------------------


def test_windows_analysis_config_fields_and_defaults() -> None:
    """C25: names python/glaurung/windows_config.py; defaults match the doc."""
    src = _read(PY / "windows_config.py")
    assert "class WindowsAnalysisConfig" in src
    for field, default in (
        ("max_read_bytes", "104_857_600"),
        ("max_blocks", "1_000_000"),
        ("max_instructions", "30_000_000"),
        ("timeout_ms", "600_000"),
        ("total_timeout_ms", "0"),
    ):
        assert re.search(rf"{field}:\s*int\s*=\s*{default}", src), field


def test_windows_analysis_config_resolution_order() -> None:
    """explicit path -> env var -> .glaurung/windows-analysis.yaml -> defaults."""
    src = _read(PY / "windows_config.py")
    m = re.search(r"def _resolve_config_path.*?(?=\ndef |\Z)", src, re.S)
    assert m is not None
    body = m.group(0)
    assert body.index("if path:") < body.index("env_path = os.environ.get")
    assert body.index("env_path = os.environ.get") < body.index(
        "DEFAULT_CONFIG_PATH.exists()"
    )


# ---------------------------------------------------------------------------
# reference/windows-api-type-sync.md  (contract C26)
# ---------------------------------------------------------------------------


def test_types_sync_flags_exist() -> None:
    src = _read(PY / "cli" / "commands" / "types.py")
    for flag in (
        "--source-lock",
        "--overlay",
        "--output",
        "--generated-dir",
        "--cache-dir",
        "--header",
        "--clang",
        "--clang-arg",
        "--offline",
        "--no-overlays",
    ):
        assert flag in src, flag


def test_windows_type_sync_examples_use_the_repository_entrypoint() -> None:
    """C26: never a bare `glaurung types sync` -- always `uv run glaurung ...`."""
    text = _read(DOCS_REF / "windows-api-type-sync.md")
    for m in re.finditer(r"^[^\n`]*\bglaurung types sync\b", text, re.M):
        line = m.group(0)
        assert "uv run glaurung types sync" in line, line


# ---------------------------------------------------------------------------
# reference/ioc-validator.md  (contract C21 + V1 status)
# ---------------------------------------------------------------------------


def test_ioc_validator_v2_symbols() -> None:
    src = _read(PY / "llm" / "agents" / "ioc_validator_v2.py")
    for name in (
        "class IOCType",
        "class IOCCandidate",
        "class IOCValidationDecision",
        "class IOCValidationOutput",
        "class ValidatedIOC",
        "def create_ioc_validator_v2",
        "def validate_iocs_v2",
        "def filter_iocs_from_artifact_v2",
    ):
        assert name in src, name


def test_ioc_validator_v2_duplicate_index_rejected() -> None:
    src = _read(PY / "llm" / "agents" / "ioc_validator_v2.py")
    assert "Duplicate validation for index" in src


def test_ioc_validator_v2_slices_before_filtering_by_kind() -> None:
    """The doc's compatibility-limitation claim: batch slicing happens before
    kind filtering, and unrecognized kinds fall back to IOCType.HOSTNAME.
    """
    src = _read(PY / "llm" / "agents" / "ioc_validator_v2.py")
    m = re.search(r"for s in artifact\.strings\.ioc_samples\[:max_batch_size\]:", src)
    assert m is not None
    assert "ioc_type_map.get(s.kind, IOCType.HOSTNAME)" in src


def test_ioc_validator_v1_exists_but_is_unused() -> None:
    """New V1-status line: V1 exists, has a test file, but no production
    caller outside itself uses it -- every caller uses V2.
    """
    v1 = PY / "llm" / "agents" / "ioc_validator.py"
    assert v1.exists()
    assert (ROOT / "python" / "tests" / "test_ioc_validator.py").exists()
    callers = []
    for path in PY.rglob("*.py"):
        if path == v1:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if (
            "agents.ioc_validator import" in text
            or "agents import ioc_validator" in text
        ):
            callers.append(path)
    assert callers == [], f"V1 gained a caller, update ioc-validator.md: {callers}"


# ---------------------------------------------------------------------------
# reference/formats/*.md  (contracts C16, C17, C18)
# ---------------------------------------------------------------------------


def test_android_elf_and_cfg_functions_exist() -> None:
    elf_src = _read(SRC / "formats" / "elf" / "mod.rs")
    assert "pub fn android_packed_relocations(" in elf_src
    assert "pub fn relr_relocations(" in elf_src
    cfg_src = _read(SRC / "analysis" / "cfg.rs")
    assert "scan_aarch64_prologue_function_starts" in cfg_src


def test_android_dex_axml_apk_symbols_exist() -> None:
    dex_src = _read(SRC / "formats" / "dex" / "mod.rs")
    assert "pub fn class_names(" in dex_src
    assert "pub fn method_signature(" in dex_src
    axml_src = _read(SRC / "formats" / "axml" / "manifest.rs")
    assert "pub struct ManifestSummary" in axml_src
    apk_src = _read(SRC / "formats" / "apk" / "mod.rs")
    assert "pub struct ApkReader" in apk_src


def test_android_ioctl_surface_symbols_exist() -> None:
    src = _read(SRC / "analysis" / "linux_ioctl.rs")
    assert "pub struct IocDecoded" in src
    assert "pub fn decode_ioc(" in src


def test_android_focused_tests_exist() -> None:
    for name in (
        "android_dex_triage",
        "android_packed_relocations",
        "android_pac_bti_cfg",
        "android_pac_stripped_discovery",
    ):
        assert (ROOT / "tests" / f"{name}.rs").exists(), name


def test_sepolicy_implements_only_header_and_magic_detection() -> None:
    """C18: sepolicy "currently implements only" header/magic parsing.

    If `avtab`, symbol-table, or reachability-query code lands in
    src/formats/sepolicy/, this test breaks and
    reference/formats/sepolicy-policydb-format.md's "next slice" framing (and
    reference/formats/android.md's "magic and header parsing only" row) need
    updating together.
    """
    src = _read(SRC / "formats" / "sepolicy" / "mod.rs")
    public_fns = set(re.findall(r"^pub fn (\w+)", src, re.M))
    assert public_fns == {"is_sepolicy", "parse_header"}, public_fns


def test_sepolicy_fixtures_exist() -> None:
    for name in ("sepolicy.30", "sepolicy.33", "sepolicy.35", "sepolicy_nomls.33"):
        assert (ROOT / "tests" / "fixtures" / "android" / name).exists(), name


# ---------------------------------------------------------------------------
# reference/syscalls/*.md  (contracts C19, C20)
# ---------------------------------------------------------------------------


def test_linux_syscall_instruction_classification() -> None:
    src = _read(SRC / "core" / "instruction.rs")
    assert '"syscall" | "sysenter" | "int" | "svc"' in src


def test_linux_syscalls_doc_states_current_boundary_not_full_emulation() -> None:
    """C19: states the current boundary, not full syscall emulation."""
    text = _read(DOCS_REF / "syscalls" / "linux.md")
    assert "Current Glaurung boundary" in text
    assert "does **not** ship a complete" in text


def test_windows_syscall_tool_names_are_real() -> None:
    """C20: names windows_syscall_stub_atlas and siblings; no runtime-resolve claim."""
    names = {
        "windows_syscall_stub_atlas": "windows_syscall_stub_atlas.py",
        "windows_syscall_atlas_diff": "windows_syscall_atlas_diff.py",
        "windows_syscall_handler_correlate": "windows_syscall_handler_correlate.py",
        "windows_live_kernel_snapshot": "windows_live_kernel_snapshot.py",
    }
    for tool_name, filename in names.items():
        src = _read(TOOLS / filename)
        assert f'name="{tool_name}"' in src
    text = _read(DOCS_REF / "syscalls" / "windows.md")
    assert "does not hook or modify a" in text


# ---------------------------------------------------------------------------
# reference/llm-tool-contract.md  (contracts C22, C23, C24)
# ---------------------------------------------------------------------------


def test_llm_tool_contract_core_symbols_exist() -> None:
    assert "class MemoryTool" in _read(PY / "llm" / "tools" / "base.py")
    assert "def tool_to_pyd_ai" in _read(PY / "llm" / "tools" / "base.py")
    assert "class MemoryContext" in _read(PY / "llm" / "context.py")
    assert "def register_analysis_tools" in _read(
        PY / "llm" / "agents" / "memory_agent.py"
    )


def test_llm_tool_routing_symbols_exist() -> None:
    src = _read(PY / "llm" / "tool_routing.py")
    assert "def route_for_question" in src
    assert "def select_tools_for_question" in src


def test_no_gpt4_or_fabricated_symbol_in_tool_contract_doc() -> None:
    """C23: no gpt-4, and no create_binary_analysis_agent_with_tools anywhere."""
    text = _read(DOCS_REF / "llm-tool-contract.md")
    assert "gpt-4" not in text.lower()
    assert "create_binary_analysis_agent_with_tools" not in text
    for path in PY.rglob("*.py"):
        assert "create_binary_analysis_agent_with_tools" not in path.read_text(
            encoding="utf-8", errors="ignore"
        )


def test_no_mocks_in_tool_contract_examples() -> None:
    """C24 (doc-example half): no unittest.mock / MagicMock in this guide."""
    text = _read(DOCS_REF / "llm-tool-contract.md")
    assert "unittest.mock" not in text
    assert "MagicMock" not in text


def test_gen_test_facets_is_named_in_the_tool_checklist() -> None:
    """Tool-addition checklist references the facet generator (65ff0a24)."""
    text = _read(DOCS_REF / "llm-tool-contract.md")
    assert "gen_test_facets.py" in text
    assert (ROOT / "tools" / "gen_test_facets.py").exists()


# ---------------------------------------------------------------------------
# reference/llm-embedded-content-tools.md
# ---------------------------------------------------------------------------


def test_embedded_content_shipped_tool_files_exist() -> None:
    for filename, tool_names in {
        "extract_archive.py": (
            "enumerate_archive",
            "extract_archive_entry",
            "extract_archive_all",
            "recursive_unpack",
        ),
        "find_embedded_executables.py": ("find_embedded_executables",),
        "find_encoded_blobs.py": (
            "find_base64_blobs",
            "find_hex_blobs",
            "find_pem_blocks",
            "try_xor_brute",
            "find_compressed_blobs",
        ),
        "find_structured_blobs.py": (
            "find_embedded_images",
            "find_xml_blobs",
            "find_json_blobs",
            "find_plist_blobs",
            "find_ini_blobs",
            "extract_pe_overlay",
            "extract_elf_section",
        ),
        "analyze_recursively.py": ("analyze_recursively",),
        "pe_list_resources.py": ("pe_list_resources",),
    }.items():
        src = _read(TOOLS / filename)
        for tool_name in tool_names:
            assert f'name="{tool_name}"' in src, (filename, tool_name)


def test_embedded_content_tools_registered_in_memory_agent() -> None:
    src = _read(PY / "llm" / "agents" / "memory_agent.py")
    for tool_name in (
        "enumerate_archive",
        "find_embedded_executables",
        "find_base64_blobs",
        "find_json_blobs",
        "analyze_recursively",
    ):
        assert f'name="{tool_name}"' in src, tool_name


def test_no_recursive_triage_agent_module() -> None:
    """The doc corrects a false claim: there is no recursive_triage.py agent
    or BinaryTriageAgent class -- analyze_recursively is one more MemoryTool.
    """
    assert not (PY / "llm" / "agents" / "recursive_triage.py").exists()
    src = _read(PY / "llm" / "agents" / "specialized.py")
    assert "class BinaryTriageAgent" not in src


# ---------------------------------------------------------------------------
# reference/llm-source-recovery-tools.md
# ---------------------------------------------------------------------------


SOURCE_RECOVERY_TOOL_FILES = (
    "classify_string_purpose",
    "classify_constant",
    "name_string_literal",
    "classify_loop_idiom",
    "name_local_variable",
    "describe_call_site",
    "recover_struct_layout",
    "recover_enum",
    "recover_error_model",
    "infer_function_signature",
    "hypothesize_protocol",
    "recover_cli_grammar",
    "classify_function_role",
    "rewrite_function_idiomatic",
    "synthesize_docstring",
    "propose_function_name_post_rewrite",  # step 16, shipped name differs
    "verify_semantic_equivalence",
    "cluster_functions_into_modules",
    "reconcile_function_identity",
    "reconcile_global_naming",
    "infer_build_system",
    "write_readme_and_manpage",
    "audit_recovered_source",
    "translate_language",
    "explain_rewrite_delta",
)


def test_source_recovery_ladder_files_exist() -> None:
    """24 of the 25 ladder steps ship as a same-named file; step 16
    (propose_function_name) ships under a different name -- see below.
    """
    for name in SOURCE_RECOVERY_TOOL_FILES:
        assert (TOOLS / f"{name}.py").exists(), name


def test_source_recovery_extra_verify_tools_are_deterministic() -> None:
    """`verify_recovery_tool.py` ships verify_compile/verify_runtime as one
    more tool, outside the 25-step ladder and registered separately in
    register_analysis_tools -- deterministic recompile/re-run checks, not an
    LLM equivalence judgement (that is step 17, verify_semantic_equivalence,
    which ships too and is asserted above).
    """
    src = _read(TOOLS / "verify_recovery_tool.py")
    assert 'name="verify_compile"' in src
    assert 'name="verify_runtime"' in src
    agent_src = _read(PY / "llm" / "agents" / "memory_agent.py")
    assert 'name="verify_compile"' in agent_src
    assert 'name="verify_runtime"' in agent_src


def test_source_recovery_orchestrated_by_script_not_agent_classes() -> None:
    """scripts/recover_source.py is the real orchestrator; the doc's
    Implementation-notes claim about per-phase agent classes in
    specialized.py is false and was corrected.
    """
    assert (ROOT / "scripts" / "recover_source.py").exists()
    src = _read(PY / "llm" / "agents" / "specialized.py")
    for missing in (
        "LayerZeroLabelerAgent",
        "StructureRecoveryAgent",
        "FunctionRewriteAgent",
        "ProjectAssemblyAgent",
        "AuditAgent",
    ):
        assert missing not in src


def test_recover_source_script_imports_the_ladder_tools() -> None:
    src = _read(ROOT / "scripts" / "recover_source.py")
    assert "from glaurung.llm.tools.audit_recovered_source import" in src
    assert "from glaurung.llm.tools.rewrite_function_idiomatic import" in src


def test_propose_types_for_function_is_registered_and_documented() -> None:
    """Extra tool beyond the 25-step ladder, registered separately."""
    assert (TOOLS / "propose_types_for_function.py").exists()
    src = _read(PY / "llm" / "agents" / "memory_agent.py")
    assert 'name="propose_types_for_function"' in src


# ---------------------------------------------------------------------------
# reference/sample-corpus.md
# ---------------------------------------------------------------------------


def test_sample_corpus_doc_paths_exist_on_disk() -> None:
    """Every `samples/...` path cited in sample-corpus.md resolves in the
    current checkout. Git LFS is installed, so these must be real files, not
    130-byte pointer stubs.
    """
    text = _read(DOCS_REF / "sample-corpus.md")
    paths = set(re.findall(r"`(samples/[^`]+)`", text))
    assert len(paths) > 20, "expected the full curated map, found too few paths"
    missing = [p for p in sorted(paths) if not (ROOT / p).exists()]
    assert missing == [], missing


def test_sample_corpus_go_binary_is_a_real_elf_not_an_lfs_pointer() -> None:
    # Path deliberately written as one literal string (not chained `/`) so
    # `tools/gen_test_facets.py`'s dumb text rule tags this file `lfs`.
    path = ROOT / "samples/binaries/platforms/linux/amd64/export/go/hello-go"
    data = path.read_bytes()[:4]
    assert data == b"\x7fELF", "looks like an unmaterialized Git LFS pointer file"


# ---------------------------------------------------------------------------
# development/decompiler-testing.md  (contract C14, @exceptions fix)
# ---------------------------------------------------------------------------


def test_decompiler_testing_doc_examples_name_real_dectest_sets() -> None:
    """The `@exceptions` set named in an old example did not exist in
    sets.toml; it was replaced with `@dispatch-forms`. This asserts every
    `@<name>` selector in the doc names a real `[<name>]` table in
    tests/decompiler_fixtures/sets.toml.
    """
    sets_toml = _read(ROOT / "tests" / "decompiler_fixtures" / "sets.toml")
    real_sets = set(re.findall(r"^\[([\w-]+)\]", sets_toml, re.M))
    text = _read(ROOT / "docs" / "development" / "decompiler-testing.md")
    cited = set(re.findall(r"dectest\.py\s+@([\w-]+)", text))
    assert cited, "expected at least one @set example in decompiler-testing.md"
    unknown = cited - real_sets
    assert unknown == set(), f"cited sets not in sets.toml: {unknown}"


def test_dectest_supports_list_sets() -> None:
    """C14: `tools/dectest.py --list-sets` is how you find named sets."""
    src = _read(ROOT / "tools" / "dectest.py")
    assert "--list-sets" in src


# ---------------------------------------------------------------------------
# docs/history/parsers-2025/{macho-README,archive-README}.md spec paths
# ---------------------------------------------------------------------------


def test_macho_readme_golang_spec_path_is_correct() -> None:
    text = _read(ROOT / "docs" / "history" / "parsers-2025" / "macho-README.md")
    assert "/reference/specifications/macho/golang_macho.go" not in text
    assert "/reference/specifications/elf/golang_macho.go" in text
    assert (ROOT / "reference" / "specifications" / "elf" / "golang_macho.go").exists()


def test_archive_readme_does_not_cite_nonexistent_archive_h() -> None:
    text = _read(ROOT / "docs" / "history" / "parsers-2025" / "archive-README.md")
    assert "archive.h" not in text
    spec_dir = ROOT / "reference" / "specifications" / "archive"
    assert spec_dir.is_dir()
    assert not (spec_dir / "archive.h").exists()


# ---------------------------------------------------------------------------
# development/test-inventory: coverage.md staleness banner
# ---------------------------------------------------------------------------


def test_coverage_md_declares_itself_a_frozen_snapshot() -> None:
    """coverage.md cannot currently be regenerated (no tool writes it, and
    the underlying survey fragments are not committed) and is measurably
    stale against index.json. Its header must say so rather than imply it
    is current.
    """
    text = _read(ROOT / "docs" / "test-inventory" / "coverage.md")
    assert "frozen snapshot" in text
    assert "tools/build_test_inventory.py" in text


def test_build_test_inventory_does_not_write_coverage_md() -> None:
    """The fact the banner above depends on: the generator's `main()` never
    writes `coverage.md`. If it starts to, the doc's caveat is obsolete.
    """
    src = _read(ROOT / "tools" / "build_test_inventory.py")
    assert "coverage.md" not in src


def test_test_inventory_readme_does_not_overclaim_coverage_generation() -> None:
    text = _read(ROOT / "docs" / "test-inventory" / "README.md")
    assert "hand-written" in text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# ---------------------------------------------------------------------------
# PENDING -- contracts whose target document is owned by an agent still
# writing in another phase. Re-assert these once that phase lands; do not
# enable by guessing the target doc's final content.
#
# C4  guides/triage.md (Phase 6) -- --max-depth, --tree, exit-status contract
# C5  guides/parsers-and-formats.md (Phase 6) -- resolve --tree "advertised
#     but not wired" against guides/triage.md before restating either way
# C6  guides/parsers-and-formats.md (Phase 6) -- triage output nests under
#     `containers`
# C7  guides/parsers-and-formats.md (Phase 6) -- no owned src/formats/macho
#     parser module
# C8  guides/parsers-and-formats.md (Phase 6) -- live parser entry points are
#     `uv run glaurung {triage,classfile,luac,pe resources}`
# C9  architecture/persistent-project.md (Phase 4) --
#     PersistentKnowledgeBase.open(...) / MemoryContext.open_persistent(...)
# C10 architecture/persistent-project.md (Phase 4) -- migrations not yet
#     implemented; schema version currently 1 (re-check against
#     python/glaurung/llm/kb/persistent.py before restating)
# C11 architecture/data-model.md (Phase 4) -- sourced from src/core/mod.rs,
#     src/triage/, python/glaurung/llm/kb/ (the KB path, not
#     python/glaurung/kb/ -- CLAUDE.md's false path is a Phase 3 fix)
# C12 development/guidelines.md (owner unclear across phases) --
#     TriageRunError does not exist; errors live in src/core/triage/errors.rs
# C13 development/setup.md (Phase 3) -- uv sync --locked --dev,
#     rust:1.88-bookworm; Phase 3 also raises 3.11 -> 3.12 and adds Git LFS
# C15 development/decompiler-curriculum-corpus.md (owner unclear) -- corpus
#     results stated at a named commit; refresh or drop the commit
# C22 architecture/llm-subsystem.md (Phase 4, being written now) -- the
#     memory-tool architecture narrative and its
#     test_tool_routing.py check command (the underlying symbols are already
#     asserted above against reference/llm-tool-contract.md, which this
#     phase owns)
# C24 wherever examples/ lands -- no unittest.mock/MagicMock in example code
#     (the doc-prose half is asserted above for llm-tool-contract.md)
# C27 guides/windows-analysis.md (Phase 6) -- "generated, revision-bound
#     snapshots" distinct from live guidance; corrected tools row (113
#     windows_*.py files, not 12-15)
# C30 docs/README.md (Phase 3) -- indexes every top-level directory, does not
#     link records as guidance
# C32 architecture/solver-backends.md (Phase 4) -- solver-axeyum is opt-in;
#     LogicalAnd history; drop "Current source gate: failing" (fixed in
#     114a5c4c)
# ---------------------------------------------------------------------------
