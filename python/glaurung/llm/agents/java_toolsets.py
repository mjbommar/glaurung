"""Focused Java/JVM toolsets for provider-facing pydantic-ai agents."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, Literal

from pydantic_ai import Agent

from ..context import MemoryContext
from ..tools.base import MemoryTool, tool_to_pyd_ai
from ..tools.java_agent_context import build_tool as build_java_agent_context
from ..tools.java_annotate_mappings import build_tool as build_java_annotate_mappings
from ..tools.java_call_graph import build_tool as build_java_call_graph
from ..tools.java_compare_rebuilt_abi import (
    build_tool as build_java_compare_rebuilt_abi,
)
from ..tools.java_compile_recovered_project import (
    build_tool as build_java_compile_recovered_project,
)
from ..tools.java_correlate_behavior_config import (
    build_tool as build_java_correlate_behavior_config,
)
from ..tools.java_decompile_archive import build_tool as build_java_decompile_archive
from ..tools.java_decompile_class import build_tool as build_java_decompile_class
from ..tools.java_detect_entrypoints import build_tool as build_java_detect_entrypoints
from ..tools.java_detect_frameworks import build_tool as build_java_detect_frameworks
from ..tools.java_detect_obfuscation import build_tool as build_java_detect_obfuscation
from ..tools.java_detect_secrets import build_tool as build_java_detect_secrets
from ..tools.java_detect_security_sensitive_behavior import (
    build_tool as build_java_detect_sensitive_behavior,
)
from ..tools.java_detect_suspicious_blobs import (
    build_tool as build_java_detect_suspicious_blobs,
)
from ..tools.java_extract_config_surface import (
    build_tool as build_java_extract_config_surface,
)
from ..tools.java_index_archive import build_tool as build_java_index_archive
from ..tools.java_index_source_project import (
    build_tool as build_java_index_source_project,
)
from ..tools.java_infer_build_system import build_tool as build_java_infer_build_system
from ..tools.java_infer_dependencies import build_tool as build_java_infer_dependencies
from ..tools.java_list_classes import build_tool as build_java_list_classes
from ..tools.java_list_fields import build_tool as build_java_list_fields
from ..tools.java_list_methods import build_tool as build_java_list_methods
from ..tools.java_list_packages import build_tool as build_java_list_packages
from ..tools.java_list_resources import build_tool as build_java_list_resources
from ..tools.java_list_services import build_tool as build_java_list_services
from ..tools.java_list_string_constants import (
    build_tool as build_java_list_string_constants,
)
from ..tools.java_lookup_mapping import build_tool as build_java_lookup_mapping
from ..tools.java_parse_decompiled_source import (
    build_tool as build_java_parse_decompiled_source,
)
from ..tools.java_reachability import build_tool as build_java_reachability
from ..tools.java_reconstruct_source_tree import (
    build_tool as build_java_reconstruct_source_tree,
)
from ..tools.java_recover_project import build_tool as build_java_recover_project
from ..tools.java_recovery_report import build_tool as build_java_recovery_report
from ..tools.java_repair_decompiled_source import (
    build_tool as build_java_repair_decompiled_source,
)
from ..tools.java_risk_report import build_tool as build_java_risk_report
from ..tools.java_trace_to_sink import build_tool as build_java_trace_to_sink
from ..tools.java_validate_recovered_application import (
    build_tool as build_java_validate_recovered_application,
)
from ..tools.java_view_bytecode import build_tool as build_java_view_bytecode
from ..tools.java_view_class import build_tool as build_java_view_class
from ..tools.java_view_manifest import build_tool as build_java_view_manifest
from ..tools.java_xrefs_from import build_tool as build_java_xrefs_from
from ..tools.java_xrefs_to import build_tool as build_java_xrefs_to
from ..tools.minecraft_detect_archive import (
    build_tool as build_minecraft_detect_archive,
)
from ..tools.minecraft_fetch_mappings import (
    build_tool as build_minecraft_fetch_mappings,
)


JavaAgentToolProfile = Literal["triage", "security", "recovery", "deobfuscation"]
JavaToolBuilder = Callable[[], MemoryTool[Any, Any]]


JAVA_TOOL_BUILDERS: Mapping[str, JavaToolBuilder] = {
    "java_agent_context": build_java_agent_context,
    "java_annotate_mappings": build_java_annotate_mappings,
    "java_call_graph": build_java_call_graph,
    "java_compare_rebuilt_abi": build_java_compare_rebuilt_abi,
    "java_compile_recovered_project": build_java_compile_recovered_project,
    "java_correlate_behavior_config": build_java_correlate_behavior_config,
    "java_decompile_archive": build_java_decompile_archive,
    "java_decompile_class": build_java_decompile_class,
    "java_detect_entrypoints": build_java_detect_entrypoints,
    "java_detect_frameworks": build_java_detect_frameworks,
    "java_detect_obfuscation": build_java_detect_obfuscation,
    "java_detect_secrets": build_java_detect_secrets,
    "java_detect_security_sensitive_behavior": build_java_detect_sensitive_behavior,
    "java_detect_suspicious_blobs": build_java_detect_suspicious_blobs,
    "java_extract_config_surface": build_java_extract_config_surface,
    "java_index_archive": build_java_index_archive,
    "java_index_source_project": build_java_index_source_project,
    "java_infer_build_system": build_java_infer_build_system,
    "java_infer_dependencies": build_java_infer_dependencies,
    "java_list_classes": build_java_list_classes,
    "java_list_fields": build_java_list_fields,
    "java_list_methods": build_java_list_methods,
    "java_list_packages": build_java_list_packages,
    "java_list_resources": build_java_list_resources,
    "java_list_services": build_java_list_services,
    "java_list_string_constants": build_java_list_string_constants,
    "java_lookup_mapping": build_java_lookup_mapping,
    "java_parse_decompiled_source": build_java_parse_decompiled_source,
    "java_reachability": build_java_reachability,
    "java_reconstruct_source_tree": build_java_reconstruct_source_tree,
    "java_recover_project": build_java_recover_project,
    "java_recovery_report": build_java_recovery_report,
    "java_repair_decompiled_source": build_java_repair_decompiled_source,
    "java_risk_report": build_java_risk_report,
    "java_trace_to_sink": build_java_trace_to_sink,
    "java_validate_recovered_application": build_java_validate_recovered_application,
    "java_view_bytecode": build_java_view_bytecode,
    "java_view_class": build_java_view_class,
    "java_view_manifest": build_java_view_manifest,
    "java_xrefs_from": build_java_xrefs_from,
    "java_xrefs_to": build_java_xrefs_to,
    "minecraft_detect_archive": build_minecraft_detect_archive,
    "minecraft_fetch_mappings": build_minecraft_fetch_mappings,
}


JAVA_TRIAGE_TOOL_NAMES: tuple[str, ...] = (
    "java_agent_context",
    "java_index_archive",
    "minecraft_detect_archive",
    "java_detect_obfuscation",
    "java_detect_entrypoints",
    "java_detect_frameworks",
    "java_list_packages",
    "java_list_classes",
    "java_list_methods",
    "java_list_fields",
    "java_list_resources",
    "java_view_manifest",
    "java_list_services",
    "java_list_string_constants",
    "java_lookup_mapping",
    "java_view_class",
)

JAVA_SECURITY_TOOL_NAMES: tuple[str, ...] = (
    "java_agent_context",
    "java_risk_report",
    "java_detect_security_sensitive_behavior",
    "java_extract_config_surface",
    "java_detect_entrypoints",
    "java_detect_secrets",
    "java_detect_suspicious_blobs",
    "java_correlate_behavior_config",
    "java_reachability",
    "java_trace_to_sink",
    "java_call_graph",
    "java_xrefs_from",
    "java_xrefs_to",
    "java_list_string_constants",
    "java_list_methods",
    "java_view_bytecode",
    "java_view_class",
    "minecraft_detect_archive",
)

JAVA_RECOVERY_TOOL_NAMES: tuple[str, ...] = (
    "java_agent_context",
    "java_recover_project",
    "java_recovery_report",
    "java_decompile_archive",
    "java_decompile_class",
    "java_reconstruct_source_tree",
    "java_parse_decompiled_source",
    "java_index_source_project",
    "java_compile_recovered_project",
    "java_repair_decompiled_source",
    "java_validate_recovered_application",
    "java_compare_rebuilt_abi",
    "java_infer_dependencies",
    "java_infer_build_system",
    "java_list_classes",
    "java_list_methods",
    "java_lookup_mapping",
    "java_view_bytecode",
    "java_view_class",
)

JAVA_DEOBFUSCATION_TOOL_NAMES: tuple[str, ...] = (
    "java_agent_context",
    "minecraft_detect_archive",
    "minecraft_fetch_mappings",
    "java_detect_obfuscation",
    "java_annotate_mappings",
    "java_lookup_mapping",
    "java_index_archive",
    "java_list_packages",
    "java_list_classes",
    "java_list_fields",
    "java_list_methods",
    "java_list_string_constants",
    "java_view_class",
    "java_view_bytecode",
    "java_xrefs_from",
    "java_xrefs_to",
    "java_call_graph",
)

JAVA_AGENT_TOOLSETS: Mapping[JavaAgentToolProfile, tuple[str, ...]] = {
    "triage": JAVA_TRIAGE_TOOL_NAMES,
    "security": JAVA_SECURITY_TOOL_NAMES,
    "recovery": JAVA_RECOVERY_TOOL_NAMES,
    "deobfuscation": JAVA_DEOBFUSCATION_TOOL_NAMES,
}


def java_tool_names_for_profile(profile: JavaAgentToolProfile) -> tuple[str, ...]:
    """Return the focused Java tool names for a provider-facing agent."""

    return JAVA_AGENT_TOOLSETS[profile]


def register_java_agent_tools(
    agent: Agent[MemoryContext, Any],
    *,
    profile: JavaAgentToolProfile | None = None,
    tool_names: Iterable[str] | None = None,
    strict: bool | None = True,
) -> Agent[MemoryContext, Any]:
    """Register a focused Java toolset on ``agent``.

    The general memory agent still owns the complete tool catalog. These
    focused sets are for live provider compatibility and better model
    ergonomics: each profile stays below Anthropic's strict-tool limit while
    preserving access to the full catalog through ``create_memory_agent``.
    """

    if tool_names is None:
        if profile is None:
            raise ValueError("profile or tool_names is required")
        tool_names = java_tool_names_for_profile(profile)

    for name in tool_names:
        builder = JAVA_TOOL_BUILDERS.get(name)
        if builder is None:
            raise ValueError(f"unknown Java agent tool: {name}")
        agent._function_toolset.add_tool(tool_to_pyd_ai(builder(), strict=strict))
    return agent


__all__ = [
    "JAVA_AGENT_TOOLSETS",
    "JAVA_DEOBFUSCATION_TOOL_NAMES",
    "JAVA_RECOVERY_TOOL_NAMES",
    "JAVA_SECURITY_TOOL_NAMES",
    "JAVA_TOOL_BUILDERS",
    "JAVA_TRIAGE_TOOL_NAMES",
    "JavaAgentToolProfile",
    "java_tool_names_for_profile",
    "register_java_agent_tools",
]
