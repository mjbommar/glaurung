from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.agents.windows_pretty_lift_agent import (
    build_windows_pretty_lift_prompt,
    create_windows_pretty_lift_agent,
)
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb import windows_boundaries, xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_function_pretty_lift import (
    PrettyLift,
    build_tool,
    validate_pretty_lift,
)


FIXTURE_DIR = Path("tests/fixtures/msvc-pdb")
NTOSKRNL = FIXTURE_DIR / "ntoskrnl.exe"
PYTEST_MARK: Any = getattr(pytest, "mark")


GLAURUNG_CMP_QUERY_BUILD_VERSION_IR = """
fn sub_140796110 {
    ret = rsp;
    &[ret+0x8] = var0;
    &[ret+0x18] = var1;
    push(var2);
    rsp = (rsp - 64);
    var1 = arg2;
    arg2 = 0;
    &[ret+0x10] = arg2;
    %zf = (arg1 == 4);
    %cf = (arg1 u< 4);
    if (%zf) {
        goto L_1408f20c5;
    }
    %zf = (arg3 == 580);
    %cf = (arg3 u< 580);
    if (%cf) {
        goto L_1408f20c5;
    }
    var4 = *&[arg0];
    &[ret+0x10] = var4;
    ret = var4;
    var0 = 0x140c13ec0;
    var0 = *&[var0+ret*8];
    stack_2 = var0;
    memset(var1, 0, arg3);
    &[var1] = var6;
    ret = *&[var5+0x140c13eb4];
    &[var1+0x2] = ret;
    ret = *&[var0];
    &[var1+0x4] = ret;
    ret = *&[var0+0x4];
    &[var1+0x8] = ret;
    ret = *&[var0+0x8];
    &[var1+0xc] = ret;
    ret = *&[var0+0xc];
    &[var1+0x10] = ret;
    ret = *&[var0+0x320];
    &[var1+0x240] = ret;
    var4 = 128;
    CmpQueryDowncastString((var1 + 20), var4, (var0 + 16));
    CmpQueryDowncastString((var1 + 148), var4, (var0 + 64));
    CmpQueryDowncastString((var1 + 276), var4, (var0 + 80));
    CmpQueryDowncastString((var1 + 404), var4, (var0 + 96));
    CmpQueryDowncastString((var1 + 532), (var2 - 102), (var0 + 32));
    CmpQueryDowncastString((var1 + 558), (var2 - 112), (var0 + 48));
    ret = stack_1;
    &[ret] = 580;
    ret = 0;
    var0 = stack_3;
    var1 = stack_4;
    rsp = (rsp + 64);
    pop(var2);
    return;
}
"""


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_function_pretty_lift_renders_evidence_backed_c(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode=GLAURUNG_CMP_QUERY_BUILD_VERSION_IR,
            function_va=0x140796110,
            function_name="CmQueryBuildVersionInformation",
        ),
    )

    packet = result.packet
    assert packet.function_name == "CmQueryBuildVersionInformation"
    assert packet.argument_roles["arg0"].semantic_name == "QueryIndex"
    assert packet.argument_roles["arg1"].semantic_name == "QueryLength"
    assert packet.argument_roles["arg2"].semantic_name == "OutputBuffer"
    assert packet.argument_roles["arg3"].semantic_name == "OutputLength"
    assert "entry_abi_arguments" in packet.coverage
    assert [
        (arg.index, arg.abi_location, arg.register_name, arg.stack_offset)
        for arg in packet.entry_abi_arguments
    ][:6] == [
        (0, "register", "rcx", None),
        (1, "register", "rdx", None),
        (2, "register", "r8", None),
        (3, "register", "r9", None),
        (4, "stack", None, 0x20),
        (5, "stack", None, 0x28),
    ]
    assert packet.entry_abi_arguments[0].semantic_name == "QueryIndex"
    assert packet.entry_abi_arguments[4].semantic_name == "ReturnLength"
    assert packet.entry_abi_arguments[5].role == "mode"
    assert any(
        fact.kind == "entry_abi_argument" and fact.key == "0:rcx"
        for fact in packet.facts
    )
    assert packet.output_size == 0x244
    assert packet.selector_table is not None
    assert packet.selector_table.table_name == "CmpLayerVersions"
    assert packet.call_counts["CmpQueryDowncastString"] == 6
    assert "call_sites" in packet.coverage
    assert [site.call_name for site in packet.call_sites[-6:]] == [
        "CmpQueryDowncastString",
        "CmpQueryDowncastString",
        "CmpQueryDowncastString",
        "CmpQueryDowncastString",
        "CmpQueryDowncastString",
        "CmpQueryDowncastString",
    ]
    assert any(
        site.call_name == "CmpQueryDowncastString"
        and site.arguments[1] == "var4"
        and site.prototype is not None
        and site.prototype.parameters[1].role == "dst_length"
        for site in packet.call_sites
    )
    assert any(
        fact.kind == "call_site" and fact.key.startswith("1:CmpQueryDowncastString:")
        for fact in packet.facts
    )
    assert packet.function_prototype is not None
    assert packet.function_prototype.prototype.startswith(
        "NTSTATUS CmQueryBuildVersionInformation("
    )
    assert any(
        prototype.symbol == "CmpQueryDowncastString"
        and prototype.parameters[1].role == "dst_length"
        for prototype in packet.call_prototypes
    )
    assert any(
        fact.kind == "function_prototype"
        and fact.key == "CmQueryBuildVersionInformation"
        for fact in packet.facts
    )
    assert "path_conditions" in packet.coverage
    assert any(
        condition.role == "length_gate"
        and condition.lhs_expression == "arg1"
        and condition.operator == "=="
        and condition.rhs_expression == "4"
        and condition.target_label == "L_1408f20c5"
        for condition in packet.path_conditions
    )
    assert any(
        condition.role == "length_gate"
        and condition.lhs_expression == "arg3"
        and condition.operator == "u<"
        and condition.rhs_expression == "580"
        for condition in packet.path_conditions
    )
    assert any(
        fact.kind == "path_condition" and fact.key == "length_gate:arg3:u<:580"
        for fact in packet.facts
    )
    assert "memory_accesses" in packet.coverage
    assert any(
        access.kind == "read"
        and access.base == "var0"
        and access.offset == 0x320
        and access.role == "memory"
        for access in packet.memory_accesses
    )
    assert any(
        access.kind == "write"
        and access.base == "var1"
        and access.offset == 0x240
        and access.role == "output_buffer"
        for access in packet.memory_accesses
    )
    assert any(
        access.kind == "read"
        and access.base == "var0"
        and access.index == "ret"
        and access.scale == 8
        and access.role == "selector_table"
        for access in packet.memory_accesses
    )
    assert any(
        fact.kind == "memory_access" and fact.key == "write:var1+0x240"
        for fact in packet.facts
    )
    assert "field_offset_groups" in packet.coverage
    assert any(
        group.base == "var1"
        and group.role == "output_buffer"
        and 0x240 in group.write_offsets
        and group.max_offset == 0x240
        for group in packet.field_offset_groups
    )
    assert any(
        group.base == "var0"
        and group.role in {"memory", "selector_table"}
        and 0x320 in group.read_offsets
        for group in packet.field_offset_groups
    )
    assert any(
        fact.kind == "field_offset_group" and fact.key == "var1:output_buffer"
        for fact in packet.facts
    )
    assert "data_references" in packet.coverage
    assert any(
        ref.kind == "global_address"
        and ref.address == 0x140C13EC0
        and ref.role == "global_table_candidate"
        for ref in packet.data_references
    )
    assert any(
        ref.kind == "selector_table_load"
        and ref.base == "var0"
        and ref.index == "ret"
        and ref.scale == 8
        for ref in packet.data_references
    )
    assert any(
        fact.kind == "data_reference" and fact.key == "selector_table_load:var0+ret*8"
        for fact in packet.facts
    )

    pretty = result.pretty_lift.pseudocode
    assert "NTSTATUS CmQueryBuildVersionInformation(" in pretty
    assert "QueryLength != sizeof(ULONG)" in pretty
    assert "OutputLength < 0x244" in pretty
    assert "index = *QueryIndex;" in pretty
    assert "version = CmpLayerVersions[index];" in pretty
    assert "memset(OutputBuffer, 0, OutputLength);" in pretty
    assert "CmpQueryDowncastString((uint8_t *)OutputBuffer + 0x14" in pretty
    assert "*ReturnLength = 0x244;" in pretty
    assert "STATUS_INFO_LENGTH_MISMATCH" in pretty
    assert "STATUS_NO_MORE_ENTRIES" in pretty
    assert "STATUS_SUCCESS" in pretty
    assert "goto " not in pretty
    assert "unaff_" not in pretty
    assert "FUN_" not in pretty

    assert result.validation.valid is True
    assert not [
        finding
        for finding in result.validation.findings
        if finding.severity in {"error", "critical"}
    ]
    assert "calls:CmpQueryDowncastString" in result.validation.preserved_facts
    assert "constant:0x244" in result.validation.preserved_facts
    assert "output_write:offset:0x240" in result.validation.preserved_facts
    assert "field_offset_group:var1:output_buffer" in (
        result.validation.preserved_facts
    )


def test_pretty_lift_validation_rejects_missing_output_write(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode=GLAURUNG_CMP_QUERY_BUILD_VERSION_IR,
            function_va=0x140796110,
            function_name="CmQueryBuildVersionInformation",
        ),
    )

    bad = result.pretty_lift.model_copy(
        update={
            "pseudocode": result.pretty_lift.pseudocode.replace(
                "    WRITE_FIELD(OutputBuffer, 0x240, READ_FIELD(version, 0x320));\n",
                "",
            ),
            "confidence": 0.9,
        }
    )
    validation = validate_pretty_lift(result.packet, bad)

    assert validation.valid is False
    assert "output_write:offset:0x240" in validation.missing_facts
    assert "field_offset_group:var1:output_buffer" in validation.missing_facts
    assert any(
        finding.fact == "output_write:offset:0x240"
        and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_renders_syscall_stub(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_18009faa0 {
    var0 = arg0;
    ret = 54;
    unknown(syscall);
    return;
}
""",
            function_va=0x18009FAA0,
            function_name="NtQuerySystemInformation",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "SYSTEM_INFORMATION_CLASS SystemInformationClass" in pretty
    assert "syscall number 0x36" in pretty
    assert "SYSCALL_54" in pretty
    assert result.packet.function_prototype is not None
    assert result.packet.function_prototype.source == "stdlib"
    assert result.packet.function_prototype.prototype.startswith(
        "NTSTATUS NtQuerySystemInformation("
    )
    assert result.validation.quality_score >= 0.90


def test_windows_function_pretty_lift_renders_status_bool_wrapper(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_1800147f0 {
    RtlSwitchedVVI();
    %zf = (ret == -0x3ffffff3);
    if (%zf) { goto L_err; }
    ret = 1;
    return;
    RtlSetLastWin32Error(1150);
    ret = 0;
    return;
}
""",
            function_va=0x1800147F0,
            function_name="VerifyVersionInfoW",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "BOOL VerifyVersionInfoW" in pretty
    assert "NTSTATUS status = RtlSwitchedVVI" in pretty
    assert "RtlSetLastWin32Error(1150)" in pretty
    assert "return FALSE" in pretty
    assert result.validation.quality_score >= 0.80


def test_windows_function_pretty_lift_classifies_direct_path_conditions(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180010000 {
    if (arg0 == 0) { goto L_null; }
    if (ret == -0x3ffffff3) { goto L_status; }
    if (arg2 u>= 0x1000) { goto L_range; }
    return;
}
""",
            function_va=0x180010000,
            function_name="GateShape",
        ),
    )

    roles = {condition.role for condition in result.packet.path_conditions}
    assert "zero_length_or_null_gate" in roles
    assert "status_gate" in roles
    assert "range_gate" in roles
    assert "path_conditions" in result.packet.coverage

    bad = PrettyLift(
        function_name="GateShape",
        prototype="NTSTATUS GateShape(void)",
        pseudocode="NTSTATUS GateShape(void) { return STATUS_SUCCESS; }",
        confidence=0.5,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert any(
        finding.fact.startswith("path_condition:zero_length_or_null_gate")
        and finding.severity == "error"
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_classifies_structured_guard_families(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180010040 {
    status = ProbeUserBuffer(Buffer, Length);
    if (!NT_SUCCESS(status)) { goto L_status; }
    if (status < 0) { goto L_status2; }
    if (Offset + Length u> OutputLength) { goto L_bounds; }
    if (SystemInformationClass == 0x58) { goto L_selector; }
    if (Buffer == NULL) { goto L_null; }
    return;
}
""",
            function_va=0x180010040,
            function_name="StructuredGuardShape",
        ),
    )

    conditions = result.packet.path_conditions
    roles = {condition.role for condition in conditions}
    assert "status_gate" in roles
    assert "bounds_gate" in roles
    assert "selector_gate" in roles
    assert "zero_length_or_null_gate" in roles
    assert any(
        condition.role == "status_gate"
        and condition.operator == "!NT_SUCCESS"
        and condition.lhs_expression == "status"
        and condition.condition_kind == "status_macro_false"
        for condition in conditions
    )
    assert any(
        condition.role == "bounds_gate"
        and condition.expression == "Offset + Length u> OutputLength"
        and condition.target_label == "L_bounds"
        for condition in conditions
    )
    assert any(
        fact.kind == "path_condition"
        and fact.key == "bounds_gate:Offset + Length:u>:OutputLength"
        for fact in result.packet.facts
    )
    assert result.validation.valid is True

    bad = PrettyLift(
        function_name="StructuredGuardShape",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS StructuredGuardShape(void) { return STATUS_SUCCESS; }",
        confidence=0.8,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert any(
        finding.fact.startswith("path_condition:bounds_gate")
        and finding.severity == "error"
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_classifies_security_boundary_path_conditions(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180010080 {
    mode = ExGetPreviousMode();
    if (mode != KernelMode) { goto L_user; }
    if (!SeSinglePrivilegeCheck(SeLoadDriverPrivilege, mode)) { goto L_denied; }
    return;
}
""",
            function_va=0x180010080,
            function_name="SecurityBoundaryGate",
        ),
    )

    roles = {condition.role for condition in result.packet.path_conditions}
    assert "mode_gate" in roles
    assert "privilege_gate" in roles
    assert any(
        condition.role == "mode_gate" and condition.expression == "mode != KernelMode"
        for condition in result.packet.path_conditions
    )
    assert any(
        condition.role == "privilege_gate"
        and "SeSinglePrivilegeCheck" in condition.expression
        for condition in result.packet.path_conditions
    )
    assert any(
        fact.kind == "path_condition"
        and fact.key.startswith("privilege_gate:SeSinglePrivilegeCheck")
        for fact in result.packet.facts
    )
    assert result.validation.valid is True
    assert any(
        preserved.startswith("path_condition:privilege_gate")
        for preserved in result.validation.preserved_facts
    )

    bad = PrettyLift(
        function_name="SecurityBoundaryGate",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS SecurityBoundaryGate(void) { return STATUS_SUCCESS; }",
        confidence=0.8,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert any(
        finding.fact.startswith("path_condition:privilege_gate")
        and finding.severity == "error"
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_renders_simple_forwarder(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180026ad0 {
    HeapCompact();
    return;
}
""",
            function_va=0x180026AD0,
            function_name="HeapCompactStub",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "return HeapCompact(/* original arguments */);" in pretty
    assert any(
        prototype.symbol == "HeapCompact"
        and prototype.prototype.startswith("uintptr_t HeapCompact(")
        for prototype in result.packet.call_prototypes
    )
    assert result.validation.quality_score >= 0.80


def test_windows_function_pretty_lift_uses_project_call_prototypes(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = tmp_path / "sample.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=ctx.file_path)
    try:
        xref_db.set_function_prototype(
            kb,
            "CustomHelper",
            "NTSTATUS",
            [
                xref_db.FunctionParam("Buffer", "void *", "output_buffer"),
                xref_db.FunctionParam("Length", "ULONG", "length"),
                xref_db.FunctionParam("InputBuffer", "const void *", "input_buffer"),
                xref_db.FunctionParam("OutputLength", "ULONG", "output_length"),
                xref_db.FunctionParam("ReturnLength", "ULONG *", "return_length"),
            ],
            set_by="manual",
            confidence=0.95,
        )
    finally:
        kb.close()

    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140010000 {
    CustomHelper(arg0, arg1, arg2, arg3, stack_1);
    return;
}
""",
            project_path=str(project),
            function_va=0x140010000,
            function_name="ProjectPrototypeCaller",
        ),
    )

    prototype = next(
        item for item in result.packet.call_prototypes if item.symbol == "CustomHelper"
    )
    site = result.packet.call_sites[0]
    assert prototype.source == "project"
    assert prototype.prototype.startswith("NTSTATUS CustomHelper(")
    assert prototype.parameters[0].role == "output_buffer"
    assert "call_site_arguments" in result.packet.coverage
    assert [
        (
            argument.index,
            argument.abi_location,
            argument.register_name,
            argument.stack_offset,
        )
        for argument in site.argument_facts
    ] == [
        (0, "register", "rcx", None),
        (1, "register", "rdx", None),
        (2, "register", "r8", None),
        (3, "register", "r9", None),
        (4, "stack", None, 0x20),
    ]
    assert site.argument_facts[0].parameter_name == "Buffer"
    assert site.argument_facts[0].role == "output_buffer"
    assert site.argument_facts[4].parameter_name == "ReturnLength"
    assert site.argument_facts[4].role == "return_length"
    assert any(
        fact.kind == "call_site_argument"
        and fact.key == "0:CustomHelper:3:4:stack+0x20"
        for fact in result.packet.facts
    )
    assert (
        "call_site_argument:0:CustomHelper:3:4:stack+0x20"
        in result.validation.preserved_facts
    )
    assert (
        "return CustomHelper(Buffer, Length, InputBuffer, OutputLength, ReturnLength);"
        in result.pretty_lift.pseudocode
    )

    bad = PrettyLift(
        function_name="ProjectPrototypeCaller",
        prototype=result.pretty_lift.prototype,
        pseudocode=(
            "NTSTATUS ProjectPrototypeCaller(void) {\n    return CustomHelper();\n}"
        ),
        confidence=0.9,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert (
        "call_site_argument:0:CustomHelper:3:4:stack+0x20" in validation.missing_facts
    )
    assert any(
        finding.fact == "call_site_argument:0:CustomHelper:3:4:stack+0x20"
        and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_normalizes_thunk_project_call_prototypes(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = tmp_path / "sample.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=ctx.file_path)
    try:
        xref_db.set_function_prototype(
            kb,
            "CustomHelper",
            "NTSTATUS",
            [
                xref_db.FunctionParam("Buffer", "void *", "output_buffer"),
                xref_db.FunctionParam("Length", "ULONG", "length"),
                xref_db.FunctionParam("InputBuffer", "const void *", "input_buffer"),
                xref_db.FunctionParam("OutputLength", "ULONG", "output_length"),
                xref_db.FunctionParam("ReturnLength", "ULONG *", "return_length"),
            ],
            set_by="manual",
            confidence=0.95,
        )
    finally:
        kb.close()

    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140010100 {
    nt!__imp_CustomHelper(arg0, arg1, arg2, arg3, stack_1);
    j_CustomHelper(arg0, arg1, arg2, arg3, stack_1);
    return;
}
""",
            project_path=str(project),
            function_va=0x140010100,
            function_name="ThunkProjectPrototypeCaller",
        ),
    )

    assert [
        (site.call_name, site.original_name) for site in result.packet.call_sites
    ] == [
        ("CustomHelper", "nt!__imp_CustomHelper"),
        ("CustomHelper", "j_CustomHelper"),
    ]
    assert [prototype.symbol for prototype in result.packet.call_prototypes] == [
        "CustomHelper"
    ]
    assert all(site.prototype is not None for site in result.packet.call_sites)
    assert all(
        site.argument_facts[0].parameter_name == "Buffer"
        and site.argument_facts[0].role == "output_buffer"
        and site.argument_facts[4].parameter_name == "ReturnLength"
        and site.argument_facts[4].role == "return_length"
        for site in result.packet.call_sites
    )
    assert (
        result.pretty_lift.pseudocode.count(
            "CustomHelper(Buffer, Length, InputBuffer, OutputLength, ReturnLength)"
        )
        == 2
    )
    assert "nt___imp_CustomHelper" not in result.pretty_lift.pseudocode
    assert "j_CustomHelper" not in result.pretty_lift.pseudocode


def test_windows_function_pretty_lift_uses_project_entry_prototype(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = tmp_path / "sample.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=ctx.file_path)
    try:
        xref_db.set_function_prototype(
            kb,
            "TypedEntry",
            "NTSTATUS",
            [
                xref_db.FunctionParam("DeviceObject", "void *", "object"),
                xref_db.FunctionParam("InputLength", "ULONG", "input_length"),
                xref_db.FunctionParam("OutputBuffer", "void *", "output_buffer"),
                xref_db.FunctionParam("OutputLength", "ULONG", "output_length"),
                xref_db.FunctionParam("ReturnLength", "ULONG *", "return_length"),
            ],
            set_by="manual",
            confidence=0.95,
        )
    finally:
        kb.close()

    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140020000 {
    return;
}
""",
            project_path=str(project),
            function_va=0x140020000,
            function_name="TypedEntry",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "NTSTATUS TypedEntry(" in pretty
    assert "void *DeviceObject" in pretty
    assert "ULONG InputLength" in pretty
    assert "void *OutputBuffer" in pretty
    assert "ULONG OutputLength" in pretty
    assert "ULONG *ReturnLength" in pretty
    assert result.packet.entry_abi_arguments[4].stack_offset == 0x20
    assert "entry_abi_argument:0:rcx" in result.validation.preserved_facts

    bad = PrettyLift(
        function_name="TypedEntry",
        prototype="NTSTATUS TypedEntry(void)",
        pseudocode="NTSTATUS TypedEntry(void) { return STATUS_SUCCESS; }",
        confidence=0.9,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert any(
        finding.fact == "entry_abi_argument:0:rcx" and finding.severity == "warning"
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_infers_roles_from_stdlib_prototypes(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140030000 {
    NtDeviceIoControlFile(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
    return;
}
""",
            function_va=0x140030000,
            function_name="NtDeviceIoControlForwarder",
        ),
    )

    prototype = next(
        item
        for item in result.packet.call_prototypes
        if item.symbol == "NtDeviceIoControlFile"
    )
    site = result.packet.call_sites[0]
    assert prototype.source == "stdlib"
    assert site.prototype is not None
    assert site.argument_facts[0].role == "handle"
    assert site.argument_facts[5].role == "ioctl_code"
    assert site.argument_facts[6].role == "input_buffer"
    assert site.argument_facts[7].role == "length"
    assert site.argument_facts[8].role == "output_buffer"
    assert site.argument_facts[9].role == "length"
    assert any(
        fact.kind == "call_site_argument"
        and fact.value.endswith("->IoControlCode:ioctl_code")
        for fact in result.packet.facts
    )


def test_windows_function_pretty_lift_infers_local_helper_prototype_roles(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140030080 {
    LocalCopyHelper(Out, Len, ReturnLength);
    return;
}
""",
            function_va=0x140030080,
            function_name="LocalPrototypeCaller",
        ),
    )

    prototype = next(
        item
        for item in result.packet.call_prototypes
        if item.symbol == "LocalCopyHelper"
    )
    site = result.packet.call_sites[0]
    assert prototype.source == "inferred_local"
    assert prototype.prototype.startswith("void LocalCopyHelper(")
    assert prototype.parameters[0].role == "output_buffer"
    assert prototype.parameters[1].role == "length"
    assert prototype.parameters[2].role == "return_length"
    assert site.prototype is not None
    assert site.argument_facts[0].role == "output_buffer"
    assert site.argument_facts[1].abi_location == "register"
    assert site.argument_facts[1].register_name == "rdx"
    assert site.argument_facts[2].role == "return_length"
    assert any(
        fact.kind == "call_prototype"
        and fact.key == "LocalCopyHelper"
        and "void * Out" in fact.value
        for fact in result.packet.facts
    )
    assert any(
        fact.kind == "call_site_argument" and fact.value == "Out->Out:output_buffer"
        for fact in result.packet.facts
    )


def test_windows_function_pretty_lift_renders_call_sequence(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140027210 {
    ret = RpcServerInqBindingHandle();
    TlsSetValue();
    RpcApiValidSecurityLevel();
    YCommitSpoolData();
    return;
}
""",
            function_va=0x140027210,
            function_name="RpcCommitSpoolData",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "status = RpcServerInqBindingHandle" in pretty
    assert "status = YCommitSpoolData" in pretty
    assert [site.call_name for site in result.packet.call_sites] == [
        "RpcServerInqBindingHandle",
        "TlsSetValue",
        "RpcApiValidSecurityLevel",
        "YCommitSpoolData",
    ]
    assert result.packet.call_sites[0].return_value_used is True
    assert result.packet.call_sites[0].return_target == "ret"
    assert "call_site_returns" in result.packet.coverage
    assert any(
        fact.kind == "call_site_return"
        and fact.key == "0:RpcServerInqBindingHandle:3"
        and fact.value == "ret"
        for fact in result.packet.facts
    )
    assert any(
        fact.kind == "call_site" and fact.key == "0:RpcServerInqBindingHandle:3"
        for fact in result.packet.facts
    )
    assert "call_site_return:0:RpcServerInqBindingHandle:3:ret" in (
        result.validation.preserved_facts
    )
    assert result.validation.quality_score >= 0.70

    bad = PrettyLift(
        function_name="RpcCommitSpoolData",
        prototype=result.pretty_lift.prototype,
        pseudocode=(
            "NTSTATUS RpcCommitSpoolData(void) {\n"
            "    YCommitSpoolData();\n"
            "    RpcServerInqBindingHandle();\n"
            "    return STATUS_SUCCESS;\n"
            "}"
        ),
        confidence=0.8,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert any(
        finding.fact == "call_order" and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_guarded_callback_requires_no_named_calls(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_1c0321fd0 {
    ret = *&[var0+0x20];
    GetCurrent();
    0x1c0159198();
    DxgkCreateOutputDuplInternal();
    return;
}
""",
            function_va=0x1C0321FD0,
            function_name="DxgkCreateOutputDupl",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "READ_GLOBAL_CALLBACK" not in pretty
    assert "DxgkCreateOutputDuplInternal" in pretty
    assert any(
        ref.kind == "callback_pointer" and ref.base == "var0" and ref.offset == 0x20
        for ref in result.packet.data_references
    )
    assert any(
        ref.kind == "absolute_call" and ref.address == 0x1C0159198
        for ref in result.packet.data_references
    )


def test_windows_function_pretty_lift_recovers_function_pointer_table_dispatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180050000 {
    var0 = 0x180120000;
    ret = *&[var0+arg0*8];
    ret(arg1);
    return;
}
""",
            function_va=0x180050000,
            function_name="DispatchThroughTable",
        ),
    )

    assert any(
        ref.kind == "function_pointer_table"
        and ref.base == "var0"
        and ref.index == "arg0"
        and ref.scale == 8
        and ref.role == "function_pointer_table_call"
        for ref in result.packet.data_references
    )
    assert any(
        fact.kind == "data_reference"
        and fact.key == "function_pointer_table:var0+arg0*8"
        for fact in result.packet.facts
    )


def test_windows_function_pretty_lift_recovers_global_count_bounds(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180050020 {
    var0 = 0x180120000;
    count = g_DispatchTableCount;
    %cf = (arg0 u< g_DispatchTableCount);
    if (!%cf) { goto L_out; }
    ret = *&[var0+arg0*8];
    ret(arg1);
L_out:
    return;
}
""",
            function_va=0x180050020,
            function_name="BoundedDispatchThroughTable",
        ),
    )

    count_refs = [
        ref for ref in result.packet.data_references if ref.kind == "global_count"
    ]
    assert any(
        ref.expression == "g_DispatchTableCount"
        and ref.role == "selector_bound_count"
        and ref.index == "arg0"
        for ref in count_refs
    )
    assert any(
        ref.expression == "g_DispatchTableCount" and ref.role == "global_count_load"
        for ref in count_refs
    )
    assert any(
        fact.kind == "data_reference"
        and fact.key == "global_count:g_DispatchTableCount:arg0"
        and fact.value == "selector_bound_count"
        for fact in result.packet.facts
    )
    assert result.validation.valid is True

    bad = PrettyLift(
        function_name="BoundedDispatchThroughTable",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS BoundedDispatchThroughTable(void) { return STATUS_SUCCESS; }",
        confidence=0.8,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert any(
        finding.fact == "data_reference:global_count:g_DispatchTableCount:arg0"
        and finding.severity == "error"
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_recovers_jump_table_dispatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180050040 {
    var0 = 0x180130000;
    ret = *&[var0+arg0*4];
    goto ret;
}
""",
            function_va=0x180050040,
            function_name="JumpThroughTable",
        ),
    )

    assert any(
        ref.kind == "jump_table"
        and ref.base == "var0"
        and ref.index == "arg0"
        and ref.scale == 4
        and ref.role == "jump_table_dispatch"
        for ref in result.packet.data_references
    )
    assert any(
        fact.kind == "data_reference" and fact.key == "jump_table:var0+arg0*4"
        for fact in result.packet.facts
    )


def test_windows_function_pretty_lift_recovers_import_thunk_dispatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180050080 {
    ret = *&[__imp_ZwClose];
    ret(arg0);
    return;
}
""",
            function_va=0x180050080,
            function_name="ImportThunkCaller",
        ),
    )

    assert any(
        ref.kind == "import_thunk"
        and ref.base == "__imp_ZwClose"
        and ref.target_symbol == "ZwClose"
        and ref.role == "import_thunk_call"
        for ref in result.packet.data_references
    )
    assert any(
        prototype.symbol == "ZwClose"
        and prototype.prototype.startswith("NTSTATUS ZwClose(")
        for prototype in result.packet.call_prototypes
    )
    site = result.packet.call_sites[0]
    assert site.call_name == "ZwClose"
    assert site.original_name == "ret"
    assert site.prototype is not None
    assert site.argument_facts[0].parameter_name in {"Handle", "ObjectHandle"}
    assert site.argument_facts[0].role in {"handle", "object_handle"}
    assert "return ZwClose(Handle);" in result.pretty_lift.pseudocode
    assert any(
        fact.kind == "data_reference" and fact.key == "import_thunk:__imp_ZwClose"
        for fact in result.packet.facts
    )
    assert "data_reference:import_thunk:__imp_ZwClose" in (
        result.validation.preserved_facts
    )

    bad = PrettyLift(
        function_name="ImportThunkCaller",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS ImportThunkCaller(void) { return STATUS_SUCCESS; }",
        confidence=0.9,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert "data_reference:import_thunk:__imp_ZwClose" in validation.missing_facts
    assert any(
        finding.fact == "data_reference:import_thunk:__imp_ZwClose"
        and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_windows_function_pretty_lift_recovers_module_qualified_import_thunk_dispatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180050180 {
    ret = *&[nt!__imp_?ZwClose@@YAXXZ];
    ret(arg0);
    return;
}
""",
            function_va=0x180050180,
            function_name="ModuleQualifiedImportThunkCaller",
        ),
    )

    assert any(
        access.kind == "read"
        and access.base == "nt!__imp_?ZwClose@@YAXXZ"
        and access.offset == 0
        for access in result.packet.memory_accesses
    )
    assert any(
        ref.kind == "import_thunk"
        and ref.base == "nt!__imp_?ZwClose@@YAXXZ"
        and ref.target_symbol == "ZwClose"
        and ref.role == "import_thunk_call"
        for ref in result.packet.data_references
    )
    site = result.packet.call_sites[0]
    assert site.call_name == "ZwClose"
    assert site.original_name == "ret"
    assert site.prototype is not None
    assert "return ZwClose(Handle);" in result.pretty_lift.pseudocode


def test_windows_function_pretty_lift_recovers_vtable_dispatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180050100 {
    ret = *&[arg0+0x18];
    ret(arg0, arg1);
    return;
}
""",
            function_va=0x180050100,
            function_name="VtableDispatch",
        ),
    )

    assert any(
        ref.kind == "vtable_dispatch"
        and ref.base == "arg0"
        and ref.offset == 0x18
        and ref.role == "vtable_method_call"
        for ref in result.packet.data_references
    )
    assert any(
        fact.kind == "data_reference" and fact.key == "vtable_dispatch:arg0+0x18"
        for fact in result.packet.facts
    )


def test_generic_lift_does_not_invent_query_prototype_for_pointer_writes(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_140007fc0 {
    var4 = *&[arg0];
    &[arg1+0x10] = var4;
    return;
}
""",
            function_va=0x140007FC0,
            function_name="sub_140007fc0",
        ),
    )

    pretty = result.pretty_lift.pseudocode
    assert "QueryIndex" not in pretty
    assert "NTSTATUS sub_140007fc0(void)" in pretty


def test_generic_lift_keeps_explicit_unknown_sections(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180030000 {
    var0 = arg0;
    unknown(vectorcall);
    ret = FUN_180012340(var0);
    return;
}
""",
            function_va=0x180030000,
            function_name="UnknownShape",
        ),
    )

    assert "unknown_sections" in result.packet.coverage
    assert any(
        section.kind == "unknown_operation" and section.label == "unknown(vectorcall)"
        for section in result.packet.unknown_sections
    )
    assert any(
        section.kind == "unresolved_symbol" and section.label == "FUN_180012340"
        for section in result.packet.unknown_sections
    )
    assert any(
        fact.kind == "unknown_section"
        and fact.key == "unknown_operation:unknown(vectorcall)"
        for fact in result.packet.facts
    )

    pretty = result.pretty_lift.pseudocode
    assert "Unknowns requiring analyst review" in pretty
    assert "unknown(vectorcall)" in pretty
    assert "FUN_180012340" in pretty

    bad = PrettyLift(
        function_name="UnknownShape",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS UnknownShape(void) { return STATUS_SUCCESS; }",
        confidence=0.8,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert (
        "unknown_section:unknown_operation:unknown(vectorcall)"
        in validation.missing_facts
    )


def test_generic_lift_summarizes_loops_and_validator_requires_them(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_180040000 {
    var0 = 0;
L_loop:
    %cf = (var0 u< arg1);
    if (!%cf) { goto L_done; }
    ProcessEntry(arg0, var0);
    var0 = (var0 + 1);
    goto L_loop;
L_done:
    return;
}
""",
            function_va=0x180040000,
            function_name="LoopShape",
        ),
    )

    assert "loop_summaries" in result.packet.coverage
    assert any(
        loop.loop_label == "L_loop"
        and loop.condition_expression == "var0 u< arg1"
        and loop.backedge_line > loop.header_line
        and loop.calls == ["ProcessEntry"]
        for loop in result.packet.loop_summaries
    )
    loop = next(
        item for item in result.packet.loop_summaries if item.loop_label == "L_loop"
    )
    assert any(
        fact.kind == "loop_summary"
        and fact.key == f"{loop.loop_label}:{loop.backedge_line}"
        for fact in result.packet.facts
    )

    pretty = result.pretty_lift.pseudocode
    assert "Loop summaries" in pretty
    assert "L_loop" in pretty
    assert "ProcessEntry" in pretty

    bad = PrettyLift(
        function_name="LoopShape",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS LoopShape(void) { ProcessEntry(); return STATUS_SUCCESS; }",
        confidence=0.8,
    )
    validation = validate_pretty_lift(result.packet, bad)
    assert validation.valid is False
    assert (
        f"loop_summary:{loop.loop_label}:{loop.backedge_line}"
        in validation.missing_facts
    )


def test_windows_function_pretty_lift_normalizes_stack_and_global_memory(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_18009faa0 {
    t0 = (*&[0x7ffe0308] & 1);
    stack_1 = arg0;
    ret = stack_1;
    &[arg1+0x18] = ret;
    return;
}
""",
            function_va=0x18009FAA0,
            function_name="MemoryShape",
        ),
    )

    accesses = result.packet.memory_accesses
    assert any(
        access.kind == "read"
        and access.absolute_address == 0x7FFE0308
        and access.role == "global"
        and access.base_object == "0x7ffe0308"
        and access.base_object_kind == "global"
        and access.pointer_class == "global_pointer"
        for access in accesses
    )
    assert any(
        access.kind == "write"
        and access.base == "stack_1"
        and access.role == "stack_slot"
        and access.base_object_kind == "stack"
        and access.pointer_class == "stack_pointer"
        for access in accesses
    )
    assert any(
        access.kind == "read"
        and access.base == "stack_1"
        and access.role == "stack_slot"
        for access in accesses
    )
    assert any(
        access.kind == "write"
        and access.base == "arg1"
        and access.offset == 0x18
        and access.role == "argument_memory"
        and access.base_object == "arg1"
        and access.base_object_kind == "argument"
        and access.pointer_class == "argument_pointer"
        and access.field_offset == 0x18
        and access.field_name == "field_0x18"
        for access in accesses
    )
    assert any(
        ref.kind == "global_memory" and ref.address == 0x7FFE0308
        for ref in result.packet.data_references
    )


def test_windows_function_pretty_lift_normalizes_typed_c_memory_accesses(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS MemoryShape(void *arg0, void *arg1, void *table, ULONG index) {
    value = *(uint32_t *)(arg0 + 0x14);
    *(uint16_t *)(arg1 + 2) = value;
    entry = *(void **)(table + index * 8 + 0x20);
    byte = *(UCHAR *)(arg0 - 1);
    return STATUS_SUCCESS;
}
""",
            function_va=0x18009FAA0,
            function_name="MemoryShape",
        ),
    )

    accesses = result.packet.memory_accesses
    assert any(
        access.kind == "read"
        and access.base == "arg0"
        and access.offset == 0x14
        and access.width_bits == 32
        and access.role == "argument_memory"
        for access in accesses
    )
    assert any(
        access.kind == "write"
        and access.base == "arg1"
        and access.offset == 2
        and access.width_bits == 16
        and access.role == "argument_memory"
        for access in accesses
    )
    assert any(
        access.kind == "read"
        and access.base == "table"
        and access.index == "index"
        and access.scale == 8
        and access.offset == 0x20
        and access.width_bits == 64
        and access.role == "selector_table"
        for access in accesses
    )
    assert any(
        access.kind == "read"
        and access.base == "arg0"
        and access.offset == -1
        and access.width_bits == 8
        for access in accesses
    )
    assert any(
        ref.kind == "selector_table_load"
        and ref.base == "table"
        and ref.index == "index"
        and ref.offset == 0x20
        for ref in result.packet.data_references
    )
    assert any(
        fact.kind == "memory_access"
        and fact.key == "read:table+index*8+0x20"
        and "selector_table" in fact.value
        and "width_bits=64" in fact.value
        and "base_kind=table" in fact.value
        and "pointer_class=table_pointer" in fact.value
        and "field=field_0x20" in fact.value
        for fact in result.packet.facts
    )


def test_windows_function_pretty_lift_classifies_typed_entry_memory_bases(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = tmp_path / "sample.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=ctx.file_path)
    try:
        xref_db.set_function_prototype(
            kb,
            "TypedMemoryShape",
            "NTSTATUS",
            [
                xref_db.FunctionParam("InputBuffer", "const void *", "input_buffer"),
                xref_db.FunctionParam("OutputBuffer", "void *", "output_buffer"),
                xref_db.FunctionParam("ReturnLength", "ULONG *", "return_length"),
                xref_db.FunctionParam("Irp", "void *", "irp"),
            ],
            set_by="manual",
            confidence=0.95,
        )
    finally:
        kb.close()

    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_18009fab0 {
    value = *&[arg0+0x10];
    &[arg1+0x18] = value;
    &[arg2] = value;
    major = *&[arg3+0xb8];
    return;
}
""",
            project_path=str(project),
            function_va=0x18009FAB0,
            function_name="TypedMemoryShape",
        ),
    )

    accesses = result.packet.memory_accesses
    assert any(
        access.kind == "read"
        and access.base == "arg0"
        and access.base_object == "InputBuffer"
        and access.base_object_kind == "argument"
        and access.pointer_class == "user_pointer_candidate"
        and access.field_offset == 0x10
        and access.field_name == "field_0x10"
        for access in accesses
    )
    assert any(
        access.kind == "write"
        and access.base == "arg1"
        and access.base_object == "OutputBuffer"
        and access.pointer_class == "user_pointer_candidate"
        and access.field_offset == 0x18
        for access in accesses
    )
    assert any(
        access.kind == "write"
        and access.base == "arg2"
        and access.base_object == "ReturnLength"
        and access.pointer_class == "user_pointer_candidate"
        and access.field_offset == 0
        for access in accesses
    )
    assert any(
        access.kind == "read"
        and access.base == "arg3"
        and access.base_object == "Irp"
        and access.pointer_class == "kernel_pointer_candidate"
        and access.field_offset == 0xB8
        for access in accesses
    )


def test_pretty_lift_validation_rejects_missing_copy_sink(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode=GLAURUNG_CMP_QUERY_BUILD_VERSION_IR,
            function_va=0x140796110,
            function_name="CmQueryBuildVersionInformation",
        ),
    )

    bad = PrettyLift(
        function_name="CmQueryBuildVersionInformation",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS CmQueryBuildVersionInformation(void) { return 0; }",
        confidence=0.2,
        assumptions=[],
        evidence_line_map={},
    )
    validation = validate_pretty_lift(result.packet, bad)

    assert validation.valid is False
    assert any(
        finding.fact == "calls:CmpQueryDowncastString"
        and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_pretty_lift_validation_rejects_missing_required_memory_access(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn sub_18009faa0 {
    t0 = (*&[0x7ffe0308] & 1);
    &[arg1+0x18] = t0;
    return;
}
""",
            function_va=0x18009FAA0,
            function_name="MemoryShape",
        ),
    )

    bad = PrettyLift(
        function_name="MemoryShape",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS MemoryShape(void) { return STATUS_SUCCESS; }",
        confidence=0.5,
        assumptions=[],
        evidence_line_map={},
    )
    validation = validate_pretty_lift(result.packet, bad)

    assert validation.valid is False
    assert any(
        finding.fact == "memory_access:write:arg1+0x18"
        and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_pretty_lift_validation_rejects_missing_api_contract_primitives(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS ContractShape(void *Out, void *Src, ULONG Len, HANDLE KeyHandle) {
    ProbeForWrite(Out, Len, 1);
    RtlCopyMemory(Out, Src, Len);
    ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, Out, Len, &ResultLength);
    return STATUS_SUCCESS;
}
""",
            function_va=0x180020000,
            function_name="ContractShape",
        ),
    )

    assert result.packet.primitive_counts["probe_for_write"] == 1
    assert result.packet.primitive_counts["user_buffer_copy"] == 1
    assert result.packet.primitive_counts["registry_query"] == 1

    bad = PrettyLift(
        function_name="ContractShape",
        prototype=result.pretty_lift.prototype,
        pseudocode="NTSTATUS ContractShape(void) { return STATUS_SUCCESS; }",
        confidence=0.8,
        assumptions=[],
        evidence_line_map={},
    )
    validation = validate_pretty_lift(result.packet, bad)

    assert validation.valid is False
    assert (
        "api_contract_primitive:probe_for_write:ProbeForWrite"
        in validation.missing_facts
    )
    assert (
        "api_contract_primitive:user_buffer_copy:RtlCopyMemory"
        in validation.missing_facts
    )
    assert (
        "api_contract_primitive:registry_query:ZwQueryValueKey"
        in validation.missing_facts
    )
    assert any(
        finding.fact == "api_contract_primitive:registry_query:ZwQueryValueKey"
        and finding.severity in {"error", "critical"}
        for finding in validation.findings
    )


def test_pretty_lift_validation_rejects_empty_raw_pseudocode() -> None:
    from glaurung.llm.tools.windows_function_pretty_lift import (
        WindowsFunctionLiftPacket,
    )

    lift_packet = WindowsFunctionLiftPacket(
        function_name="EmptyFunction",
        raw_pseudocode="",
        pseudocode_source="glaurung_decompiler",
        missing_capabilities=["raw_pseudocode"],
    )
    pretty = PrettyLift(
        function_name="EmptyFunction",
        prototype="NTSTATUS EmptyFunction(void)",
        pseudocode="NTSTATUS EmptyFunction(void) { return STATUS_SUCCESS; }",
        confidence=0.1,
    )

    validation = validate_pretty_lift(lift_packet, pretty)

    assert validation.valid is False
    assert "raw_pseudocode" in validation.missing_facts


def test_windows_function_pretty_lift_uses_pdb_public_range_fallback(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    def fake_decompile_at(*_args, **_kwargs):
        return ""

    def fake_decompile_range_at(
        _path,
        func_va,
        range_start,
        range_end,
        **_kwargs,
    ):
        assert func_va == 0x1000
        assert range_start == 0x1000
        assert range_end == 0x1020
        return "fn sub_1000 { ret = 0; return; }"

    def fake_analyze_pe_pdb_cache_path(*_args, **_kwargs):
        return {
            "public_symbols": [
                {"name": "Target", "va": 0x1000, "function": True},
                {"name": "Next", "va": 0x1020, "function": True},
            ]
        }

    ir = getattr(g, "ir")
    debug = getattr(g, "debug")

    monkeypatch.setattr(ir, "decompile_at", fake_decompile_at)
    monkeypatch.setattr(ir, "decompile_range_at", fake_decompile_range_at)
    monkeypatch.setattr(
        debug, "analyze_pe_pdb_cache_path", fake_analyze_pe_pdb_cache_path
    )

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(tmp_path / "sample.sys"),
            function_va=0x1000,
            function_name="Target",
            pdb_cache=str(tmp_path),
        ),
    )

    assert result.packet.pseudocode_source == "glaurung_decompiler_pdb_public_range"
    assert "raw_pseudocode" in result.packet.coverage


def test_windows_function_pretty_lift_uses_project_boundary_range_fallback(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    binary = tmp_path / "sample.sys"
    binary.write_bytes(b"MZ")
    project = tmp_path / "sample.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    try:
        xref_db.set_function_name(kb, 0x1000, "driver!Target", set_by="pdb")
        windows_boundaries.ensure_schema(kb)
        kb._conn.execute(
            "INSERT INTO function_boundaries "
            "(binary_id, entry_va, end_va, size, source, confidence, name, detail_json, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kb.binary_id,
                0x1000,
                0x1030,
                0x30,
                "pdb_symbol_adjacency",
                0.82,
                "driver!Target",
                '{"range_source":"symbol_adjacency"}',
                0,
            ),
        )
        kb._conn.commit()
    finally:
        kb.close()

    ctx = _ctx(tmp_path)
    tool = build_tool()

    def fake_decompile_at(*_args, **_kwargs):
        return ""

    def fake_decompile_range_at(
        _path,
        func_va,
        range_start,
        range_end,
        **_kwargs,
    ):
        assert func_va == 0x1000
        assert range_start == 0x1000
        assert range_end == 0x1030
        return "fn driver!Target { ret = 0; return; }"

    ir = getattr(g, "ir")
    monkeypatch.setattr(ir, "decompile_at", fake_decompile_at)
    monkeypatch.setattr(ir, "decompile_range_at", fake_decompile_range_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            function_va=0x1000,
        ),
    )

    assert result.packet.pseudocode_source == (
        "glaurung_decompiler_project_boundary_range"
    )
    assert "raw_pseudocode" in result.packet.coverage


def test_memory_agent_registers_windows_function_pretty_lift() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_function_pretty_lift" in agent._function_toolset.tools


def test_windows_pretty_lift_agent_prompt_and_structured_output(
    tmp_path: Path,
) -> None:
    from pydantic_ai.models.test import TestModel

    ctx = _ctx(tmp_path)
    tool = build_tool()
    packet_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode=GLAURUNG_CMP_QUERY_BUILD_VERSION_IR,
            function_va=0x140796110,
            function_name="CmQueryBuildVersionInformation",
        ),
    )
    prompt = build_windows_pretty_lift_prompt(packet_result.packet)

    assert "required_facts" in prompt
    assert "CmpQueryDowncastString" in prompt
    assert "call_sites" in prompt
    assert "path_conditions" in prompt
    assert "raw_pseudocode" in prompt

    agent = create_windows_pretty_lift_agent(model="test")
    model = TestModel(custom_output_args=packet_result.pretty_lift)
    result = agent.run_sync(prompt, model=model, deps=ctx)

    assert result.output.function_name == "CmQueryBuildVersionInformation"
    assert "STATUS_SUCCESS" in result.output.pseudocode


@PYTEST_MARK.skipif(not NTOSKRNL.exists(), reason="ntoskrnl fixture missing")
def test_ntoskrnl_cmp_query_build_version_pretty_lift_fixture(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(NTOSKRNL),
            function_va=0x140796110,
            range_start=0x140796110,
            range_end=0x14079625C,
            function_name="CmQueryBuildVersionInformation",
            pdb_cache=str(FIXTURE_DIR),
            max_blocks=1024,
            max_instructions=50_000,
            timeout_ms=5_000,
        ),
    )

    assert result.validation.valid is True
    assert result.pretty_lift.quality_score >= 0.85
    assert "version = CmpLayerVersions[index];" in result.pretty_lift.pseudocode
    assert "CmpQueryDowncastString" in result.pretty_lift.pseudocode
    assert "goto " not in result.pretty_lift.pseudocode
    assert "unaff_" not in result.pretty_lift.pseudocode
    assert "FUN_" not in result.pretty_lift.pseudocode
