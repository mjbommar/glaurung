from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_api_contract_rule_scan import build_tool


PSEUDOCODE = """
NTSTATUS NtExample(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength) {
  NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
  switch (SystemInformationClass) {
  case 0x42:
    if (SystemInformationLength == 0) {
      status = STATUS_SUCCESS;
    }
    ProbeForWrite(SystemInformation, SystemInformationLength, 1);
    Helper(SystemInformation, SystemInformationLength, ReturnLength);
    *ReturnLength = 4;
    break;
  }
  return status;
}
"""


GLAURUNG_IR_PSEUDOCODE = """
fn sub_140796110(arg0, arg1, arg2, arg3, arg4) {
  %zf = (arg1 == 4);
  %cf = (arg3 u< 580);
  var4 = *&[arg0];
  var0 = 0x140c13ec0;
  var0 = *&[var0+ret*8];
  &[var1] = var6;
  &[var1+0x14] = ret;
  CmpQueryDowncastString((var1 + 20), var4, (var0 + 16));
  RtlUnicodeStringToAnsiString((rsp + 32), ret, 0);
}
"""


NO_PROBE_PSEUDOCODE = """
NTSTATUS NtExample(PVOID UserOutputBuffer, ULONG Length) {
  if (Length < 8) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  *UserOutputBuffer = 0;
  return STATUS_SUCCESS;
}
"""


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_api_contract_rule_scan_flags_review_patterns(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(pseudocode=PSEUDOCODE, add_to_kb=True),
    )

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "selector_routes_pointer_to_helper" in rule_ids
    assert "zero_length_probe_boundary" in rule_ids
    assert "return_length_write_after_error_status" in rule_ids
    assert result.primitive_counts["probe_for_write"] == 1
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_api_contract_rule_scan"
        for node in ctx.kb.nodes()
    )


def test_windows_api_contract_rule_scan_flags_writes_without_probe(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(pseudocode=NO_PROBE_PSEUDOCODE))

    assert "probe_primitives" in result.missing_capabilities
    assert any(
        finding.rule_id == "user_pointer_write_without_probe"
        for finding in result.findings
    )


def test_windows_api_contract_rule_scan_flags_selector_table_to_string_sink(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(pseudocode=GLAURUNG_IR_PSEUDOCODE),
    )

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "selector_global_table_to_string_copy" in rule_ids
    assert "user_pointer_write_without_probe" in rule_ids
    assert result.primitive_counts["string_conversion_copy"] >= 2


def test_memory_agent_registers_windows_api_contract_rule_scan() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_api_contract_rule_scan" in agent._function_toolset.tools
