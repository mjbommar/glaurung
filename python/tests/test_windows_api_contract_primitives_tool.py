from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_api_contract_primitives import build_tool


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


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_api_contract_primitives_extracts_low_level_facts(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(pseudocode=PSEUDOCODE, add_to_kb=True),
    )

    roles = {param.name: param.role for param in result.parameters}
    assert roles["SystemInformationClass"] == "selector"
    assert roles["SystemInformation"] == "pointer"
    assert roles["SystemInformationLength"] == "length"
    assert roles["ReturnLength"] == "return_length"
    assert result.primitive_counts["selector_dispatch"] >= 1
    assert result.primitive_counts["length_comparison"] == 1
    assert result.primitive_counts["probe_for_write"] == 1
    assert result.primitive_counts["syscall_argument_forward"] == 1
    assert result.primitive_counts["return_length_write"] == 1
    assert result.primitive_counts["error_status_assignment"] >= 1
    assert "probe_primitives" not in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_api_contract_primitives"
        for node in ctx.kb.nodes()
    )


def test_windows_api_contract_primitives_understands_glaurung_ir_and_rtl_sinks(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(pseudocode=GLAURUNG_IR_PSEUDOCODE),
    )

    assert result.primitive_counts["length_comparison"] >= 2
    assert result.primitive_counts["selector_dispatch"] >= 2
    assert result.primitive_counts["pointer_write"] >= 2
    assert result.primitive_counts["string_conversion_copy"] >= 2

    pointer_writes = [
        item for item in result.primitives if item.kind == "pointer_write"
    ]
    assert any(item.expressions == ["&[var1+0x14]"] for item in pointer_writes)

    sinks = [
        item for item in result.primitives if item.kind == "string_conversion_copy"
    ]
    assert any("RtlUnicodeStringToAnsiString" in item.snippet for item in sinks)
    assert any("CmpQueryDowncastString" in item.snippet for item in sinks)
    assert "string_conversion_sinks" in result.coverage
    assert "selector_dispatch" not in result.missing_capabilities


def test_windows_api_contract_primitives_classifies_ioctl_and_pool_apis(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS DriverControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, InputLength, 'gaTG');
  NtDeviceIoControlFile(Handle, 0, 0, 0, &IoStatus, IoctlCode, InputBuffer, InputLength, OutputBuffer, OutputLength);
  IoBuildDeviceIoControlRequest(IoctlCode, DeviceObject, InputBuffer, InputLength, OutputBuffer, OutputLength, FALSE, 0, &IoStatus);
  ExFreePoolWithTag(buffer, 'gaTG');
  return STATUS_SUCCESS;
}
""",
        ),
    )

    assert result.primitive_counts["ioctl_call"] == 2
    assert result.primitive_counts["pool_allocation"] == 1
    assert result.primitive_counts["pool_free"] == 1
    ioctl = [item for item in result.primitives if item.kind == "ioctl_call"][0]
    assert ioctl.roles["ioctl_code"] == "value"
    assert ioctl.roles["input_buffer"] == "input_buffer"
    assert ioctl.roles["output_length"] == "length"
    pool = [item for item in result.primitives if item.kind == "pool_allocation"][0]
    assert pool.roles["size"] == "length"
    assert "ioctl_call" in result.coverage
    assert "pool_allocation" in result.coverage


def test_windows_api_contract_primitives_classifies_kernel_contract_families(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS DriverPath(PIRP Irp, PMDL Mdl, HANDLE KeyHandle, PVOID UserBuffer) {
  ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, KeyInfo, KeyInfoLength, &ResultLength);
  ZwSetValueKey(KeyHandle, &ValueName, 0, REG_BINARY, UserBuffer, UserBufferLength);
  ObReferenceObjectByHandle(UserHandle, DesiredAccess, *IoFileObjectType, UserMode, &Object, NULL);
  stack = IoGetCurrentIrpStackLocation(Irp);
  MmProbeAndLockPages(Mdl, UserMode, IoWriteAccess);
  system = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
  NtAlpcSendWaitReceivePort(Port, 0, &Send, NULL, &Receive, &Length, NULL, NULL);
  EtwWrite(Provider, &Descriptor, 0, NULL);
  PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE);
  KeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer, &OutputLength);
  ObDereferenceObject(Object);
  return STATUS_SUCCESS;
}
""",
        ),
    )

    assert result.primitive_counts["registry_query"] == 1
    assert result.primitive_counts["registry_write"] == 1
    assert result.primitive_counts["object_reference"] == 1
    assert result.primitive_counts["object_release"] == 1
    assert result.primitive_counts["irp_access"] == 1
    assert result.primitive_counts["mdl_access"] == 2
    assert result.primitive_counts["alpc_message"] == 1
    assert result.primitive_counts["trace_emit"] == 1
    assert result.primitive_counts["callback_registration"] == 1
    assert result.primitive_counts["callback_dispatch"] == 1

    registry = [item for item in result.primitives if item.kind == "registry_query"][0]
    assert registry.roles["key_value_information"] == "output_buffer"
    assert registry.roles["result_length"] == "return_length"
    object_ref = [
        item for item in result.primitives if item.kind == "object_reference"
    ][0]
    assert object_ref.roles["object"] == "output_object"
    mdl = [item for item in result.primitives if item.kind == "mdl_access"][0]
    assert mdl.roles["mdl"] == "mdl"
    callback = [item for item in result.primitives if item.kind == "callback_dispatch"][
        0
    ]
    assert callback.roles["output_buffer"] == "output_buffer"
    assert "registry_query" in result.coverage
    assert "callback_dispatch" in result.coverage


def test_windows_api_contract_primitives_classifies_irp_ioctl_fields(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  irpSp = IoGetCurrentIrpStackLocation(Irp);
  code = irpSp->Parameters.DeviceIoControl.IoControlCode;
  inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
  outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
  type3 = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
  system = Irp->AssociatedIrp.SystemBuffer;
  user = Irp->UserBuffer;
  mdl = Irp->MdlAddress;
  requestor = Irp->RequestorMode;
  Irp->IoStatus.Information = outLen;
  return STATUS_SUCCESS;
}
""",
        ),
    )

    assert result.primitive_counts["irp_access"] == 1
    assert result.primitive_counts["ioctl_stack_parameter"] == 4
    assert result.primitive_counts["irp_buffer_access"] == 5

    ioctl_fields = [
        item for item in result.primitives if item.kind == "ioctl_stack_parameter"
    ]
    assert any(item.roles.get("ioctl_code") == "value" for item in ioctl_fields)
    assert any(item.roles.get("input_length") == "length" for item in ioctl_fields)
    assert any(
        item.roles.get("output_length") == "return_length" for item in ioctl_fields
    )
    assert any(
        item.roles.get("type3_input_buffer") == "input_buffer" for item in ioctl_fields
    )

    irp_fields = [
        item for item in result.primitives if item.kind == "irp_buffer_access"
    ]
    assert any(
        item.roles.get("system_buffer") == "input_output_buffer" for item in irp_fields
    )
    assert any(item.roles.get("user_buffer") == "user_pointer" for item in irp_fields)
    assert any(item.roles.get("mdl_address") == "mdl" for item in irp_fields)
    assert any(item.roles.get("requestor_mode") == "access_mode" for item in irp_fields)
    assert any(
        item.roles.get("io_status_information") == "return_length"
        for item in irp_fields
    )
    assert "ioctl_stack_parameter" in result.coverage
    assert "irp_buffer_access" in result.coverage


def test_windows_api_contract_primitives_classifies_wdf_request_buffers(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode) {
  WdfRequestGetParameters(Request, &Params);
  WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &InputBuffer, &InLength);
  WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &OutputBuffer, &OutLength);
  WdfRequestRetrieveUnsafeUserInputBuffer(Request, 16, &UserInput, &UserInputLength);
  WdfRequestRetrieveUnsafeUserOutputBuffer(Request, 32, &UserOutput, &UserOutputLength);
  return STATUS_SUCCESS;
}
""",
        ),
    )

    assert result.primitive_counts["ioctl_stack_parameter"] == 1
    assert result.primitive_counts["wdf_request_buffer_access"] == 4

    buffers = [
        item for item in result.primitives if item.kind == "wdf_request_buffer_access"
    ]
    assert any(item.roles.get("input_buffer") == "input_buffer" for item in buffers)
    assert any(item.roles.get("output_buffer") == "output_buffer" for item in buffers)
    assert all(item.roles["request"] == "request" for item in buffers)
    assert "wdf_request_buffer_access" in result.coverage


def test_windows_api_contract_primitives_classifies_security_boundary_apis(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
NTSTATUS SecurityPath(PIRP Irp, PEPROCESS Process, PACCESS_STATE AccessState) {
  mode = ExGetPreviousMode();
  requestor = IoGetRequestorMode(Irp);
  if (!SeSinglePrivilegeCheck(SeLoadDriverPrivilege, mode)) {
    return STATUS_PRIVILEGE_NOT_HELD;
  }
  if (!SePrivilegeCheck(&Privileges, &SubjectContext, requestor)) {
    return STATUS_ACCESS_DENIED;
  }
  token = PsReferencePrimaryToken(Process);
  SeQueryInformationToken(token, TokenUser, &TokenInfo);
  PsDereferencePrimaryToken(token);
  return STATUS_SUCCESS;
}
""",
        ),
    )

    assert result.primitive_counts["requestor_mode_read"] == 2
    assert result.primitive_counts["privilege_check"] == 2
    assert result.primitive_counts["token_reference"] == 1
    assert result.primitive_counts["token_query"] == 1
    assert result.primitive_counts["token_release"] == 1

    privilege = [item for item in result.primitives if item.kind == "privilege_check"][
        0
    ]
    assert privilege.roles["privilege"] == "privilege"
    assert privilege.roles["access_mode"] == "access_mode"
    mode = [item for item in result.primitives if item.kind == "requestor_mode_read"][1]
    assert mode.roles["irp"] == "irp"
    token = [item for item in result.primitives if item.kind == "token_query"][0]
    assert token.roles["token"] == "token"
    assert token.roles["token_information"] == "output_buffer"
    assert "privilege_check" in result.coverage
    assert "token_reference" in result.coverage


def test_memory_agent_registers_windows_api_contract_primitives() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_api_contract_primitives" in agent._function_toolset.tools
