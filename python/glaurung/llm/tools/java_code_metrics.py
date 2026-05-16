from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class JavaInstructionMetrics(BaseModel):
    branch_instruction_count: int = 0
    switch_instruction_count: int = 0
    invoke_instruction_count: int = 0
    field_instruction_count: int = 0
    class_instruction_count: int = 0
    constant_load_instruction_count: int = 0
    string_constant_count: int = 0
    dynamic_instruction_count: int = 0
    return_instruction_count: int = 0
    throw_instruction_count: int = 0
    monitor_instruction_count: int = 0
    allocation_instruction_count: int = 0
    array_allocation_instruction_count: int = 0


class JavaCodeRollup(JavaInstructionMetrics):
    methods_with_code: int = 0
    methods_with_line_numbers: int = 0
    methods_with_local_variables: int = 0
    method_code_length_total: int = 0
    method_instruction_count: int = 0
    method_unknown_instruction_count: int = 0
    method_stack_map_frame_count: int = 0
    method_line_number_count: int = 0
    first_line: int | None = None
    last_line: int | None = None
    method_local_variable_count: int = 0
    method_local_variable_type_count: int = 0
    method_exception_handler_count: int = 0
    code_type_annotation_count: int = 0


BRANCH_MNEMONICS = {
    "ifeq",
    "ifne",
    "iflt",
    "ifge",
    "ifgt",
    "ifle",
    "if_icmpeq",
    "if_icmpne",
    "if_icmplt",
    "if_icmpge",
    "if_icmpgt",
    "if_icmple",
    "if_acmpeq",
    "if_acmpne",
    "goto",
    "jsr",
    "ifnull",
    "ifnonnull",
    "goto_w",
    "jsr_w",
}
SWITCH_MNEMONICS = {"tableswitch", "lookupswitch"}
INVOKE_MNEMONICS = {
    "invokevirtual",
    "invokespecial",
    "invokestatic",
    "invokeinterface",
    "invokedynamic",
}
FIELD_MNEMONICS = {"getstatic", "putstatic", "getfield", "putfield"}
CLASS_MNEMONICS = {"new", "anewarray", "checkcast", "instanceof", "multianewarray"}
CONSTANT_LOAD_MNEMONICS = {"ldc", "ldc_w", "ldc2_w"}
RETURN_MNEMONICS = {
    "ireturn",
    "lreturn",
    "freturn",
    "dreturn",
    "areturn",
    "return",
}
ALLOCATION_MNEMONICS = {"new", "newarray", "anewarray", "multianewarray"}
ARRAY_ALLOCATION_MNEMONICS = {"newarray", "anewarray", "multianewarray"}


def instruction_metrics(code: Any) -> JavaInstructionMetrics:
    """Return stable instruction category counts for parsed Java Code data."""
    if not isinstance(code, dict):
        return JavaInstructionMetrics()
    metrics = JavaInstructionMetrics()
    instructions = code.get("instructions")
    if isinstance(instructions, list):
        for instruction in instructions:
            if not isinstance(instruction, dict):
                continue
            mnemonic = str(instruction.get("mnemonic") or "")
            if mnemonic in BRANCH_MNEMONICS:
                metrics.branch_instruction_count += 1
            if mnemonic in SWITCH_MNEMONICS:
                metrics.switch_instruction_count += 1
            if mnemonic in INVOKE_MNEMONICS:
                metrics.invoke_instruction_count += 1
            if mnemonic in FIELD_MNEMONICS:
                metrics.field_instruction_count += 1
            if mnemonic in CLASS_MNEMONICS:
                metrics.class_instruction_count += 1
            if mnemonic in CONSTANT_LOAD_MNEMONICS:
                metrics.constant_load_instruction_count += 1
            if mnemonic == "invokedynamic":
                metrics.dynamic_instruction_count += 1
            if mnemonic in RETURN_MNEMONICS:
                metrics.return_instruction_count += 1
            if mnemonic == "athrow":
                metrics.throw_instruction_count += 1
            if mnemonic in {"monitorenter", "monitorexit"}:
                metrics.monitor_instruction_count += 1
            if mnemonic in ALLOCATION_MNEMONICS:
                metrics.allocation_instruction_count += 1
            if mnemonic in ARRAY_ALLOCATION_MNEMONICS:
                metrics.array_allocation_instruction_count += 1

    xrefs = code.get("xrefs")
    if isinstance(xrefs, list):
        metrics.string_constant_count = sum(
            1
            for xref in xrefs
            if isinstance(xref, dict) and xref.get("kind") == "string"
        )
        metrics.dynamic_instruction_count = max(
            metrics.dynamic_instruction_count,
            sum(
                1
                for xref in xrefs
                if isinstance(xref, dict)
                and xref.get("kind") in {"dynamic", "invokedynamic"}
            ),
        )
    return metrics


def merge_instruction_metrics(
    metrics: list[JavaInstructionMetrics],
) -> JavaInstructionMetrics:
    """Return the field-wise sum of instruction metrics."""
    merged = JavaInstructionMetrics()
    for item in metrics:
        for field in type(merged).model_fields:
            setattr(merged, field, getattr(merged, field) + getattr(item, field))
    return merged


def class_code_rollup(methods: Any) -> JavaCodeRollup:
    """Aggregate debug and bytecode metrics over parsed Java methods."""
    rollup = JavaCodeRollup()
    if not isinstance(methods, list):
        return rollup
    lines: list[int] = []
    instruction_metric_items: list[JavaInstructionMetrics] = []
    for method in methods:
        if not isinstance(method, dict):
            continue
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        rollup.methods_with_code += 1
        rollup.method_code_length_total += int(code.get("code_length", 0))
        rollup.method_instruction_count += int(code.get("instruction_count", 0))
        rollup.method_unknown_instruction_count += int(
            code.get("unknown_instruction_count", 0)
        )
        rollup.method_stack_map_frame_count += int(code.get("stack_map_frame_count", 0))
        rollup.method_exception_handler_count += int(code.get("exception_table_len", 0))
        rollup.code_type_annotation_count += int(code.get("type_annotation_count", 0))
        code_lines = _line_numbers(code)
        lines.extend(code_lines)
        if code_lines:
            rollup.methods_with_line_numbers += 1
        local_variable_count = _list_count(code.get("local_variables"))
        local_variable_type_count = _list_count(code.get("local_variable_types"))
        rollup.method_local_variable_count += local_variable_count
        rollup.method_local_variable_type_count += local_variable_type_count
        if local_variable_count:
            rollup.methods_with_local_variables += 1
        instruction_metric_items.append(instruction_metrics(code))
    rollup.method_line_number_count = len(lines)
    rollup.first_line = min(lines) if lines else None
    rollup.last_line = max(lines) if lines else None
    merged_metrics = merge_instruction_metrics(instruction_metric_items)
    for field in type(merged_metrics).model_fields:
        setattr(rollup, field, getattr(merged_metrics, field))
    return rollup


def _line_numbers(code: dict[str, Any]) -> list[int]:
    line_numbers = code.get("line_numbers")
    if not isinstance(line_numbers, list):
        return []
    out: list[int] = []
    for line in line_numbers:
        if not isinstance(line, dict):
            continue
        value = line.get("line_number")
        if isinstance(value, int):
            out.append(value)
    return out


def _list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0
