from __future__ import annotations


_IMPLIED_GATE_FACTS: dict[str, tuple[str, ...]] = {
    "user_pointer_write_range_valid": ("destination_range_valid",),
    "user_pointer_read_range_valid": ("source_range_valid",),
}


def expanded_gate_facts(proves: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for fact in proves:
        for value in (fact, *_IMPLIED_GATE_FACTS.get(fact, ())):
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
    return out


def matched_required_gates(proves: list[str], required_gates: list[str]) -> list[str]:
    expanded = set(expanded_gate_facts(proves))
    return [required for required in required_gates if required in expanded]


def missing_required_gates(proves: list[str], required_gates: list[str]) -> list[str]:
    expanded = set(expanded_gate_facts(proves))
    return [required for required in required_gates if required not in expanded]
