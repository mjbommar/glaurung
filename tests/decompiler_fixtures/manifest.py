"""Declarative oracle for the decompiler fixture corpus.

The harness recovers each function's signature from DWARF; this manifest supplies
the *safe, deterministic* execution contract DWARF cannot:

  * REQUIRED_FUNCTIONS — functions that MUST exist (a renamed/dropped symbol
    fails the gate);
  * OVERRIDES — pointer buffer allocation length + which scalar args are
    lengths/indices into that buffer (so a random -64..63 is never passed as a
    length and we never write out of bounds), plus extra deterministic vectors
    and a `skip_exec` flag for constructs not safely executable in-process yet.

Per-function pass/fail expectations are NOT here — they live in the generated,
committed `baseline.json`, so the gate fails only on NEW regressions while known
bugs stay visible. Everything here is data, read by `tools/diff_decompile.py`.
"""
from __future__ import annotations

INT_MIN = -(2**31)
INT_MAX = 2**31 - 1
UINT_MAX = 2**32 - 1

# Pointer buffer elements to allocate by default. Scalar args flagged `len_args`
# are clamped to [0, ptr_len] so in-process ctypes calls stay in bounds.
DEFAULT_PTR_LEN = 16

# (fixture, function) -> contract override.
#   ptr_len:      int    — buffer elements for pointer params.
#   len_args:     [int]  — scalar param indices that are a length/count into the
#                          buffer; clamped to [0, ptr_len].
#   extra_vectors:[[...]]— explicit arg tuples (scalar=int, pointer=list[int]).
#   skip_exec:    bool   — not safely executable; checked structurally instead.
OVERRIDES: dict[tuple[str, str], dict] = {
    ("01_conditional_polarity", "early_return_ge"): {
        "extra_vectors": [[99], [100], [101], [INT_MIN], [INT_MAX]],
    },
    # 06: functions that take >6 args exercise stack-arg recovery; recursion /
    # tail calls. Length-free, all scalar — safe to execute directly.
    # 07: bounded parser — the second arg is the message length.
    ("07_packet_parser", "validate_header"): {"len_args": [1]},
    ("07_packet_parser", "decode_header"): {"len_args": [1]},
    ("07_packet_parser", "parse_packet"): {"len_args": [1]},
    # 09: buffer transforms — the count arg indexes the buffer.
    ("09_memory_effects", "mem_copy"): {"len_args": [2]},
    ("09_memory_effects", "mem_set"): {"len_args": [2]},
    ("09_memory_effects", "vec_sum"): {"len_args": [1]},
    ("09_memory_effects", "vec_transform"): {"len_args": [1]},
    # 08: apply() takes a function pointer — not int-differential; check structurally.
    ("08_indirect_dispatch", "apply"): {"skip_exec": True},
}

# Functions that MUST be present in each fixture (real names; a missing one fails
# the gate). Not exhaustive — enough to catch a dropped/renamed symbol.
REQUIRED_FUNCTIONS: dict[str, list[str]] = {
    "01_conditional_polarity": [
        "cmp_signed", "cmp_unsigned", "early_return", "early_return_ge",
        "nested", "elseif", "ternary", "sc_and", "sc_or", "classify",
    ],
    "02_integer_widths": [
        "rt_u8", "rt_u16", "rt_u32", "rt_u64", "sext_i8", "zext_u32_to_u64",
        "trunc_u8", "sar_signed", "shr_unsigned",
    ],
    "03_loop_shapes": [
        "for_sum", "dowhile_atleastonce", "while_reload_header", "loop_break",
        "loop_continue", "nested_pairs",
    ],
    "04_switch_shapes": [
        "dense_jumptable", "sparse_switch", "negative_cases", "shared_bodies",
        "explicit_fallthrough", "no_default",
    ],
    "05_cleanup_and_state_machine": ["fsm", "process"],
    "06_calling_conventions": [
        "sum_arg0", "sum_arg1", "sum_arg2", "sum_arg6", "sum_arg7", "sum_arg10",
        "fib", "fact_mod",
    ],
    "07_packet_parser": [
        "read_be16", "read_be32", "validate_header", "decode_header", "parse_packet",
    ],
    "08_indirect_dispatch": ["dispatch", "dispatch_switch", "tail_dispatch", "apply"],
    "09_memory_effects": [
        "tick", "read_counter", "cas_update", "mem_copy", "mem_set", "vec_sum",
        "vec_transform",
    ],
}


def override(fixture: str, func: str) -> dict:
    return OVERRIDES.get((fixture, func), {})


def scalar_boundaries() -> list[int]:
    """Deterministic values every scalar arg is tried at (plus seeded fuzz)."""
    return [0, 1, -1, 2, -2, 7, 10, 100, INT_MIN, INT_MAX, 0x7FFF, -0x8000]
