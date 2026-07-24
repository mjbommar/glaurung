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

import os

INT_MIN = -(2**31)
INT_MAX = 2**31 - 1
UINT_MAX = 2**32 - 1

# Pointer buffer elements to allocate by default. Scalar args flagged `len_args`
# are clamped to [0, ptr_len] so in-process ctypes calls stay in bounds.
DEFAULT_PTR_LEN = 16

# Seeded-fuzz trial count. Shared by the baseline generator and the matrix gate
# so both exercise IDENTICAL vectors (the fuzz seed is stable across processes);
# a mismatch would surface as phantom regressions/improvements.
FIXTURE_FUZZ = 12

# (fixture, function) -> contract override.
#   ptr_len:      int    — buffer elements for pointer params.
#   ptr_elem:     str    — pointer element type: "int" (default, 4B) or "u8"
#                          (1B; required for byte-accurate wire buffers).
#   len_args:     [int]  — scalar param indices that are a length/count into the
#                          buffer; clamped to [0, ptr_len].
#   extra_vectors:[[...]]— explicit arg tuples (scalar=int, pointer=list[int]).
#                          NOT clamped — used for exact case/boundary/packet inputs.
#   skip_exec:    bool   — not safely executable; checked structurally instead.
OVERRIDES: dict[tuple[str, str], dict] = {
    ("01_conditional_polarity", "early_return_ge"): {
        "extra_vectors": [[99], [100], [101], [INT_MIN], [INT_MAX]],
    },
    # 04: switch discriminant recovery — drive EXACTLY each real case constant
    # (not positional 0/1/2/...), plus a default/fall-off value. A decompiler
    # that relabels or fabricates a discriminant sends one of these to the wrong
    # arm and the unique per-case return diverges.
    ("04_switch_shapes", "dense_jumptable"): {
        "extra_vectors": [[0], [1], [2], [3], [4], [5], [6], [7], [8], [15]],
    },
    ("04_switch_shapes", "sparse_switch"): {
        "extra_vectors": [[1], [5], [17], [100], [0], [999]],
    },
    ("04_switch_shapes", "negative_cases"): {
        "extra_vectors": [[-3], [-1], [0], [2], [5], [-100]],
    },
    ("04_switch_shapes", "shared_bodies"): {
        "extra_vectors": [[0], [2], [1], [3], [4], [8]],  # 0,2->500  1,3->600
    },
    ("04_switch_shapes", "explicit_fallthrough"): {
        "extra_vectors": [[0], [1], [2], [3]],  # 0 falls through into 1
    },
    ("04_switch_shapes", "no_default"): {
        "extra_vectors": [[2], [5], [0], [3]],  # only 2,5 are cases
    },
    # 06: functions that take >6 args exercise stack-arg recovery; recursion /
    # tail calls. Length-free, all scalar — safe to execute directly.
    # 07: bounded wire parser. The buffer is BYTES (u8), the second arg is the
    # message length. Drive it with byte-accurate valid and each-distinct-invalid
    # packet so a mis-decompiled bounds relationship (length vs remaining) shows
    # up as a wrong error code or an OOB access. Header is 8 bytes, big-endian:
    #   magic=0xC0DE, ver_type=(ver<<4|type), flags, length(be16), reserved(be16).
    ("07_packet_parser", "validate_header"): {
        "ptr_elem": "u8", "ptr_len": 32, "len_args": [1],
        "extra_vectors": [
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00], 12),  # ok -> 0
            ([0x00, 0x00, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00], 12),  # bad magic -> -3
            ([0xC0, 0xDE, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00], 8),   # bad version -> -4
            ([0xC0, 0xDE, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00], 8),   # type 0 -> -5
            ([0xC0, 0xDE, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00], 8),   # type 8 -> -5
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0xFF, 0x00, 0x00], 8),   # len overrun -> -6
            ([0xC0, 0xDE], 4),                                        # too short -> -2
        ],
    },
    ("07_packet_parser", "decode_header"): {"ptr_elem": "u8", "ptr_len": 32, "len_args": [1]},
    ("07_packet_parser", "parse_packet"): {
        "ptr_elem": "u8", "ptr_len": 32, "len_args": [1],
        "extra_vectors": [
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44], 12),  # ok
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00], 8),   # ok, empty payload
            ([0x00, 0x00, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00], 12),  # bad magic -> -3
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0xFF, 0x00, 0x00], 10),  # len overrun -> -6
            ([0xC0, 0xDE], 4),                                        # too short -> -2
        ],
    },
    # 09: buffer transforms — the count arg indexes the buffer.
    ("09_memory_effects", "mem_copy"): {"len_args": [2]},
    ("09_memory_effects", "mem_set"): {"len_args": [2]},
    ("09_memory_effects", "vec_sum"): {"len_args": [1]},
    ("09_memory_effects", "vec_transform"): {"len_args": [1]},
    # 08: apply() takes a function pointer — not int-differential; check structurally.
    ("08_indirect_dispatch", "apply"): {"skip_exec": True},
}

# Structural expectations for the structural lane (checked on decompiled text, not
# by execution): effects/constructs that MUST survive lowering. `indirect_call` —
# a call through a computed/loaded pointer (operations table / callback) must be
# emitted, not dropped or replaced by a fabricated direct target. `memory_store` —
# a write to memory must survive (not be dead-store-eliminated away).
STRUCTURAL: dict[tuple[str, str], dict] = {
    ("08_indirect_dispatch", "dispatch"): {"indirect_call": True},
    ("08_indirect_dispatch", "apply"): {"indirect_call": True},
    ("08_indirect_dispatch", "tail_dispatch"): {"indirect_call": True},
    ("09_memory_effects", "mem_set"): {"memory_store": True},
    ("09_memory_effects", "mem_copy"): {"memory_store": True},
    ("09_memory_effects", "cas_update"): {"memory_store": True},
    ("09_memory_effects", "vec_transform"): {"memory_store": True},
    ("09_memory_effects", "tick"): {"memory_store": True},  # volatile store must survive
    # C++ runtime shapes — initial vtable/EH assertions (ratchet upward).
    ("10_cpp_runtime_shapes", "cpp_virtual_dispatch"): {"indirect_call": True},  # vtable dispatch
    ("10_cpp_runtime_shapes", "cpp_ctor_dtor"): {"memory_store": True},          # ctor/dtor markers
    ("10_cpp_runtime_shapes", "cpp_raii_guard"): {"memory_store": True},         # cleanup write
    ("10_cpp_runtime_shapes", "cpp_exception"): {"nonempty": True},              # EH body recovered
}


def structural_spec(fixture: str, func: str) -> dict:
    return STRUCTURAL.get((fixture, func), {})

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
    # Only exported (non-static) functions — read_be16/read_be32/decode_header are
    # `static` (inlined away at O2, never dynamically loadable) so they are not
    # required and not execution-tested.
    "07_packet_parser": ["validate_header", "parse_packet"],
    "08_indirect_dispatch": ["dispatch", "dispatch_switch", "tail_dispatch", "apply"],
    "09_memory_effects": [
        "tick", "read_counter", "cas_update", "mem_copy", "mem_set", "vec_sum",
        "vec_transform",
    ],
    "10_cpp_runtime_shapes": [
        "cpp_virtual_dispatch", "cpp_ctor_dtor", "cpp_raii_guard", "cpp_exception",
        "cpp_lambda_capture", "cpp_move",
    ],
}


def tmpdir() -> str | None:
    """A writable directory for isolated build/exec scratch, or None (system
    tempfile default). Honors GLAURUNG_FIXTURE_TMPDIR then TMPDIR, ignoring any
    that is missing/unwritable — so the harness is portable to a CI runner that
    has no `/nas4/...` path. Never hardcode a machine-specific path."""
    for env in ("GLAURUNG_FIXTURE_TMPDIR", "TMPDIR"):
        p = os.environ.get(env)
        if p and os.path.isdir(p) and os.access(p, os.W_OK):
            return p
    return None


def override(fixture: str, func: str) -> dict:
    return OVERRIDES.get((fixture, func), {})


def scalar_boundaries(width: int = 4, signed: bool = True) -> list[int]:
    """Deterministic values a scalar arg of this width/signedness is tried at
    (plus seeded fuzz). Includes each type's extremes and — for 64-bit — values
    with the high 32 bits set, so a dropped/zero-extended high half is caught."""
    common = [0, 1, 2, 7, 10, 100]
    lo_hi = {
        1: (-0x80, 0x7F) if signed else (0, 0xFF),
        2: (-0x8000, 0x7FFF) if signed else (0, 0xFFFF),
        4: (INT_MIN, INT_MAX) if signed else (0, UINT_MAX),
        8: (-(2**63), 2**63 - 1) if signed else (0, 2**64 - 1),
    }[width]
    vals = list(common) + list(lo_hi)
    if signed:
        vals += [-1, -2]
    if width >= 8:
        # values whose high 32 bits are non-zero — expose truncated 64-bit paths
        vals += [0x1_0000_0007, 0x7FFF_FFFF_8000_0001 if signed else 0xFFFF_FFFF_0000_0001]
    # de-dupe preserving order
    seen, out = set(), []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
