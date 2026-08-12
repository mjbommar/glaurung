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
import pathlib as _pathlib

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
#   ptr_elem:     str    — pointer element type: "int" (default, 4B), "u8", or
#                          "cstr" (u8 with a guaranteed NUL and a varying length)
#                          (1B; required for byte-accurate wire buffers).
#   len_args:     [int]  — scalar param indices that are a length/count into the
#                          buffer; clamped to [0, ptr_len].
#   extra_vectors:[[...]]— explicit arg tuples (scalar=int, pointer=list[int]).
#                          NOT clamped — used for exact case/boundary/packet inputs.
#   arg_values:   {i:[v]}— restrict scalar param `i` to exactly these values, in
#                          BOTH the boundary sweep and the seeded fuzz. For a
#                          parameter that guards an unbounded/very long path: the
#                          verdict must not depend on how fast the machine is.
#   skip_exec:    bool   — not safely executable; checked structurally instead.
#   skip_exec_lanes: (str,) — as skip_exec but only for `"<compiler>:<opt>"` lanes.
#                          Optimisation changes the SHAPE, so a function can be
#                          unexecutable at -O0 and correct at -O2; skipping it
#                          everywhere would discard the lanes that do work.
#   pointer_return_arg: int — compare a returned pointer by its element index
#                          within this caller-owned pointer-argument buffer.
#   non_length_args: [int] — human-reviewed scalar parameters beside a pointer
#                          that are values/keys, not bounds used for addressing.
# --- the DecBench validation corpus (tests/decbench_corpus/) --------------------
#
# The same mechanism, for a corpus that had none. Without these the harness invents
# a length: `sum_array` was handed a 16-element buffer and `n = 100`, so BOTH sides
# read out of bounds and disagreed about the garbage, and `reverse`/`matmul` wrote
# out of bounds and segfaulted. That is the harness misusing the function, not the
# decompiler getting it wrong — and reading it as a decompiler failure overstated how
# broken the output was: `sum_array` decompiled CORRECTLY.
#
# `len_args` clamps a scalar to [0, ptr_len]. `arg_values` pins a domain where the
# SOURCE is undefined outside it, which is not the same thing and is noted per case.
# `python/tests/test_decbench_corpus_contracts.py` fails closed if a corpus function
# that needs an entry here does not have one.
DECBENCH_OVERRIDES: dict[tuple[str, str], dict] = {
    # The generic sweep includes each integer type's extrema.  Keep it wherever
    # the source operation is defined, but do not ask a differential to compare
    # signed overflow or an invalid shift count: the optimiser is allowed to
    # produce different answers for those even when the decompilation is exact.
    ("arith", "addmul"): {
        "arg_values": {
            0: [-1000000, -1000, -1, 0, 1, 1000, 1000000],
            1: [-1000000, -1000, -1, 0, 1, 1000, 1000000],
            2: [-1000000, -1000, -1, 0, 1, 1000, 1000000],
        }
    },
    ("arith", "shifts"): {"arg_values": {1: [1, 2, 7, 15, 16, 31]}},
    ("arith", "signs"): {
        "arg_values": {
            0: [-1000000, -1000, -1, 0, 1, 1000, 1000000],
            1: [-1000000, -1000, -1, 0, 1, 1000, 1000000],
        }
    },
    ("branches", "classify"): {
        "arg_values": {
            0: [-1000000, -1, 0, 1, 1000000],
            1: [-1000000, -1, 0, 1, 1000000],
        }
    },
    ("branches", "nested"): {"arg_values": {2: [-1000000, -1, 0, 1, 1000000]}},
    ("arrays", "sum_array"): {"len_args": [1]},
    ("arrays", "max_array"): {"len_args": [1]},
    ("arrays", "reverse"): {"len_args": [1]},
    ("sort", "bubble"): {"len_args": [1]},
    ("sort", "bsearch_i"): {"len_args": [1]},
    ("checksum", "fletcher16"): {"len_args": [1]},
    # `matmul` indexes A[i*n+k] over THREE buffers, so n is bounded by sqrt(len):
    # n=4 fills a 16-element matrix exactly.
    ("matrix", "matmul"): {"arg_values": {3: [0, 1, 2, 3, 4]}},
    # `fp_div(a, b)` is `((long)a << 16) / b`, and BOTH parameters need bounding:
    #
    #   b: divide-by-zero is undefined in the source — the original binary raises
    #      SIGFPE on `fp_div(1, 0)`, so there is nothing to compare against.
    #      Verified by running it, not assumed.
    #   a: left-shifting a NEGATIVE value is undefined in C (C11 6.5.7p4). gcc and
    #      clang both implement it as two's complement, so the original binary and a
    #      recompile of our C usually agree — but "usually" is the problem: the
    #      recompiled C puts that shift in a different context, where the optimiser
    #      is entitled to exploit the UB differently. A differential that can fail
    #      for reasons unrelated to the decompilation is not a gate.
    #
    # Negative-input coverage is not lost: `fp_mul` is `((long)a * b) >> 16`, whose
    # RIGHT shift of a negative value is implementation-defined rather than
    # undefined, so it exercises the sign-extension path — which is where the
    # extension-width bug actually lived — without the UB.
    ("fixedpoint", "fp_div"): {
        "arg_values": {
            0: [0, 1, 2, 3, 7, 100, 65535, 65536, 1000000, 2147483647],
            1: [1, 2, 3, 7, 100, -1, -2, 65536, 2147483647],
        },
    },
    # `isqrt` overflows `(x+1)/2` for large n — signed overflow, undefined in the
    # source. Every DEFINED input already agreed; the original happens to return 0 at
    # INT64_MAX under gcc -O0, which is not a contract.
    ("fixedpoint", "isqrt"): {
        "arg_values": {0: [0, 1, 2, 3, 100, 1000000, 2147483647, -1]},
    },
    # Exponential and doubly-recursive: bound both so the verdict tests the recursion
    # rather than the machine's speed, exactly as the fixture `fib` needed.
    ("recursion", "fib"): {"arg_values": {0: [-1, 0, 1, 2, 3, 7, 12, 20]}},
    ("recursion", "ackermann"): {
        "arg_values": {0: [0, 1, 2], 1: [0, 1, 2, 3]},
    },
    # A `char *` buffer must be NUL-terminated or every string function runs off the
    # end. "cstr" guarantees the terminator and varies where it lands.
    ("strops", "str_len"): {"ptr_elem": "cstr"},
    ("strops", "str_cmp"): {"ptr_elem": "cstr"},
    ("strops", "hash_djb2"): {"ptr_elem": "cstr"},
    ("statemachine", "fsm"): {"len_args": [1], "ptr_elem": "u8"},
    # These loops are finite for every integer but the generic INT_MAX boundary
    # would make the gate spend billions of iterations.  factorial additionally
    # has signed overflow above 20 on this 64-bit source type.
    ("loops", "sum_to"): {"arg_values": {0: [-2, -1, 0, 1, 2, 3, 7, 10, 100, 1000]}},
    ("loops", "factorial"): {"arg_values": {0: [-2, -1, 0, 1, 2, 3, 7, 10, 15, 20]}},
    # A random signed 32-bit opcode reaches the default arm almost every time.
    # Pin every jump-table arm, including the negative case-7 operand that caught
    # `sar eax,1` being rendered as a 64-bit logical shift. Values stay small so
    # add/mul/left-shift do not invoke signed-overflow or negative-shift UB.
    ("switch_jt", "dispatch"): {
        "extra_vectors": [
            [-1, -9, -3],
            [8, -9, -3],
            [0, -9, -3],
            [0, -3, 9],
            [1, -9, -3],
            [1, 9, -3],
            [2, -9, -3],
            [2, -3, 9],
            [3, -9, -3],
            [4, -9, -3],
            [5, -9, -3],
            [6, 9, -3],
            [6, 0, -1],
            [7, -9, -3],
            [7, 0, -1],
        ]
    },
    # Recursive node links are materialized as bounded acyclic chains. list_find's
    # pointer result is meaningful only relative to its input graph, so compare the
    # returned node index rather than unrelated process addresses.
    ("linkedlist", "list_sum"): {"extra_vectors": [[[[1, 10], [2, -20], [-1, 30]]]]},
    ("linkedlist", "list_find"): {
        "pointer_return_arg": 0,
        "non_length_args": [1],
        "extra_vectors": [
            [[[1, 10], [2, 20], [-1, 30]], 10],
            [[[1, 10], [2, 20], [-1, 30]], 20],
            [[[1, 10], [2, 20], [-1, 30]], 99],
        ],
    },
}

# Exported semantic units in the compact 14-program DecBench validation corpus.
# This is intentionally separate from REQUIRED_FUNCTIONS below: that mapping is
# an exact manifest of files in FIXTURE_SRC, while these sources live under
# tests/decbench_corpus/src.  The matrix behavior gate uses this catalog to fail
# closed when a function is absent or renamed instead of silently scoring only
# whichever functions the backend happened to recover.
DECBENCH_PROJECTS: dict[str, list[str]] = {
    "arith": ["addmul", "shifts", "signs"],
    "arrays": ["sum_array", "max_array", "reverse"],
    "branches": ["classify", "nested"],
    "checksum": ["crc32_step", "fletcher16"],
    "fixedpoint": ["fp_mul", "fp_div", "isqrt"],
    "linkedlist": ["list_sum", "list_find"],
    "loops": ["sum_to", "factorial", "count_bits"],
    "matrix": ["matmul"],
    "recursion": ["fib", "ackermann"],
    "sort": ["bubble", "bsearch_i"],
    "statemachine": ["fsm"],
    "strops": ["str_len", "str_cmp", "hash_djb2"],
    "structs": ["dist2", "rect_area"],
    "switch_jt": ["dispatch"],
}

OVERRIDES: dict[tuple[str, str], dict] = {
    # x86 DIV/IDIV trap on zero; IDIV also traps on INT64_MIN / -1 because the
    # quotient is not representable. Pin nonzero divisors while retaining signs,
    # large magnitudes, and high-word coverage in the dividend.
    ("02_integer_widths", "urem64"): {
        "arg_values": {1: [1, 2, 3, 7, 10, 100, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF]},
    },
    ("02_integer_widths", "srem64"): {
        "arg_values": {1: [1, 2, 3, 7, 10, 100, 2147483647, -(2**63)]},
    },
    # 14_flag_effects: all scalar, but three take a loop-trip-count parameter that
    # must be bounded or the verdict measures machine speed instead of the flag
    # modelling. `dec_preserves_carry` is unbounded on purpose — it has no loop.
    ("14_flag_effects", "dec_loop"): {"arg_values": {0: [-1, 0, 1, 2, 3, 7, 8, 100]}},
    # `while (n--)` on a NEGATIVE n decrements past INT_MIN — signed overflow, which
    # is undefined in the source, so there is nothing to compare against. Same class
    # as fp_div's left shift of a negative value: a differential that can fail for
    # reasons unrelated to the decompilation is not a gate.
    ("14_flag_effects", "countdown"): {"arg_values": {0: [0, 1, 2, 3, 7, 8, 100]}},
    # `a + b` must not overflow: signed overflow is undefined, and the boundary
    # sweep would otherwise pair INT_MIN with INT_MIN. Bounded to halves of the
    # range so every sum is representable while still crossing zero in both
    # directions, which is the whole point of the function.
    ("14_flag_effects", "add_then_negative"): {
        "arg_values": {
            0: [-1073741824, -1000, -1, 0, 1, 1000, 1073741823],
            1: [-1073741824, -1000, -1, 0, 1, 1000, 1073741823],
        },
    },
    ("14_flag_effects", "shift_until_zero"): {
        "arg_values": {0: [0, 1, 2, 3, 255, 65536, 2147483647, 4294967295]},
    },
    # 13_loop_early_exit: every function takes a buffer and its length. Same
    # reasoning as DECBENCH_OVERRIDES above — an unclamped length makes both
    # binaries read out of bounds and the differential compares garbage.
    ("13_loop_early_exit", "find_first"): {"len_args": [1]},
    ("13_loop_early_exit", "bisect"): {"len_args": [1]},
    ("13_loop_early_exit", "classify_run"): {"len_args": [1]},
    ("13_loop_early_exit", "has_pair"): {
        "len_args": [1],
        # GCC -O2's nested-loop CFG has a match exit and an exhaustion exit.
        # This deterministic no-match vector caught a lossy one-exit `While`
        # recovery that the smaller seeded sample happened not to exercise.
        "extra_vectors": [
            [
                [-61, -46, 38, 10, 61, 34, 29, -7, 30, 57, -45, -20, -33, 18, 43, -27],
                16,
                100,
            ],
        ],
    },
    ("13_loop_early_exit", "sum_until_zero"): {"len_args": [1]},
    ("13_loop_early_exit", "sum_positive"): {"len_args": [1]},
    # `fib` is exponential. Once argument reconstruction started working the
    # decompiled version actually recursed — correctly — and then ran for
    # `fib(INT_MAX)` exactly as the original would. Before the fix it returned
    # instantly BECAUSE it was wrong, so the boundary sweep looked cheap. Pin the
    # input to values that terminate: the verdict must test the recursion, not
    # the machine's speed. Negatives still exercise the `n < 0` guard.
    ("06_calling_conventions", "fib"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 7, 12, 20]},
    },
    # Linear recursion: the generic signed-int boundary sweep includes INT_MAX,
    # which makes the ORIGINAL require roughly 2.1 billion frames and crash before
    # the differential can call our version. Retain negative/base cases, every GCC
    # unrolled prefix, and values large enough to exercise repeated modulo lowering.
    ("06_calling_conventions", "fact_mod"): {
        "arg_values": {0: [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 10, 20, 50, 100, 500, 1000]},
    },
    # 12: drive each trip count across its masked range, including the zero-trip
    # case a wrongly-polarised loop condition turns into a full run (and back).
    ("12_loop_rotation", "factorial_while"): {
        "extra_vectors": [[0], [1], [2], [15], [16], [-1]]
    },
    ("12_loop_rotation", "count_up"): {"extra_vectors": [[0], [1], [15], [16], [-1]]},
    ("12_loop_rotation", "for_accumulate"): {"extra_vectors": [[0], [1], [15], [-1]]},
    ("12_loop_rotation", "do_while_control"): {"extra_vectors": [[0], [1], [15], [-1]]},
    ("12_loop_rotation", "find_first_set"): {
        "extra_vectors": [[0], [1], [0x80000000], [0xFFFFFFFF]]
    },
    ("12_loop_rotation", "skip_odd_sum"): {"extra_vectors": [[0], [1], [2], [15]]},
    ("12_loop_rotation", "nested_rotated"): {
        "extra_vectors": [[0, 0], [1, 1], [7, 7], [0, 7], [7, 0]]
    },
    ("12_loop_rotation", "down_by_negative_imm"): {
        "extra_vectors": [[0], [1], [15], [-1]]
    },
    # 11: drive the boundaries where a wrong width is visible — the 8-bit wrap,
    # the 32-bit product that needs 64 bits, and the sign flip in the callee.
    ("11_call_shapes", "wrap_byte"): {
        "extra_vectors": [[0], [8], [0xFF], [0x100], [0xFFFFFFFF]],
    },
    ("11_call_shapes", "widen_mul"): {
        "extra_vectors": [
            [0xFFFFFFFF, 0xFFFFFFFF],
            [0x10000, 0x10000],
            [1, 0xFFFFFFFF],
        ],
    },
    ("11_call_shapes", "call_fold_wide_result"): {
        "extra_vectors": [[0xFFFFFFFF, 0xFFFFFFFF], [0x10000, 0x10000], [0, 5]],
    },
    ("11_call_shapes", "call_result_drives_branch"): {
        "extra_vectors": [[999], [1000], [1001], [INT_MIN], [INT_MAX]],
    },
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
        "ptr_elem": "u8",
        "ptr_len": 32,
        "len_args": [1],
        "extra_vectors": [
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00], 12),  # ok -> 0
            ([0x00, 0x00, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00], 12),  # bad magic -> -3
            ([0xC0, 0xDE, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00], 8),  # bad version -> -4
            ([0xC0, 0xDE, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00], 8),  # type 0 -> -5
            ([0xC0, 0xDE, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00], 8),  # type 8 -> -5
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0xFF, 0x00, 0x00], 8),  # len overrun -> -6
            ([0xC0, 0xDE], 4),  # too short -> -2
        ],
    },
    ("07_packet_parser", "decode_header"): {
        "ptr_elem": "u8",
        "ptr_len": 32,
        "len_args": [1],
    },
    ("07_packet_parser", "parse_packet"): {
        "ptr_elem": "u8",
        "ptr_len": 32,
        "len_args": [1],
        "extra_vectors": [
            (
                [
                    0xC0,
                    0xDE,
                    0x13,
                    0x00,
                    0x00,
                    0x04,
                    0x00,
                    0x00,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                ],
                12,
            ),  # ok
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00], 8),  # ok, empty payload
            ([0x00, 0x00, 0x13, 0x00, 0x00, 0x04, 0x00, 0x00], 12),  # bad magic -> -3
            ([0xC0, 0xDE, 0x13, 0x00, 0x00, 0xFF, 0x00, 0x00], 10),  # len overrun -> -6
            ([0xC0, 0xDE], 4),  # too short -> -2
        ],
    },
    # 09: buffer transforms — the count arg indexes the buffer.
    ("09_memory_effects", "mem_copy"): {"len_args": [2]},
    ("09_memory_effects", "mem_set"): {"len_args": [2]},
    ("09_memory_effects", "vec_sum"): {"len_args": [1]},
    ("09_memory_effects", "vec_transform"): {"len_args": [1]},
    # 08: apply() takes a function pointer — not int-differential; check structurally.
    ("08_indirect_dispatch", "apply"): {"skip_exec": True},
    # The virtual wrapper remains structural by design.  Unlike the five C++
    # wrappers below, its recovered body materializes each vtable-backed automatic
    # object as an uninitialized pointer and dereferences it on the first vector.
    # That is the aggregate/vtable-object recovery gap (EPIC 3), not an
    # architecture-specific call, stack, or EH defect.  Executing the emitted C
    # therefore deterministically crashes before it can judge dispatch.  Keep the
    # structural indirect-call assertion until the object model can emit the two
    # concrete objects and their vptr initializers.
    ("10_cpp_runtime_shapes", "cpp_virtual_dispatch"): {"skip_exec": True},
    # 06: guarded_spin's `spin` guard MUST stay 0, which is the contract its source
    # comment already states ("the harness always passes 0"). It was never enforced,
    # so the boundary sweep and fuzz drove `spin` nonzero and every such vector ran
    # `volatile x += 1` until the 32-bit wraparound — seconds per vector, twice
    # (original + recompiled). The verdict then depended on machine speed: it passed
    # on a 24-core workstation and hit the worker's wall-clock timeout on a 4-vCPU
    # CI runner, i.e. a flaky gate. The loop still has to be STRUCTURED correctly;
    # that is what the structural lane checks.
    ("06_calling_conventions", "guarded_spin"): {"arg_values": {0: [0]}},
    # 15-30: undergraduate algorithms curriculum.  Every bound below is part of
    # the executable contract, not a convenience: all pointer buffers contain 16
    # elements, graph matrices are at most 4x4, and algorithms with user-supplied
    # indices validate both canonical and adversarial inputs without reading out
    # of bounds.  `extra_vectors` provide at least one recognizable textbook
    # example alongside the deterministic boundary sweep and seeded fuzz.
    ("15_binary_search_tree", "bst_search"): {
        "arg_values": {1: [0, 1, 4, 7, 16], 2: [-1, 0, 1, 6, 15, 16]},
        "extra_vectors": [
            [
                [
                    [8, 1, 2],
                    [4, 3, 4],
                    [12, 5, 6],
                    [2, -1, -1],
                    [6, -1, -1],
                    [10, -1, -1],
                    [14, -1, -1],
                ],
                7,
                0,
                10,
            ]
        ],
    },
    ("15_binary_search_tree", "bst_inorder_checksum"): {
        "arg_values": {1: [0, 1, 4, 7, 16], 2: [-1, 0, 1, 6, 15, 16]},
        "extra_vectors": [
            [
                [
                    [8, 1, 2],
                    [4, 3, 4],
                    [12, 5, 6],
                    [2, -1, -1],
                    [6, -1, -1],
                    [10, -1, -1],
                    [14, -1, -1],
                ],
                7,
                0,
            ]
        ],
    },
    ("16_red_black_tree", "rb_validate"): {
        "arg_values": {1: [0, 1, 3, 7, 16], 2: [-1, 0, 1, 6, 15, 16]},
        "extra_vectors": [
            [
                [
                    [8, 1, 2, 0],
                    [4, 3, 4, 1],
                    [12, 5, 6, 1],
                    [2, -1, -1, 0],
                    [6, -1, -1, 0],
                    [10, -1, -1, 0],
                    [14, -1, -1, 0],
                ],
                7,
                0,
            ]
        ],
    },
    ("17_hash_table", "hash_lookup"): {
        "len_args": [2],
        "extra_vectors": [
            [
                [INT_MIN, 9, 17, 1, INT_MIN, INT_MIN, INT_MIN, INT_MIN],
                [0, 90, 170, 10, 0, 0, 0, 0],
                8,
                17,
            ]
        ],
    },
    ("17_hash_table", "hash_insert"): {
        "len_args": [2],
        "extra_vectors": [
            [
                [INT_MIN, 9, 17, 1, INT_MIN, INT_MIN, INT_MIN, INT_MIN],
                [0, 90, 170, 10, 0, 0, 0, 0],
                8,
                25,
                250,
            ]
        ],
    },
    ("18_binary_heap", "heap_push"): {
        "len_args": [1, 2],
        "extra_vectors": [[[2, 5, 7, 12, 9, 11], 6, 16, 3]],
    },
    ("18_binary_heap", "heap_pop"): {
        "len_args": [1],
        "extra_vectors": [[[2, 5, 7, 12, 9, 11], 6, [0]]],
    },
    ("19_disjoint_set", "dsu_find"): {
        "len_args": [1],
        "extra_vectors": [[[0, 0, 1, 3, 3, 4], 6, 5]],
    },
    ("19_disjoint_set", "dsu_union"): {
        "len_args": [2],
        "extra_vectors": [[[0, 0, 2, 2, 4, 4], [1, 0, 1, 0, 1, 0], 6, 1, 5]],
    },
    ("20_graph_bfs", "graph_bfs"): {
        "arg_values": {1: [0, 1, 2, 3, 4], 2: [-1, 0, 1, 3, 4]},
        "extra_vectors": [
            [
                [0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0],
                4,
                0,
                [0],
            ]
        ],
    },
    ("21_graph_dfs", "graph_dfs"): {
        "arg_values": {1: [0, 1, 2, 3, 4], 2: [-1, 0, 1, 3, 4]},
        "extra_vectors": [
            [
                [0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0],
                4,
                0,
                [0],
            ]
        ],
    },
    ("22_dijkstra", "dijkstra_dense"): {
        "arg_values": {1: [0, 1, 2, 3, 4], 2: [-1, 0, 1, 3, 4]},
        "extra_vectors": [
            [
                [0, 4, 1, 0, 4, 0, 2, 5, 1, 2, 0, 8, 0, 5, 8, 0],
                4,
                0,
                [0],
            ]
        ],
    },
    ("23_topological_sort", "topological_sort"): {
        "arg_values": {1: [0, 1, 2, 3, 4]},
        "extra_vectors": [
            [
                [0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
                4,
                [0],
            ]
        ],
    },
    ("24_merge_sort", "merge_sort_i32"): {
        "len_args": [1],
        "extra_vectors": [[[9, -3, 7, 7, 0, 12, -8, 1], 8]],
    },
    ("25_kmp_search", "kmp_search"): {
        "ptr_elem": "u8",
        "len_args": [1, 3],
        "extra_vectors": [[[1, 2, 1, 2, 1, 3], 6, [1, 2, 1, 3], 4]],
    },
    ("26_sparse_matrix", "csr_matvec"): {
        "arg_values": {
            5: [0, 1, 2, 4],
            6: [0, 1, 2, 4, 16],
            7: [0, 1, 4, 7, 16],
        },
        "extra_vectors": [
            [
                [0, 2, 3, 5, 7],
                [0, 3, 1, 0, 2, 1, 3],
                [10, 2, 3, 4, 5, 6, 7],
                [1, 2, 3, 4],
                [0],
                4,
                4,
                7,
            ]
        ],
    },
    ("28_euler_ode", "euler_decay_q16"): {
        "arg_values": {
            0: [-65536, -32768, 0, 32768, 65536, 131072],
            1: [-65536, -16384, 0, 16384, 32768, 65536],
            2: [-1, 0, 1, 2, 8, 16, 32, 33],
        },
    },
    ("29_polynomial", "polynomial_eval_mod32"): {
        "len_args": [1],
        "extra_vectors": [[[1, 2, 3, 4], 4, 5]],
    },
    ("29_polynomial", "polynomial_derivative_mod32"): {
        "len_args": [1],
        "extra_vectors": [[[1, 2, 3, 4], 4, 5]],
    },
    ("30_finite_difference", "heat_step_1d"): {
        "len_args": [2],
        "extra_vectors": [[[0], [0, 0, 100, 0, 0], 5]],
    },
    # --- domain expansion contracts (fixtures 31-80) ---
    ("31_edit_distance", "edit_distance"): {
        "arg_values": {1: [0, 1, 2, 5, 8], 3: [0, 1, 3, 8]},
    },
    ("31_edit_distance", "hamming_distance"): {
        "arg_values": {2: [0, 1, 4, 8]},
    },
    ("32_longest_common_subsequence", "lcs_length"): {
        "arg_values": {1: [0, 1, 4, 8], 3: [0, 2, 8]},
    },
    ("32_longest_common_subsequence", "lcs_recover"): {
        "arg_values": {1: [0, 1, 4, 8], 3: [0, 2, 8]},
    },
    ("33_knapsack", "knapsack_best_value"): {
        "arg_values": {2: [0, 1, 4, 8], 3: [0, 1, 8, 16]},
    },
    ("33_knapsack", "unbounded_knapsack"): {
        "arg_values": {2: [0, 1, 4, 8], 3: [0, 1, 8, 16]},
    },
    ("34_coin_change", "min_coins"): {
        "arg_values": {1: [0, 1, 3, 8], 2: [0, 1, 6, 11, 32]},
        "extra_vectors": [[[1, 3, 4], 3, 6], [[2, 5], 2, 3]],
    },
    ("34_coin_change", "count_change"): {
        "arg_values": {1: [0, 1, 3, 8], 2: [0, 1, 5, 32]},
        "extra_vectors": [[[1, 2, 5], 3, 5]],
    },
    ("35_matrix_chain", "matrix_chain_cost"): {
        "arg_values": {1: [1, 2, 3, 7]},
        "extra_vectors": [[[10, 30, 5, 60], 3], [[5, 4, 6, 2, 7], 4]],
    },
    ("36_quicksort", "quicksort_i32"): {
        "len_args": [1],
    },
    ("37_heapsort", "heapsort_i32"): {
        "len_args": [1],
    },
    ("38_insertion_shell_sort", "insertion_sort_i32"): {
        "len_args": [1],
    },
    ("38_insertion_shell_sort", "shell_sort_i32"): {
        "len_args": [1],
    },
    ("39_counting_radix_sort", "counting_sort_u8"): {
        "len_args": [1],
    },
    ("39_counting_radix_sort", "radix_sort_u32"): {
        "len_args": [1],
    },
    ("40_quickselect", "quickselect_kth"): {
        "len_args": [1, 2],
    },
    ("41_tokenizer", "tokenize"): {
        "len_args": [1],
        "extra_vectors": [[[97, 98, 32, 49, 50, 0, 0, 0], 5, [0], [0]]],
    },
    ("42_rpn_evaluator", "rpn_evaluate"): {
        "len_args": [2],
        "extra_vectors": [[[35, 35, 43], [2, 3, 0], 3, [0]]],
    },
    ("43_base64", "base64_encode"): {
        "arg_values": {1: [0, 1, 2, 3, 6, 9, 12]},
        "extra_vectors": [[[77, 97, 110], 3, [0]]],
    },
    ("43_base64", "base64_decode"): {
        "arg_values": {1: [0, 4, 8, 12, 16]},
        "extra_vectors": [[[84, 87, 70, 117], 4, [0]]],
    },
    ("44_run_length", "rle_encode"): {
        "len_args": [1, 3],
    },
    ("44_run_length", "rle_decode"): {
        "len_args": [1, 3],
    },
    ("45_string_algorithms", "parse_decimal"): {
        "len_args": [1],
        "extra_vectors": [[[45, 49, 50, 51], 4, [0]], [[57, 57, 57], 3, [0]]],
    },
    ("45_string_algorithms", "format_decimal"): {
        "len_args": [2],
        "extra_vectors": [[-4096, [0], 8], [0, [0], 4]],
    },
    ("45_string_algorithms", "is_palindrome"): {
        "len_args": [1],
    },
    ("46_bitset", "bitset_population"): {
        "arg_values": {1: [0, 1, 4, 8]},
    },
    ("46_bitset", "bitset_rank"): {
        "arg_values": {1: [0, 1, 4, 8], 2: [0, 1, 31, 32, 64, 128, 256]},
    },
    ("46_bitset", "bitset_select"): {
        "arg_values": {1: [0, 1, 4, 8], 2: [0, 1, 5, 31, 255]},
    },
    ("47_huffman", "huffman_code_lengths"): {
        "arg_values": {1: [1, 2, 4, 8]},
        "extra_vectors": [[[5, 9, 12, 13, 16, 45], 6, [0]]],
    },
    ("47_huffman", "kraft_sum_q16"): {
        "arg_values": {1: [0, 1, 4, 8]},
    },
    ("48_gray_code", "gray_sequence"): {
        "len_args": [1],
    },
    ("49_crc32", "crc32_bitwise"): {
        "len_args": [1],
        "extra_vectors": [[[49, 50, 51, 52, 53, 54, 55, 56, 57], 9]],
    },
    ("49_crc32", "crc32_table_driven"): {
        "len_args": [1],
        "extra_vectors": [[[49, 50, 51, 52, 53, 54, 55, 56, 57], 9]],
    },
    ("49_crc32", "internet_checksum"): {
        "len_args": [1],
    },
    ("50_varint", "varint_encode"): {
        "len_args": [2],
    },
    ("50_varint", "varint_decode"): {
        "len_args": [1],
        "extra_vectors": [[[172, 2], 2, [0]], [[1], 1, [0]]],
    },
    ("51_rc4", "rc4_keystream_checksum"): {
        "arg_values": {1: [1, 2, 8, 16], 2: [0, 1, 16, 64]},
        "extra_vectors": [[[75, 101, 121], 3, 16]],
    },
    ("52_hash_functions", "fnv1a_32"): {
        "len_args": [1],
    },
    ("52_hash_functions", "djb2_xor"): {
        "len_args": [1],
    },
    ("53_pseudorandom", "bounded_sample"): {
        "len_args": [3],
        "arg_values": {1: [1, 2, 10, 1024]},
    },
    ("54_sha256_block", "sha256_compress_block"): {
        "ptr_len": 16,
    },
    ("55_modular_arithmetic", "extended_gcd"): {
        "arg_values": {0: [0, 1, 12, 240, 100000], 1: [0, 1, 8, 46, 100000]},
    },
    ("56_sieve", "sieve_primes"): {
        "len_args": [1],
    },
    ("56_sieve", "factorize"): {
        "arg_values": {0: [2, 3, 12, 97, 360, 999983], 2: [1, 4, 8]},
    },
    ("57_bignum", "bignum_add"): {
        "arg_values": {1: [0, 1, 4, 8], 3: [0, 1, 4, 8], 5: [1, 4, 8]},
    },
    ("57_bignum", "bignum_mul_small"): {
        "arg_values": {1: [0, 1, 4, 8], 2: [0, 1, 7, 65535], 4: [1, 4, 8]},
    },
    ("58_rational", "rational_add"): {
        "arg_values": {0: [-7, 0, 1, 3, 10000], 1: [-4, 1, 2, 6, 10000], 2: [-3, 0, 1, 5, 10000], 3: [-2, 1, 3, 8, 10000]},
    },
    ("58_rational", "rational_compare"): {
        "arg_values": {0: [-7, 0, 1, 3, 10000], 1: [-4, 1, 2, 6, 10000], 2: [-3, 0, 1, 5, 10000], 3: [-2, 1, 3, 8, 10000]},
    },
    ("59_combinatorics", "pascal_row"): {
        "arg_values": {0: [0, 1, 2, 5, 12], 2: [13]},
    },
    ("60_integer_matrix", "matrix_multiply"): {
        "arg_values": {3: [0, 1, 2, 3, 4]},
    },
    ("60_integer_matrix", "matrix_transpose"): {
        "arg_values": {2: [0, 1, 2, 3, 4]},
    },
    ("60_integer_matrix", "determinant3"): {
        "ptr_len": 16,
    },
    ("62_gaussian_elimination", "gaussian_solve"): {
        "ptr_len": 20,
        "arg_values": {1: [1, 2, 3, 4]},
        "extra_vectors": [[[131072, 65536, 196608, 65536, 262144, 327680], 2, [0, 0]]],
    },
    ("63_numerical_integration", "trapezoid_integrate"): {
        "arg_values": {2: [1, 2, 4, 8, 32]},
    },
    ("63_numerical_integration", "simpson_integrate"): {
        "arg_values": {2: [2, 4, 8, 32]},
    },
    ("64_root_finding", "bisection_sqrt"): {
        "arg_values": {1: [1, 16, 256, 65536]},
    },
    ("64_root_finding", "newton_sqrt"): {
        "arg_values": {1: [1, 16, 256, 65536]},
    },
    ("65_projectile_motion", "projectile_step"): {
        "arg_values": {2: [1, 256, 6553, 65536], 3: [0, 1, 8, 32]},
    },
    ("66_orbital_step", "orbital_step"): {
        "arg_values": {4: [1, 65536, 655360], 5: [1, 256, 6553, 65536], 6: [0, 1, 4, 16]},
    },
    ("68_thermodynamics", "newton_cooling"): {
        "arg_values": {2: [0, 1024, 32768, 65536], 3: [0, 1, 8, 24]},
    },
    ("69_molar_mass", "molar_mass_centi"): {
        "len_args": [1],
        "extra_vectors": [[[72, 50, 79], 3], [[67, 54, 72, 49, 50, 79, 54], 7], [[78, 97, 67, 108], 4]],
    },
    ("70_reaction_balance", "balance_reaction"): {
        "arg_values": {4: [1, 2, 3, 4]},
        "extra_vectors": [[[0, 2], [2, 0], [2, 1], [0, 0], 2, [0, 0, 0, 0]]],
    },
    ("71_compound_interest", "compound_balance"): {
        "arg_values": {1: [0, 655, 6553, 65536], 2: [0, 1, 8, 32]},
    },
    ("71_compound_interest", "annuity_future_value"): {
        "arg_values": {1: [0, 655, 6553, 65536], 2: [0, 1, 8, 32]},
    },
    ("72_loan_amortization", "amortization_schedule"): {
        "arg_values": {1: [0, 655, 6553], 2: [1, 65536, 655360], 3: [0, 1, 6, 12]},
    },
    ("72_loan_amortization", "remaining_balance"): {
        "arg_values": {1: [0, 655, 6553], 2: [1, 65536, 655360], 3: [0, 1, 6, 12]},
    },
    ("73_present_value", "net_present_value"): {
        "arg_values": {1: [0, 1, 4, 12], 2: [0, 655, 6553, 65536]},
    },
    ("73_present_value", "internal_rate_of_return"): {
        "arg_values": {1: [1, 4, 12]},
    },
    ("74_moving_statistics", "simple_moving_average"): {
        "len_args": [1, 2],
    },
    ("74_moving_statistics", "exponential_moving_average"): {
        "arg_values": {1: [1, 4, 16], 2: [0, 6553, 32768, 65536]},
    },
    ("74_moving_statistics", "population_variance"): {
        "arg_values": {1: [1, 4, 16]},
    },
    ("75_order_book", "match_order"): {
        "arg_values": {2: [0, 1, 4, 8], 4: [0, 1, 100, 1000000], 5: [0, 1]},
        "extra_vectors": [[[100, 101, 102], [5, 5, 5], 3, 101, 7, 1, [0]]],
    },
    ("76_portfolio_rebalance", "maximum_drift"): {
        "arg_values": {2: [1, 2, 4, 8]},
    },
    ("76_portfolio_rebalance", "rebalance_trades"): {
        "arg_values": {2: [1, 2, 4, 8]},
    },
    ("77_lru_cache", "lru_access"): {
        "arg_values": {2: [1, 2, 4, 8], 4: [0, 1, 100]},
    },
    ("78_ring_buffer", "ring_push"): {
        "ptr_len": 16,
    },
    ("78_ring_buffer", "ring_pop"): {
        "ptr_len": 16,
    },
    ("79_segment_tree", "segment_build"): {
        "arg_values": {1: [0, 1, 4, 8]},
    },
    ("79_segment_tree", "segment_update"): {
        "arg_values": {1: [0, 1, 4, 7]},
    },
    ("79_segment_tree", "segment_range_sum"): {
        "arg_values": {1: [0, 1, 4], 2: [0, 2, 5, 8]},
    },
    ("80_trie", "trie_insert"): {
        "ptr_len": 96,
        "arg_values": {4: [0, 1, 3, 8]},
        "extra_vectors": [[[0], [0], [1], [97, 98], 2]],
    },
    ("80_trie", "trie_lookup"): {
        "ptr_len": 96,
        "arg_values": {3: [0, 1, 3, 8]},
    },
}

# Structural expectations for the structural lane (checked on decompiled text, not
# by execution): effects/constructs that MUST survive lowering. `indirect_call` —
# a call through a computed/loaded pointer (operations table / callback) must be
# emitted, not dropped or replaced by a fabricated direct target. `memory_store` —
# a write to memory must survive (not be dead-store-eliminated away).
STRUCTURAL: dict[tuple[str, str], dict] = {
    # A2 loop-form acceptance: after reload folding, the source head test must
    # become the loop condition rather than an explicit break inside while (1).
    ("12_loop_rotation", "factorial_while"): {"head_tested_while": True},
    ("08_indirect_dispatch", "dispatch"): {"indirect_call": True},
    ("08_indirect_dispatch", "apply"): {"indirect_call": True},
    ("08_indirect_dispatch", "tail_dispatch"): {"indirect_call": True},
    ("09_memory_effects", "mem_set"): {"memory_store": True, "void_signature": True},
    ("09_memory_effects", "mem_copy"): {"memory_store": True, "void_signature": True},
    ("09_memory_effects", "cas_update"): {"memory_store": True},
    ("09_memory_effects", "vec_transform"): {"memory_store": True},
    ("09_memory_effects", "tick"): {"memory_store": True, "void_signature": True},
    ("09_memory_effects", "tick_n"): {"memory_store": True, "void_signature": True},
    ("09_memory_effects", "reset_counter"): {
        "memory_store": True,
        "void_signature": True,
    },
    # C++ runtime shapes — initial vtable/EH assertions (ratchet upward).
    ("10_cpp_runtime_shapes", "cpp_virtual_dispatch"): {
        "indirect_call": True
    },  # vtable dispatch
    ("10_cpp_runtime_shapes", "cpp_ctor_dtor"): {
        "memory_store": True
    },  # ctor/dtor markers
    ("10_cpp_runtime_shapes", "cpp_raii_guard"): {
        "memory_store": True
    },  # cleanup write
    ("10_cpp_runtime_shapes", "cpp_exception"): {"nonempty": True},  # EH body recovered
}


def structural_spec(fixture: str, func: str) -> dict:
    return STRUCTURAL.get((fixture, func), {})


# A deliberately recognizable undergraduate curriculum.  Keeping this catalog
# separate makes corpus growth reviewable: every project must name its exported
# semantic units, exist on disk, and receive a safe execution contract where it
# indexes caller-owned memory.
CURRICULUM_PROJECTS: dict[str, list[str]] = {
    "15_binary_search_tree": ["bst_search", "bst_inorder_checksum"],
    "16_red_black_tree": ["rb_validate"],
    "17_hash_table": ["hash_lookup", "hash_insert"],
    "18_binary_heap": ["heap_push", "heap_pop"],
    "19_disjoint_set": ["dsu_find", "dsu_union"],
    "20_graph_bfs": ["graph_bfs"],
    "21_graph_dfs": ["graph_dfs"],
    "22_dijkstra": ["dijkstra_dense"],
    "23_topological_sort": ["topological_sort"],
    "24_merge_sort": ["merge_sort_i32"],
    "25_kmp_search": ["kmp_search"],
    "26_sparse_matrix": ["csr_matvec"],
    "27_newton_raphson": ["newton_isqrt"],
    "28_euler_ode": ["euler_decay_q16"],
    "29_polynomial": ["polynomial_eval_mod32", "polynomial_derivative_mod32"],
    "30_finite_difference": ["heat_step_1d"],
    # --- domain expansion: algorithms, numerics, and applied-science kernels ---
    "31_edit_distance": ["edit_distance", "hamming_distance"],
    "32_longest_common_subsequence": ["lcs_length", "lcs_recover"],
    "33_knapsack": ["knapsack_best_value", "unbounded_knapsack"],
    "34_coin_change": ["min_coins", "count_change"],
    "35_matrix_chain": ["matrix_chain_cost"],
    "36_quicksort": ["quicksort_i32"],
    "37_heapsort": ["heapsort_i32"],
    "38_insertion_shell_sort": ["insertion_sort_i32", "shell_sort_i32"],
    "39_counting_radix_sort": ["counting_sort_u8", "radix_sort_u32"],
    "40_quickselect": ["quickselect_kth", "median_of_three"],
    "41_tokenizer": ["tokenize"],
    "42_rpn_evaluator": ["rpn_evaluate"],
    "43_base64": ["base64_encode", "base64_decode"],
    "44_run_length": ["rle_encode", "rle_decode"],
    "45_string_algorithms": ["parse_decimal", "format_decimal", "is_palindrome"],
    "46_bitset": ["bitset_population", "bitset_rank", "bitset_select"],
    "47_huffman": ["huffman_code_lengths", "kraft_sum_q16"],
    "48_gray_code": ["binary_to_gray", "gray_to_binary", "reverse_bits32", "gray_sequence"],
    "49_crc32": ["crc32_bitwise", "crc32_table_driven", "internet_checksum"],
    "50_varint": ["zigzag_encode", "zigzag_decode", "varint_encode", "varint_decode"],
    "51_rc4": ["rc4_keystream_checksum"],
    "52_hash_functions": ["fnv1a_32", "djb2_xor", "murmur3_finalize"],
    "53_pseudorandom": ["xorshift32", "lcg64_next_high", "bounded_sample"],
    "54_sha256_block": ["sha256_compress_block"],
    "55_modular_arithmetic": ["gcd_i32", "extended_gcd", "mod_pow"],
    "56_sieve": ["sieve_primes", "factorize"],
    "57_bignum": ["bignum_add", "bignum_mul_small"],
    "58_rational": ["rational_add", "rational_compare"],
    "59_combinatorics": ["pascal_row", "binomial", "catalan"],
    "60_integer_matrix": ["matrix_multiply", "matrix_transpose", "determinant3"],
    "61_fixed_point": ["fixed_multiply", "fixed_divide", "fixed_sqrt", "fixed_lerp"],
    "62_gaussian_elimination": ["gaussian_solve"],
    "63_numerical_integration": ["trapezoid_integrate", "simpson_integrate"],
    "64_root_finding": ["bisection_sqrt", "newton_sqrt"],
    "65_projectile_motion": ["projectile_step", "kinetic_energy"],
    "66_orbital_step": ["orbital_step"],
    "67_elastic_collision": ["elastic_velocity_a", "inelastic_velocity", "momentum_residual"],
    "68_thermodynamics": ["ideal_gas_pressure", "newton_cooling", "mixing_temperature"],
    "69_molar_mass": ["molar_mass_centi"],
    "70_reaction_balance": ["balance_reaction"],
    "71_compound_interest": ["compound_balance", "annuity_future_value"],
    "72_loan_amortization": ["amortization_schedule", "remaining_balance"],
    "73_present_value": ["net_present_value", "internal_rate_of_return"],
    "74_moving_statistics": ["simple_moving_average", "exponential_moving_average", "population_variance"],
    "75_order_book": ["match_order"],
    "76_portfolio_rebalance": ["maximum_drift", "rebalance_trades"],
    "77_lru_cache": ["lru_access"],
    "78_ring_buffer": ["ring_push", "ring_pop", "ring_occupancy"],
    "79_segment_tree": ["segment_build", "segment_update", "segment_range_sum"],
    "80_trie": ["trie_insert", "trie_lookup"],
}

# Functions that MUST be present in each fixture (real names; a missing one fails
# the gate). Not exhaustive — enough to catch a dropped/renamed symbol.
REQUIRED_FUNCTIONS: dict[str, list[str]] = {
    "01_conditional_polarity": [
        "cmp_signed",
        "cmp_unsigned",
        "early_return",
        "early_return_ge",
        "nested",
        "elseif",
        "ternary",
        "sc_and",
        "sc_or",
        "classify",
    ],
    "02_integer_widths": [
        "rt_u8",
        "rt_u16",
        "rt_u32",
        "rt_u64",
        "sext_i8",
        "zext_u32_to_u64",
        "trunc_u8",
        "sar_signed",
        "shr_unsigned",
        "umul_high64",
        "smul_high64",
        "urem64",
        "srem64",
    ],
    "03_loop_shapes": [
        "for_sum",
        "dowhile_atleastonce",
        "while_reload_header",
        "loop_break",
        "loop_continue",
        "nested_pairs",
    ],
    "04_switch_shapes": [
        "dense_jumptable",
        "sparse_switch",
        "negative_cases",
        "shared_bodies",
        "explicit_fallthrough",
        "no_default",
    ],
    "05_cleanup_and_state_machine": ["fsm", "process"],
    "06_calling_conventions": [
        "sum_arg0",
        "sum_arg1",
        "sum_arg2",
        "sum_arg6",
        "sum_arg7",
        "sum_arg10",
        "fib",
        "fact_mod",
    ],
    # Only exported (non-static) functions — read_be16/read_be32/decode_header are
    # `static` (inlined away at O2, never dynamically loadable) so they are not
    # required and not execution-tested.
    "07_packet_parser": ["validate_header", "parse_packet"],
    "08_indirect_dispatch": ["dispatch", "dispatch_switch", "tail_dispatch", "apply"],
    "09_memory_effects": [
        "tick",
        "tick_n",
        "read_counter",
        "reset_counter",
        "cas_update",
        "mem_copy",
        "mem_set",
        "vec_sum",
        "vec_transform",
    ],
    "10_cpp_runtime_shapes": [
        "cpp_virtual_dispatch",
        "cpp_ctor_dtor",
        "cpp_raii_guard",
        "cpp_exception",
        "cpp_lambda_capture",
        "cpp_move",
    ],
    # Every function is a loop SHAPE; a decompiler that drops the back-edge returns
    # the first iteration's value, which every one of these makes visible.
    "12_loop_rotation": [
        "factorial_while",
        "count_up",
        "for_accumulate",
        "do_while_control",
        "find_first_set",
        "skip_odd_sum",
        "nested_rotated",
        "down_by_negative_imm",
    ],
    "13_loop_early_exit": [
        "find_first",
        "bisect",
        "classify_run",
        "has_pair",
        "sum_until_zero",
        "sum_positive",
    ],
    "14_flag_effects": [
        "dec_loop",
        "countdown",
        "sub_then_sign",
        "and_is_zero",
        "add_then_negative",
        "shift_until_zero",
        "dec_preserves_carry",
    ],
    # Callees are required too: a callee whose own recovery is wrong makes every
    # caller's verdict meaningless.
    "11_call_shapes": [
        "widen_mul",
        "wrap_byte",
        "signed_step",
        "spill_combine",
        "call_fold_wide_result",
        "call_accumulate_bytes",
        "call_result_drives_branch",
        "call_nested",
        "call_twice_and_combine",
        "call_into_spill",
        "call_chain_in_loop",
        "call_forward_result",
        "call_result_unused",
    ],
    **CURRICULUM_PROJECTS,
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
    """The contract for one function, from whichever corpus it belongs to.

    The DecBench validation corpus is kept in its own table rather than merged: the
    two corpora are separate populations, and a name collision between them would
    otherwise silently apply one's contract to the other's function."""
    if (fixture, func) in DECBENCH_OVERRIDES:
        return DECBENCH_OVERRIDES[(fixture, func)]
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
        vals += [
            0x1_0000_0007,
            0x7FFF_FFFF_8000_0001 if signed else 0xFFFF_FFFF_0000_0001,
        ]
    # de-dupe preserving order
    seen, out = set(), []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


#: Directory holding the fixture sources, resolved relative to this file so that
#: every caller agrees on it regardless of where it was imported from.
FIXTURE_SRC = _pathlib.Path(__file__).resolve().parent / "src"


def assert_fixtures_declared() -> None:
    """Every fixture on disk is declared, and every declared fixture exists.

    A SHARED precondition, because it used to live inside one refresher and not the
    other. `fixture_harness.py --write-baseline` checked it (inside a function about
    compilation) and correctly refused when 13_loop_early_exit.c was added without a
    REQUIRED_FUNCTIONS entry — while `gen_structural_baseline.py`, run in the same
    breath, wrote structural_baseline.json anyway. The two baselines would then
    disagree about which fixtures exist, with the undeclared one's structural state
    silently blessed and its execution state absent.

    Both refreshers call this now. A guard that only one writer honours is not a
    guard; it is a way of finding out later.
    """
    on_disk = {
        p.stem
        for p in sorted(FIXTURE_SRC.glob("*.c")) + sorted(FIXTURE_SRC.glob("*.cpp"))
    }
    declared = set(REQUIRED_FUNCTIONS)
    if on_disk != declared:
        raise AssertionError(
            "fixture sources and the manifest disagree: "
            f"only on disk {sorted(on_disk - declared)}, "
            f"only declared {sorted(declared - on_disk)}"
        )
