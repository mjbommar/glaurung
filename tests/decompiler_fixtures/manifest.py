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
#                          NOTE the vocabulary: `fixture_harness` names a lane by
#                          COMPILER (`gcc:O2`), while `tools/arch_roundtrip.py`
#                          names it by ARCHITECTURE (`x86_64:O2`). An entry here
#                          therefore never applies to a cross-architecture lane,
#                          and an entry that a cross-architecture run must also
#                          honour has to name both spellings. This is why the
#                          only live entry made the x86-64 control lane disagree
#                          with the gate and blocked `--write-baseline`.
#   pointer_return_arg: int — compare a returned pointer by its element index
#                          within this caller-owned pointer-argument buffer.
#   non_length_args: [int] — human-reviewed scalar parameters beside a pointer
#                          that are values/keys, not bounds used for addressing.
#   link_chains: [[int]] — THE LINKED-STRUCTURE ARGUMENT KIND. A list of node
#                          chains over a caller-owned array of self-referential
#                          structs; the buffer for vector `k` uses chain
#                          `k % len(link_chains)`. A chain is an element-index
#                          walk (`chain[0] -> chain[1] -> ... -> NULL`); every
#                          node the chain does not name is NULL-linked. The
#                          worker turns the indices into real addresses AFTER
#                          allocating each side's array, so the original and the
#                          rebuilt object get the same graph in their own
#                          storage, and reads any surviving link back as an
#                          index.
#                          Declare one whenever a fixture is ABOUT pointer
#                          chasing. Without it the successor is `index + 1`, and
#                          a recovery that turns `p = p->next` into `p += 1`
#                          walks the identity chain identically — the fixture
#                          would pass no matter what the decompiler did with the
#                          load. Validated fail-closed: a chain must start at
#                          element 0 (the callee is handed `&buffer[0]`; anything
#                          else is unreachable), must not repeat an index (a
#                          cycle does not terminate, and the ORIGINAL side would
#                          eat the whole wall clock), and must stay inside
#                          ptr_len. `extra_vectors` state their links inline and
#                          are not affected by this.
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

#: The node chains `192_pointer_chased_list` links its generated buffers with,
#: cycled by vector index. Named rather than repeated so every function in that
#: fixture walks the SAME graphs and their answers are comparable by hand.
#:
#: Four are deliberately not the identity successor -- a subset, a short chain
#: that reaches the last element, a singleton, and a full permutation -- because
#: the identity chain is exactly the one a `p += 1` misrecovery walks correctly.
#: The fifth IS the identity, so the degenerate graph keeps a lane.
_L192_CHAINS: list[list[int]] = [
    [0, 5, 2, 9, 1, 14],
    [0, 15, 7, 3],
    [0],
    [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
    list(range(16)),
]

#: One hand-built graph for `192_pointer_chased_list`, as `[next, key, payload]`
#: per node in DWARF field order. Chain 0 -> 3 -> 5 -> NULL; nodes 1, 2 and 4 are
#: reachable only by an index walk, and carry the keys the searches ask for.
_L192_GRAPH: list[list[int]] = [
    [3, 5, 1],
    [-1, 7, 20],
    [-1, 8, 30],
    [5, 7, 4],
    [-1, 9, 50],
    [-1, 6, 7],
]

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
        "arg_values": {
            0: [-7, 0, 1, 3, 10000],
            1: [-4, 1, 2, 6, 10000],
            2: [-3, 0, 1, 5, 10000],
            3: [-2, 1, 3, 8, 10000],
        },
    },
    ("58_rational", "rational_compare"): {
        "arg_values": {
            0: [-7, 0, 1, 3, 10000],
            1: [-4, 1, 2, 6, 10000],
            2: [-3, 0, 1, 5, 10000],
            3: [-2, 1, 3, 8, 10000],
        },
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
        "arg_values": {
            4: [1, 65536, 655360],
            5: [1, 256, 6553, 65536],
            6: [0, 1, 4, 16],
        },
    },
    ("68_thermodynamics", "newton_cooling"): {
        "arg_values": {2: [0, 1024, 32768, 65536], 3: [0, 1, 8, 24]},
    },
    ("69_molar_mass", "molar_mass_centi"): {
        "len_args": [1],
        "extra_vectors": [
            [[72, 50, 79], 3],
            [[67, 54, 72, 49, 50, 79, 54], 7],
            [[78, 97, 67, 108], 4],
        ],
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
    # --- packed and unaligned wire formats ---
    # --- scale and complexity stress ---
    # --- IEEE floating point (harness FP support landed with these) ---
    ("172_float_double_widths", "accumulate_narrow"): {
        "len_args": [1],
    },
    ("172_float_double_widths", "accumulate_wide"): {
        "len_args": [1],
        # The `gcc:O2` skip that used to live here worked around a HANG, not an
        # unexecutable shape: `refine_float_copy_types` reported "the map did
        # not take my hint" as progress, and this function — a `double`
        # accumulator fed by `float` terms, the exact declined join — spun
        # forever. That is fixed (it now decompiles in ~0.03s), so the skip is
        # removed and the lane records its real verdict.
        #
        # Removing it also settles a disagreement between the two harnesses.
        # `skip_exec_lanes` is keyed by `"<compiler>:<opt>"`, which is what
        # `fixture_harness` passes; `tools/arch_roundtrip.py` passes
        # `"<arch>:<opt>"`, so no entry here has ever applied to a
        # cross-architecture lane. This function was the only live entry, and
        # it made the x86-64 control lane (`x86_64:O2`, executed) disagree with
        # the gate (`gcc:O2`, skipped) — which blocks `--write-baseline`.
    },
    ("174_float_compare_classify", "ordered_compare_binary32"): {
        "extra_vectors": [[0.0, -0.0], [-0.0, 0.0], [1.0, -1.0]],
    },
    ("175_float_matrix_kernel", "dot_product_f32"): {
        "len_args": [2],
    },
    ("175_float_matrix_kernel", "dot_product_f64"): {
        "len_args": [2],
    },
    ("175_float_matrix_kernel", "sum_of_squares_f32"): {
        "len_args": [1],
    },
    ("175_float_matrix_kernel", "scale_series_f32"): {
        "len_args": [1],
    },
    # --- coverage-directed additions ------------------------------------
    # 181: `terms` is a float buffer read at `count` elements.
    ("181_compensated_summation", "naive_sum_f64"): {
        "len_args": [1],
    },
    ("181_compensated_summation", "kahan_sum_f64"): {
        "len_args": [1],
    },
    ("181_compensated_summation", "summation_disagrees"): {
        "len_args": [1],
    },
    # 183: index-list walks over a caller-owned integer buffer. `key` is a
    # value being searched for, never a bound.
    ("183_sentinel_list_search", "find_by_key"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("183_sentinel_list_search", "find_terminated_by_sentinel"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("183_sentinel_list_search", "find_before_either_sentinel"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("183_sentinel_list_search", "find_byte_before_nul"): {
        "ptr_elem": "cstr",
        "non_length_args": [1],
    },
    ("183_sentinel_list_search", "length_to_nul"): {
        "ptr_elem": "cstr",
    },
    # 184: every fill WRITES its buffer, so both the count and the probe index
    # must be clamped into it.
    ("184_rep_stos_widths", "fill_bytes_and_probe"): {
        "ptr_elem": "u8",
        "len_args": [1, 2],
    },
    ("184_rep_stos_widths", "fill_dwords_and_probe"): {
        "len_args": [1, 2],
    },
    ("184_rep_stos_widths", "fill_qwords_and_probe"): {
        # Eight-byte elements in a buffer measured in four-byte units: halve the
        # element count so the fill stays inside the allocation.
        "ptr_len": 8,
        "len_args": [1, 2],
    },
    ("184_rep_stos_widths", "fill_then_patch_and_probe"): {
        "ptr_elem": "u8",
        "len_args": [1, 2],
    },
    ("184_rep_stos_widths", "zero_fixed_block_and_probe"): {
        # The fixed block is FILL184_LIMIT dwords; the buffer must hold them.
        "ptr_len": 16,
        "non_length_args": [1],
    },
    # 186: the discriminant is a value, not a bound. Every real case constant
    # is driven exactly, plus at least one value that falls off the end — the
    # answer for THAT input is what separates a defaultless switch from one
    # whose out-of-range edge was recovered as an invented default arm, and a
    # random -64..63 would never reach the sparse cases at all.
    ("186_defaultless_guarded_switch", "dense_no_default"): {
        "extra_vectors": [[0], [1], [2], [3], [4], [5], [6], [7], [8], [-1]],
    },
    ("186_defaultless_guarded_switch", "sparse_no_default"): {
        "extra_vectors": [[-1000], [0], [17], [4096], [1000000], [1], [-1], [INT_MAX]],
    },
    ("186_defaultless_guarded_switch", "fallthrough_no_default"): {
        "extra_vectors": [[0], [1], [2], [3], [4], [5], [6], [7]],
    },
    ("186_defaultless_guarded_switch", "returning_arms_no_default"): {
        "extra_vectors": [[10], [11], [12], [13], [9], [14], [0]],
    },
    ("186_defaultless_guarded_switch", "loop_switch_no_default"): {
        "len_args": [1],
    },
    # 185: sub-word division. The boundary sweep supplies the extremes; these
    # add the pairs where sign extension is the whole answer — a negative
    # dividend with a positive divisor, and both `INT*_MIN / -1` guards.
    ("185_subword_signed_division", "divide_signed_bytes"): {
        "extra_vectors": [[-7, 2], [7, -2], [-128, -1], [-128, 1], [127, -1], [0, -3]],
    },
    ("185_subword_signed_division", "remainder_signed_bytes"): {
        "extra_vectors": [[-7, 2], [7, -2], [-128, -1], [-128, 3], [127, -1], [0, -3]],
    },
    ("185_subword_signed_division", "divide_signed_shorts"): {
        "extra_vectors": [
            [-30000, 7],
            [30000, -7],
            [-32768, -1],
            [-32768, 3],
            [32767, -1],
            [0, -3],
        ],
    },
    ("185_subword_signed_division", "remainder_signed_shorts"): {
        "extra_vectors": [
            [-30000, 7],
            [30000, -7],
            [-32768, -1],
            [-32768, 3],
            [32767, -1],
            [0, -3],
        ],
    },
    ("185_subword_signed_division", "divide_short_by_seven"): {
        "extra_vectors": [[-30000], [-7], [-6], [-1], [0], [6], [7], [32767]],
    },
    ("151_wide_branch_ladder", "big151_branch_ladder"): {
        "len_args": [2],
        "non_length_args": [0],
    },
    ("152_deep_nesting", "deep152_nested_loops"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("152_deep_nesting", "deep152_while_tower"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("153_many_live_locals", "spill153_live_set"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("153_many_live_locals", "spill153_static_web"): {
        "len_args": [1],
    },
    ("154_wide_switch", "wide154_dense_effects"): {
        "len_args": [2],
        "non_length_args": [0],
    },
    ("155_long_dependency_chain", "chain155_buffered"): {
        "len_args": [1],
    },
    ("161_packed_struct_layout", "pk161_member_offset"): {
        "arg_values": {0: [0, 1, 2, 3, 4, 5, 6, 7]},
    },
    ("161_packed_struct_layout", "pk161_encode"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "non_length_args": [2, 3],
    },
    ("161_packed_struct_layout", "pk161_read_field"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {2: [0, 1, 2, 3]},
        "extra_vectors": [[[52, 239, 190, 173, 222, 18, 0, 222], 8, 1]],
    },
    ("162_unaligned_memcpy_access", "ua162_load_native32"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 2],
    },
    ("162_unaligned_memcpy_access", "ua162_load_native16"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 2],
    },
    ("162_unaligned_memcpy_access", "ua162_load_be32"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 2],
        "extra_vectors": [[[17, 34, 51, 68, 85, 102, 119, 136], 16, 1]],
    },
    ("162_unaligned_memcpy_access", "ua162_store_native32"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 2],
        "non_length_args": [3],
    },
    ("162_unaligned_memcpy_access", "ua162_store_be32"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 2],
        "non_length_args": [3],
    },
    ("162_unaligned_memcpy_access", "ua162_move_field32"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 2, 3],
    },
    ("162_unaligned_memcpy_access", "ua162_roundtrip"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 5, 11, 12, 13, 16]},
    },
    ("163_wire_header_parser", "hdr163_validate"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "extra_vectors": [
            [[90, 71, 2, 3, 222, 173, 190, 239, 0, 4, 65, 66, 67, 68, 0, 0], 14],
            [[90, 71, 2, 3, 222, 173, 190, 239, 0, 4, 65, 66, 67, 68, 0, 0], 12],
            [[90, 71, 2, 3, 222, 173, 190, 239, 0, 4, 65, 66, 67, 68, 0, 0], 6],
        ],
    },
    ("163_wire_header_parser", "hdr163_stream_id"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "extra_vectors": [
            [[90, 71, 2, 3, 222, 173, 190, 239, 0, 4, 65, 66, 67, 68, 0, 0], 14]
        ],
    },
    ("163_wire_header_parser", "hdr163_payload_digest"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "extra_vectors": [
            [[90, 71, 2, 3, 222, 173, 190, 239, 0, 4, 65, 66, 67, 68, 0, 0], 14]
        ],
    },
    ("163_wire_header_parser", "hdr163_copy_payload"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1, 3],
    },
    ("163_wire_header_parser", "hdr163_build"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {3: [-1, 0, 1, 4, 6, 7, 100]},
        "non_length_args": [2],
    },
    ("164_nested_tlv_walker", "tlv164_node_count"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "extra_vectors": [
            [[129, 8, 1, 2, 170, 187, 130, 2, 3, 0, 4, 1, 119, 0, 0, 0], 13]
        ],
    },
    ("164_nested_tlv_walker", "tlv164_max_depth"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "extra_vectors": [
            [[129, 8, 1, 2, 170, 187, 130, 2, 3, 0, 4, 1, 119, 0, 0, 0], 13]
        ],
    },
    ("164_nested_tlv_walker", "tlv164_leaf_sum"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "extra_vectors": [
            [[129, 8, 1, 2, 170, 187, 130, 2, 3, 0, 4, 1, 119, 0, 0, 0], 13]
        ],
    },
    ("164_nested_tlv_walker", "tlv164_find_type"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {2: [0, 1, 3, 4, 129, 130, 9, 255]},
        "non_length_args": [2],
        "extra_vectors": [
            [[129, 8, 1, 2, 170, 187, 130, 2, 3, 0, 4, 1, 119, 0, 0, 0], 13, 3]
        ],
    },
    ("164_nested_tlv_walker", "tlv164_encode_nested"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {3: [-1, 0, 1, 2, 4, 5, 100]},
        "non_length_args": [2],
    },
    ("165_bitstream_reader", "bit165_read_bits"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {
            2: [-1, 0, 1, 3, 7, 8, 15, 16, 31, 32, 35, 39, 40, 127, 128],
            3: [-1, 0, 1, 3, 8, 13, 19, 24, 25, 32],
        },
        "extra_vectors": [
            [[191, 255, 18, 52, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 5, 3, 13],
            [[191, 255, 18, 52, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 5, 16, 19],
            [[191, 255, 18, 52, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 5, 0, 3],
        ],
    },
    ("165_bitstream_reader", "bit165_cross_check"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {
            2: [-1, 0, 1, 3, 7, 8, 15, 16, 31, 32, 35, 39, 40, 127, 128],
            3: [-1, 0, 1, 3, 8, 13, 19, 24, 25, 32],
        },
        "extra_vectors": [
            [[191, 255, 18, 52, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 5, 3, 13]
        ],
    },
    ("165_bitstream_reader", "bit165_read_sequence"): {
        "ptr_len": 16,
        "len_args": [1, 4],
        "arg_values": {2: [-1, 0, 1, 3, 5, 8, 13, 24, 25, 64]},
    },
    ("165_bitstream_reader", "bit165_write_frame"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "non_length_args": [2, 3],
    },
    # --- ELF linking and dynamic-loading shapes ---
    ("156_plt_and_got_calls", "plt_fold_calls"): {
        "len_args": [1],
    },
    ("157_symbol_visibility", "vis_read_bias"): {
        "arg_values": {0: [0, 1, 2, 3, -1]},
    },
    ("157_symbol_visibility", "vis_fold_with_biases"): {
        "len_args": [1],
    },
    ("158_weak_symbols", "weak_dispatch"): {
        "arg_values": {1: [0, 1]},
    },
    ("158_weak_symbols", "weak_fold"): {
        "len_args": [1],
    },
    ("159_ifunc_resolver", "ifunc_fold"): {
        "len_args": [1],
    },
    # 160: .init_array state cannot survive rebuilding ONE function. The rebuilt
    # object has no constructor and no .init_array entry, so these globals hold
    # their .data image values (-1 / 0 / zeroed) while the original holds the
    # post-constructor values (1 / 12 / 10,20,30,40). Verified NOT a decompiler
    # defect: a hand-written faithful recovery returning the true image value
    # still fails (1 != -1, 12 != 0, 10 != 0). Contracts kept intact so they
    # remain correct if skip_exec is ever removed.
    ("160_init_and_fini", "initfini_ready"): {"skip_exec": True},
    ("160_init_and_fini", "initfini_order"): {"skip_exec": True},
    ("160_init_and_fini", "initfini_table"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 4]},
        "skip_exec": True,
    },
    ("160_init_and_fini", "initfini_fold"): {
        "len_args": [1],
        "skip_exec": True,
    },
    # --- obfuscated and adversarial constructs ---
    ("145_control_flow_flattening", "flattened_accumulate"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("145_control_flow_flattening", "flattened_search"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("146_opaque_predicates", "opaque_loop_filter"): {
        "len_args": [1],
    },
    ("146_opaque_predicates", "opaque_guarded_store"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("147_instruction_substitution", "substituted_checksum"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
    },
    ("148_dispatch_obfuscation", "chained_table_walk"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("149_mba_expressions", "mba_mix_buffer"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "non_length_args": [2],
    },
    ("150_obfuscation_composite", "obfuscated_transform"): {
        "len_args": [1],
        "non_length_args": [2],
    },
    ("150_obfuscation_composite", "obfuscated_digest"): {
        "ptr_len": 16,
        "ptr_elem": "u8",
        "len_args": [1],
        "arg_values": {2: [0, 1, 2, 3, 4]},
    },
    # --- systems and ABI: TLS, atomics, non-local control, inline asm ---
    ("140_thread_local_storage", "tls_indexed"): {
        "arg_values": {0: [-1, 0, 1, 3, 4]},
    },
    ("141_atomics", "atomic_increment"): {
        "arg_values": {1: [0, 1, 8, 16]},
    },
    ("142_nonlocal_control", "setjmp_returns_twice"): {
        "arg_values": {0: [0, 1, 4, 8, 9]},
    },
    ("142_nonlocal_control", "longjmp_unwinds_frames"): {
        "arg_values": {0: [0, 1, 4, 8], 1: [1, 3, 8]},
    },
    ("143_dynamic_frames", "alloca_dynamic_frame"): {
        "arg_values": {0: [1, 2, 8, 16]},
    },
    ("143_dynamic_frames", "alloca_in_loop"): {
        "arg_values": {0: [0, 1, 2, 4], 1: [1, 4, 8]},
    },
    ("143_dynamic_frames", "cleanup_on_every_exit"): {
        "ptr_len": 4,
        "arg_values": {1: [0, 1, 2, 3]},
    },
    ("144_inline_asm", "asm_memory_barrier"): {
        "ptr_len": 4,
    },
    ("144_inline_asm", "builtin_bit_intrinsics"): {
        "arg_values": {1: [0, 1, 2, 3]},
    },
    ("144_inline_asm", "builtin_overflow_checked"): {
        "ptr_len": 4,
    },
    # --- C++ runtime shape contracts ---
    ("136_cpp_exception_unwinding", "cpp_catch_by_type"): {
        "arg_values": {0: [0, 1, 2, 3]},
    },
    ("136_cpp_exception_unwinding", "cpp_destructors_run_while_unwinding"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 2, 3]},
    },
    ("136_cpp_exception_unwinding", "cpp_rethrow_and_nest"): {
        "arg_values": {0: [0, 1, 2, 3]},
    },
    ("137_cpp_templates", "cpp_template_int32"): {
        "len_args": [1],
    },
    ("137_cpp_templates", "cpp_template_int16"): {
        "len_args": [1],
    },
    ("137_cpp_templates", "cpp_template_uint8"): {
        "len_args": [1],
    },
    ("137_cpp_templates", "cpp_template_predicate"): {
        "len_args": [1],
    },
    ("137_cpp_templates", "cpp_template_nontype"): {
        "len_args": [1],
    },
    ("139_cpp_object_lifetime", "cpp_destruction_order"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1]},
    },
    ("139_cpp_object_lifetime", "cpp_array_destruction"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 2, 3, 4]},
    },
    ("139_cpp_object_lifetime", "cpp_live_object_count"): {
        "arg_values": {0: [-1, 0, 1, 2, 4]},
    },
    ("132_cpp_vtable_layout", "cpp_vtable_area"): {
        "arg_values": {0: [0, 1, 2, 3]},
    },
    ("132_cpp_vtable_layout", "cpp_vtable_inherited_slot"): {
        "arg_values": {0: [0, 1, 2, 3]},
    },
    ("134_cpp_virtual_inheritance", "cpp_virtual_final_overrider"): {
        "arg_values": {0: [0, 1, 2, 3]},
    },
    ("135_cpp_rtti", "cpp_dynamic_cast_succeeds"): {
        "arg_values": {0: [0, 1]},
    },
    ("135_cpp_rtti", "cpp_dynamic_cast_fails"): {
        "arg_values": {0: [0, 1]},
    },
    ("135_cpp_rtti", "cpp_typeid_compare"): {
        "arg_values": {0: [0, 1, 2, 3]},
    },
    ("138_cpp_operators", "cpp_operator_compound"): {
        "arg_values": {1: [0, 1, 8, 16]},
    },
    # --- C language edge-case contracts (fixtures 82-131) ---
    ("82_comma_operator", "comma_chain"): {
        "ptr_len": 4,
    },
    ("82_comma_operator", "comma_in_for"): {
        "arg_values": {0: [0, 1, 2, 7, 16]},
    },
    ("82_comma_operator", "comma_in_condition"): {
        "arg_values": {0: [0, 1, 5, 32]},
    },
    ("83_ternary_chains", "nested_ternary_assignment"): {
        "ptr_len": 4,
    },
    ("86_flexible_array_member", "flexible_sum"): {
        "len_args": [1],
        "extra_vectors": [[[3, 7, 10, 20, 30], 5]],
    },
    ("87_variable_length_array", "vla_reverse_sum"): {
        "arg_values": {1: [1, 2, 5, 16]},
    },
    ("87_variable_length_array", "vla_two_dimensional"): {
        "arg_values": {0: [1, 2, 4], 1: [1, 3, 4]},
    },
    ("88_restrict_pointers", "restrict_accumulate"): {
        "len_args": [2],
    },
    ("88_restrict_pointers", "aliasing_accumulate"): {
        "len_args": [2],
    },
    ("95_function_pointer_table", "dispatch_operation"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 4, 5]},
    },
    ("95_function_pointer_table", "fold_operations"): {
        "len_args": [1],
    },
    ("99_char_and_endianness", "load_big_endian"): {
        "len_args": [1],
    },
    ("102_duffs_device", "duff_copy"): {
        "arg_values": {2: [1, 2, 3, 7, 8, 9, 16]},
    },
    ("103_computed_goto", "threaded_interpreter"): {
        "len_args": [1],
    },
    ("104_statement_expression", "single_evaluation"): {
        "ptr_len": 4,
    },
    ("105_goto_ladder", "acquire_and_release"): {
        "arg_values": {0: [0, 1, 2, 3, 4], 2: [4, 8, 16]},
    },
    ("107_short_circuit", "short_circuit_and"): {
        "ptr_len": 4,
    },
    ("107_short_circuit", "short_circuit_or"): {
        "ptr_len": 4,
    },
    ("107_short_circuit", "guarded_dereference"): {
        "len_args": [1, 2],
    },
    ("108_multidimensional_arrays", "sum_true_2d"): {
        "arg_values": {1: [0, 1, 2, 4]},
    },
    ("108_multidimensional_arrays", "sum_flat_with_stride"): {
        "arg_values": {1: [0, 1, 2, 4], 2: [0, 1, 2, 4]},
    },
    ("108_multidimensional_arrays", "row_decay_span"): {
        "arg_values": {1: [0, 1, 2, 3]},
    },
    ("109_subscript_commutativity", "reversed_subscript"): {
        "len_args": [1, 2],
    },
    ("109_subscript_commutativity", "mixed_subscript_sum"): {
        "len_args": [1],
    },
    ("109_subscript_commutativity", "negative_offset_from_interior"): {
        "arg_values": {1: [2, 3, 8, 16]},
    },
    # A constant bias is only exercised when `count` actually reaches the
    # guarded domain, so every entry pins the domain rather than clamping it:
    # the boundary value and the first rejected value are both swept, and a
    # rejected count must return -1 identically on both sides.
    # Counts are pinned rather than clamped so the vectorized path is actually
    # entered: a count below the vector width never emits a packed batch, and a
    # count past the guard must return -1 identically on both sides.
    # scratch[0] is the effect counter, scratch[1] the selected value,
    # scratch[2] the witnessed count; flags are pinned to both polarities so
    # each arm of every diamond is actually taken.
    # Address-shaped constants in two roles, against `program::references`.
    # `MC193_NAMES` is a relocation-fixed pointer table: its slots are
    # references the loader writes, and reading them as either an image address
    # or a number produces a value the rebuilt unit does not map.
    # `MC193_OFFSETS` is the control — same indexed-table shape, entries chosen
    # to sit inside this object's own mapped range, and still integers. `which`
    # covers the table domain and both out-of-range neighbours (the source
    # masks, so nothing is UB). `probe` is pinned to the exact control entries
    # (0x00f0, 0x1140, 0x2008, 0x2100) and to values either side, so an entry
    # that was promoted to a pointer moves the comparison instead of cancelling.
    ("193_mapped_constant_roles", "mc193_name_length"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 4]},
    },
    ("193_mapped_constant_roles", "mc193_name_bytes"): {
        "ptr_len": 4,
        "non_length_args": [0],
        "arg_values": {0: [-1, 0, 1, 2, 3, 4]},
    },
    ("193_mapped_constant_roles", "mc193_names_differ"): {
        "arg_values": {0: [0, 1, 2, 3], 1: [0, 1, 2, 3]},
    },
    ("193_mapped_constant_roles", "mc193_offset_sum"): {
        "arg_values": {0: [0, 1, 2, 3, 4]},
    },
    ("193_mapped_constant_roles", "mc193_offset_matches"): {
        "arg_values": {
            0: [0, 1, 2, 3],
            1: [0, 240, 4415, 4416, 8200, 8448, 4294967295],
        },
    },
    ("193_mapped_constant_roles", "mc193_scaled_constant"): {
        "arg_values": {0: [0, 1, 2, 255, 65536, 4294967295]},
    },
    # A caller-owned node array walked by POINTER CHASE. `link_chains` is what
    # makes these functions test anything: the generated buffers are linked as a
    # scrambled, proper subset of the array, so a recovery that reads `p =
    # p->next` as `p += 1` visits a different set of nodes in a different order
    # on the very first vector. Four of the five chains are deliberately not the
    # identity; the fifth IS the identity, so the degenerate graph stays covered.
    # `l192_scan_index_control` shares the chains because it must walk the SAME
    # memory by index and disagree with the chase — that is what makes it a
    # near-miss control rather than an unrelated function.
    #
    # `extra_vectors` state one hand-built graph inline (links are element
    # indices; `link_chains` does not apply to them). Its shape is the point:
    # nodes 1, 2 and 4 sit OFF the chain and carry the keys the searches ask
    # for, so an index walk answers 1 where the chase answers 3, and answers 2
    # where the chase answers "not found". The padding the harness appends
    # (`next = -1`, `key = 0`) is off-chain too, which is why key 0 is searched.
    #
    #   idx: [next, key, payload]      chain: 0 -> 3 -> 5 -> NULL
    #     0: [ 3,  5,  1]   on chain, head
    #     1: [-1,  7, 20]   OFF chain, decoy key 7 at a lower index than node 3
    #     2: [-1,  8, 30]   OFF chain, decoy key 8 that the chase must NOT find
    #     3: [ 5,  7,  4]   on chain, the correct answer for key 7
    #     4: [-1,  9, 50]   OFF chain
    #     5: [-1,  6,  7]   on chain, tail
    ("192_pointer_chased_list", "l192_find_key"): {
        "pointer_return_arg": 0,
        "non_length_args": [1],
        "link_chains": _L192_CHAINS,
        "extra_vectors": [
            [_L192_GRAPH, 7],  # chase -> node 3; an index walk -> node 1
            [_L192_GRAPH, 5],  # head
            [_L192_GRAPH, 6],  # tail
            [_L192_GRAPH, 8],  # chase -> NULL; an index walk -> node 2
            [_L192_GRAPH, 0],  # chase -> NULL; an index walk -> the padding
            [_L192_GRAPH, 99],  # absent everywhere
        ],
    },
    ("192_pointer_chased_list", "l192_chase_keys"): {
        "arg_values": {2: [0, 1, 3, 8, 16, 17]},
        "link_chains": _L192_CHAINS,
        "extra_vectors": [
            [_L192_GRAPH, [0], 16],
            [_L192_GRAPH, [0], 2],
        ],
    },
    ("192_pointer_chased_list", "l192_sum_until_key"): {
        "non_length_args": [1],
        "link_chains": _L192_CHAINS,
        "extra_vectors": [
            [_L192_GRAPH, 7],  # stops after node 0
            [_L192_GRAPH, 6],  # stops after nodes 0 and 3
            [_L192_GRAPH, 99],  # runs the whole chain
        ],
    },
    ("192_pointer_chased_list", "l192_stamp_chain"): {
        "non_length_args": [1],
        "link_chains": _L192_CHAINS,
        "extra_vectors": [
            [_L192_GRAPH, 1],
            [_L192_GRAPH, -3],
        ],
    },
    ("192_pointer_chased_list", "l192_scan_index_control"): {
        "len_args": [1],
        "non_length_args": [2],
        "link_chains": _L192_CHAINS,
        "extra_vectors": [
            [_L192_GRAPH, 6, 7],  # index walk -> node 1, where the chase says 3
            [_L192_GRAPH, 6, 8],  # index walk -> node 2, where the chase says -1
            [_L192_GRAPH, 6, 99],
        ],
    },
    # A call through a proven function-pointer table. Every entry records the
    # arguments it received in the caller's buffer (slots 0-2), so an argument
    # list that is wrong but plausible is caught by the witness rather than by
    # luck. `which` is pinned to the table's own domain plus both out-of-range
    # neighbours; `t191_computed_args` deliberately passes values this function
    # computed rather than its own parameters.
    ("191_indirect_table_args", "t191_dispatch"): {
        "ptr_len": 8,
        "arg_values": {1: [-1, 0, 1, 2, 3, 4]},
    },
    ("191_indirect_table_args", "t191_computed_args"): {
        "ptr_len": 8,
        "arg_values": {1: [-1, 0, 1, 2, 3, 4]},
    },
    ("191_indirect_table_args", "t191_fold"): {
        "ptr_len": 8,
        "len_args": [2],
    },
    ("191_indirect_table_args", "t191_direct_control"): {"ptr_len": 8},
    # Aggregates by value across the SysV classification boundaries. The
    # struct-returning helpers are reachable only through their callers, which
    # is deliberate: the harness rebuilds one function at a time against extern
    # callees, so a caller's recovered C must get the aggregate ABI right to call
    # its helper at all. `seed` is pinned small and exact so the mixed case's
    # double stays exactly representable.
    ("195_by_value_aggregates", "bv195_pair_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("195_by_value_aggregates", "bv195_quad_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("195_by_value_aggregates", "bv195_mixed_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("195_by_value_aggregates", "bv195_big_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("195_by_value_aggregates", "bv195_scalar_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    # All-float aggregates: the return class 195 left out, and the one where the
    # two ABIs disagree most. Verified by disassembly rather than from memory
    # (`gcc -O1 -c` + `objdump -d`, and the aarch64 cross the same way):
    #
    #   {double,double}  SysV xmm0:xmm1        AAPCS64 d0,d1
    #   {float x4}       SysV xmm0:xmm1        AAPCS64 s0,s1,s2,s3
    #                    (TWO floats packed per xmm on SysV; FOUR separate
    #                     registers on AArch64 — same struct, same source)
    #   {float x3}       SysV xmm0 + half xmm1 AAPCS64 s0,s1,s2
    #   {float,int32_t}  SysV rax alone        AAPCS64 x0 alone
    #
    # `seed` stays small and integral so every float and double value is exactly
    # representable in both widths and the differential compares exact values.
    ("197_homogeneous_float_aggregates", "hfa197_pair2d_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("197_homogeneous_float_aggregates", "hfa197_quad4f_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("197_homogeneous_float_aggregates", "hfa197_trio3f_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("197_homogeneous_float_aggregates", "hfa197_tagged_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("197_homogeneous_float_aggregates", "hfa197_scalar_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    # Returns narrower than a register. `nrw194_bool_and` needs vectors where
    # BOTH masks are set, because that is the only case where normalising each
    # operand to 0/1 before the AND differs from ANDing the raw masks (4 & 8 is
    # zero). The seeded fuzz draws from -64..63 and hits it often; the explicit
    # vectors below make it independent of the draw, and pin the neighbouring
    # cases where exactly one operand is set.
    ("194_narrow_return_widths", "nrw194_bool_and"): {
        "extra_vectors": [[4, 8], [4, 0], [0, 8], [12, 24], [-1, -1], [5, 9]],
    },
    ("194_narrow_return_widths", "nrw194_bool_wide_control"): {
        "extra_vectors": [[4, 8], [4, 0], [0, 8], [12, 24], [-1, -1], [5, 9]],
    },
    # `x & 0x100` is outside the fuzz draw's -64..63, so without these the bit
    # this function is about is never set and the answer is a constant 0.
    ("194_narrow_return_widths", "nrw194_bool_bit"): {
        "extra_vectors": [[0x100], [0x1FF], [0xFF], [-0x100], [0x101], [0x200]],
    },
    # The aggregate return classes 195 and 197 leave out. Same discipline as
    # those two: the struct/union-returning helpers are reachable only through
    # their callers, because `exec_class` refuses every aggregate return, and
    # `seed` is pinned small and exact so no product overflows and the double
    # written into the union has an exactly representable bit pattern.
    ("198_aggregate_return_edges", "agr198_one_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_bytes3_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_trio_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_bits_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_arr2_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_five_roundtrip"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_i64_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("198_aggregate_return_edges", "agr198_scalar_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    # POINTER RETURNS. `pointer_return_arg` is what makes them executable at
    # all: without it `exec_class` refuses a pointer return outright, and with
    # it the worker compares the returned ELEMENT INDEX inside the named
    # caller-owned buffer instead of two unrelated process addresses. `n` is the
    # length (clamped to the buffer); `key`/`k` are values.
    #
    # `key` must sometimes HIT and sometimes MISS, or the fixture only ever
    # measures one branch. The buffer is drawn from -64..63, so the pinned
    # values below straddle it: 1000 can never occur (NULL), and the small ones
    # occur often. `extra_vectors` states buffers with a REPEATED key, which is
    # the only way `ptr199_find_const`'s reverse scan differs from
    # `ptr199_find_i32`'s forward one, and buffers whose match is in the
    # INTERIOR, which is where `ptr199_edge_element` stops agreeing with a
    # recovery that let the match position reach the result.
    ("199_pointer_return_kinds", "ptr199_find_i32"): {
        "ptr_len": 8,
        "pointer_return_arg": 0,
        "len_args": [1],
        "non_length_args": [2],
        "arg_values": {2: [0, 1, -1, 5, 1000]},
        "extra_vectors": [
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 3],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 5],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 9],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 42],
        ],
    },
    ("199_pointer_return_kinds", "ptr199_find_void"): {
        "ptr_len": 8,
        "pointer_return_arg": 0,
        "len_args": [1],
        "non_length_args": [2],
        "arg_values": {2: [0, 1, -1, 5, 1000]},
        "extra_vectors": [
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 3],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 5],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 9],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 42],
        ],
    },
    ("199_pointer_return_kinds", "ptr199_find_const"): {
        "ptr_len": 8,
        "pointer_return_arg": 0,
        "len_args": [1],
        "non_length_args": [2],
        "arg_values": {2: [0, 1, -1, 5, 1000]},
        "extra_vectors": [
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 3],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 5],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 9],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 42],
        ],
    },
    ("199_pointer_return_kinds", "ptr199_offset"): {
        "ptr_len": 8,
        "pointer_return_arg": 0,
        "len_args": [1],
        "non_length_args": [2],
        "arg_values": {2: [0, 1, 7, 8, -1, -9, 2147483647]},
    },
    ("199_pointer_return_kinds", "ptr199_edge_element"): {
        "ptr_len": 8,
        "pointer_return_arg": 0,
        "len_args": [1],
        "non_length_args": [2],
        "arg_values": {2: [0, 1, -1, 5, 1000]},
        "extra_vectors": [
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 3],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 5],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 9],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 42],
        ],
    },
    ("199_pointer_return_kinds", "ptr199_find_index"): {
        "ptr_len": 8,
        "len_args": [1],
        "non_length_args": [2],
        "arg_values": {2: [0, 1, -1, 5, 1000]},
        "extra_vectors": [
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 3],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 5],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 9],
            [[9, 3, 5, 3, 7, 5, 1, 0], 8, 42],
        ],
    },
    # The frame-slot controls. `dfs196_indexed_control` masks its seed down to
    # an index, so the vectors have to include values that select the slot the
    # pending load reads (k == 5) as well as ones that do not.
    ("196_disjoint_frame_slots", "dfs196_spill_web"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4, 2147483647]},
    },
    ("196_disjoint_frame_slots", "dfs196_alias_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    ("196_disjoint_frame_slots", "dfs196_indexed_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 5, 7, 13, -1, -4]},
    },
    ("196_disjoint_frame_slots", "dfs196_overlap_control"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1, 3, 7, -1, -4]},
    },
    # Two logically distinct values from ONE machine operation. `b` is pinned
    # away from zero on most vectors (the guard returns early otherwise, which
    # tests nothing) and includes values where quotient and remainder differ in
    # magnitude, so substituting one for the other is visible.
    ("190_dual_role_products", "dp190_div_and_rem"): {
        "ptr_len": 12,
        "arg_values": {2: [1, 3, 7, 256, 4294967295]},
    },
    ("190_dual_role_products", "dp190_sdiv_and_rem"): {
        "ptr_len": 12,
        "arg_values": {2: [1, -1, 3, -7, 256]},
    },
    ("190_dual_role_products", "dp190_mul_both_halves"): {
        "ptr_len": 12,
        "arg_values": {
            1: [0, 1, 65535, 65536, 4294967295],
            2: [1, 3, 65536, 4294967295],
        },
    },
    ("190_dual_role_products", "dp190_pair_across_join"): {
        "ptr_len": 12,
        "arg_values": {2: [1, 3, 7, 256], 3: [0, 1]},
    },
    ("190_dual_role_products", "dp190_quotient_only"): {
        "ptr_len": 12,
        "arg_values": {2: [1, 3, 7, 256]},
    },
    ("189_effectful_select", "se189_bump"): {"ptr_len": 4},
    ("189_effectful_select", "se189_select_call"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1]},
    },
    ("189_effectful_select", "se189_select_one_arm"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1]},
    },
    ("189_effectful_select", "se189_nested_select"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1], 2: [0, 1]},
    },
    ("189_effectful_select", "se189_select_pure"): {
        "ptr_len": 8,
        "arg_values": {1: [0, 1]},
    },
    ("188_vector_transport", "vt188_copy_forward"): {
        "ptr_len": 64,
        "arg_values": {2: [0, 1, 4, 8, 16, 33, 64, 65]},
    },
    ("188_vector_transport", "vt188_copy_backward"): {
        "ptr_len": 64,
        "arg_values": {2: [0, 1, 4, 8, 16, 33, 64, 65]},
    },
    ("188_vector_transport", "vt188_copy_two_streams"): {
        "ptr_len": 64,
        "arg_values": {3: [0, 1, 4, 8, 16, 33, 64, 65]},
    },
    ("188_vector_transport", "vt188_lane_math"): {
        "ptr_len": 64,
        "arg_values": {2: [0, 1, 4, 8, 16, 33, 64, 65]},
    },
    ("187_constant_bias_index", "bias_forward_sum"): {
        "arg_values": {1: [0, 1, 2, 7, 13, 14, 15]},
    },
    ("187_constant_bias_index", "bias_backward_pair"): {
        "arg_values": {1: [0, 1, 2, 8, 15, 16, 17]},
    },
    ("187_constant_bias_index", "adjacent_difference"): {
        "arg_values": {1: [0, 1, 2, 8, 15, 16, 17]},
    },
    ("187_constant_bias_index", "value_bias_not_index"): {
        "arg_values": {1: [0, 1, 2, 8, 15, 16, 17]},
    },
    ("187_constant_bias_index", "variable_bias"): {
        "arg_values": {1: [0, 1, 2, 8, 16, 17], 2: [0, 1, 2, 3]},
    },
    ("110_pointer_arithmetic", "element_distance"): {
        "len_args": [1],
    },
    ("110_pointer_arithmetic", "byte_versus_element_step"): {
        "len_args": [1],
    },
    ("110_pointer_arithmetic", "walk_until_sentinel"): {
        "len_args": [1],
    },
    ("111_self_referential_struct", "link_and_sum"): {
        "arg_values": {1: [0, 1, 4, 8]},
    },
    ("113_varargs", "variadic_three"): {
        "arg_values": {0: [-3, 0, 7], 1: [-1, 2, 9], 2: [0, 4, 11]},
    },
    ("113_varargs", "variadic_weighted_four"): {
        "arg_values": {0: [-3, 0, 7], 1: [-1, 2, 9], 2: [0, 4, 11], 3: [1, 5, 13]},
    },
    ("116_string_literals", "literal_index"): {
        "arg_values": {0: [-1, 0, 3, 5, 6]},
    },
    ("116_string_literals", "count_matching"): {
        "len_args": [1],
    },
    ("116_string_literals", "escape_sequences"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 4, 5]},
    },
    ("117_modular_arithmetic", "modular_exponent_of_two"): {
        "arg_values": {0: [-1, 0, 1, 16, 31, 32]},
    },
    ("118_bit_tricks", "xor_swap"): {
        "ptr_len": 4,
    },
    ("119_branch_hints", "hinted_validation"): {
        "len_args": [1],
    },
    ("119_branch_hints", "unhinted_validation"): {
        "len_args": [1],
    },
    ("120_const_and_literals", "pointer_to_const_still_loads"): {
        "len_args": [1],
    },
    ("120_const_and_literals", "const_array_of_pointers"): {
        "arg_values": {0: [-1, 0, 1, 2, 3]},
    },
    ("121_dense_expression", "dense_fold"): {
        "len_args": [1],
    },
    ("121_dense_expression", "chained_assignment"): {
        "ptr_len": 4,
    },
    ("121_dense_expression", "conditional_lvalue_select"): {
        "ptr_len": 4,
    },
    ("122_compound_assignment", "subscript_evaluated_once"): {
        "len_args": [1],
    },
    ("122_compound_assignment", "narrow_compound_truncates"): {
        "arg_values": {1: [0, 1, 5, 16]},
    },
    ("123_sizeof_semantics", "sizeof_probe_sets_flag"): {
        "ptr_len": 4,
    },
    ("123_sizeof_semantics", "sizeof_does_not_evaluate"): {
        "ptr_len": 4,
    },
    ("123_sizeof_semantics", "sizeof_after_decay"): {
        "ptr_len": 8,
    },
    ("123_sizeof_semantics", "sizeof_vla_is_evaluated"): {
        "arg_values": {0: [1, 2, 8, 16]},
    },
    ("124_loop_break_continue", "break_binds_to_switch"): {
        "len_args": [1],
    },
    ("124_loop_break_continue", "nested_loop_early_exit"): {
        "arg_values": {1: [0, 1, 2, 4], 2: [0, 1, 2, 4]},
    },
    ("124_loop_break_continue", "continue_in_do_while"): {
        "arg_values": {0: [0, 1, 5, 16]},
    },
    ("125_loop_shapes", "while_zero_trips"): {
        "arg_values": {0: [0, 1, 5, 16]},
    },
    ("125_loop_shapes", "do_while_always_once"): {
        "arg_values": {0: [0, 1, 5, 16]},
    },
    ("125_loop_shapes", "infinite_with_internal_exit"): {
        "arg_values": {0: [0, 1, 5, 16]},
    },
    ("125_loop_shapes", "decrementing_loop"): {
        "arg_values": {0: [0, 1, 5, 16]},
    },
    ("126_x_macros", "opcode_weight"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 4, 5]},
    },
    ("126_x_macros", "apply_opcode"): {
        "arg_values": {0: [-1, 0, 1, 2, 3, 4, 5]},
    },
    ("127_inline_linkage", "inline_in_loop"): {
        "len_args": [1],
    },
    ("128_qualifier_combinations", "pointer_to_const_walks"): {
        "len_args": [1],
    },
    ("128_qualifier_combinations", "const_pointer_writes"): {
        "len_args": [1],
    },
    ("131_obfuscated_composite", "obfuscated_pipeline"): {
        "len_args": [1],
    },
    ("81_call_argument_identity", "two_decrements_one_scratch"): {
        "arg_values": {1: [0, 1, 7], 2: [0, 2, 9], 3: [1, 4, 32]},
        "extra_vectors": [[[5], 1, 2, 9]],
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
    # A 2D-ARRAY PARAMETER CANNOT BE SYNTHESISED BY THE HARNESS, so both of these
    # are `structural` in every lane and nothing executes behind them. They carried
    # no assertion at all until the DWARF extractor learned to describe array
    # members, at which point `gen_structural_baseline.py` correctly refused to
    # write a baseline that named them as gaps.
    # THE PAIR IS THE ASSERTION. Same fixture, same `const int32_t grid[R][C]`
    # parameter, same `int32_t` return, same bounds-check prologue -- and one has
    # both loop forms while the other has neither. A recovery that hallucinates a
    # loop over the row decay, or that flattens the nested loop away, breaks
    # exactly one side of the contrast.
    # `memory_store` is False on both deliberately: both functions only READ the
    # grid, so a recovery that turns an indexed load into a store is caught here
    # rather than surfacing later as an unexplained execution failure.
    # NOT asserted: `indirect_call`. It measures True for both despite neither
    # containing a call of any kind -- its first regex matches any `))(`, which
    # ordinary nested casts produce, and it fires on 31% of sampled corpus
    # functions. Asserting it here would record a tautology.
    ("108_multidimensional_arrays", "sum_true_2d"): {
        "for_loop": True,
        "head_tested_while": True,
        "memory_store": False,
        "nonempty": True,
    },
    ("108_multidimensional_arrays", "row_decay_span"): {
        "for_loop": False,
        "head_tested_while": False,
        "memory_store": False,
        "nonempty": True,
    },
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
    ("10_cpp_runtime_shapes", "cpp_exception"): {"nonempty": True},
    # Skipped for execution (see OVERRIDES): checked structurally instead.
    ("160_init_and_fini", "initfini_ready"): {"nonempty": True},
    ("160_init_and_fini", "initfini_order"): {"nonempty": True},
    ("160_init_and_fini", "initfini_table"): {"nonempty": True},
    ("160_init_and_fini", "initfini_fold"): {
        "nonempty": True,
        "for_loop": True,
    },  # EH body recovered
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
    "48_gray_code": [
        "binary_to_gray",
        "gray_to_binary",
        "reverse_bits32",
        "gray_sequence",
    ],
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
    "67_elastic_collision": [
        "elastic_velocity_a",
        "inelastic_velocity",
        "momentum_residual",
    ],
    "68_thermodynamics": ["ideal_gas_pressure", "newton_cooling", "mixing_temperature"],
    "69_molar_mass": ["molar_mass_centi"],
    "70_reaction_balance": ["balance_reaction"],
    "71_compound_interest": ["compound_balance", "annuity_future_value"],
    "72_loan_amortization": ["amortization_schedule", "remaining_balance"],
    "73_present_value": ["net_present_value", "internal_rate_of_return"],
    "74_moving_statistics": [
        "simple_moving_average",
        "exponential_moving_average",
        "population_variance",
    ],
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
    # --- ELF linking and dynamic-loading shapes ---
    # --- scale and complexity stress ---
    "151_wide_branch_ladder": [
        "big151_branch_ladder",
        "big151_flat_cascade",
    ],
    "152_deep_nesting": [
        "deep152_conditional_tower",
        "deep152_nested_loops",
        "deep152_while_tower",
    ],
    "153_many_live_locals": [
        "spill153_live_set",
        "spill153_static_web",
    ],
    "154_wide_switch": [
        "wide154_dense_effects",
        "wide154_dense_switch",
        "wide154_sparse_switch",
    ],
    "155_long_dependency_chain": [
        "chain155_buffered",
        "chain155_scalar",
        "chain155_signed",
    ],
    # --- packed and unaligned wire formats ---
    "161_packed_struct_layout": [
        "pk161_encode",
        "pk161_layout_delta",
        "pk161_member_offset",
        "pk161_read_field",
        "pk161_roundtrip",
    ],
    "162_unaligned_memcpy_access": [
        "ua162_load_be32",
        "ua162_load_native16",
        "ua162_load_native32",
        "ua162_move_field32",
        "ua162_roundtrip",
        "ua162_store_be32",
        "ua162_store_native32",
    ],
    "163_wire_header_parser": [
        "hdr163_build",
        "hdr163_copy_payload",
        "hdr163_payload_digest",
        "hdr163_stream_id",
        "hdr163_validate",
    ],
    "164_nested_tlv_walker": [
        "tlv164_encode_nested",
        "tlv164_find_type",
        "tlv164_leaf_sum",
        "tlv164_max_depth",
        "tlv164_node_count",
    ],
    "165_bitstream_reader": [
        "bit165_cross_check",
        "bit165_read_bits",
        "bit165_read_sequence",
        "bit165_roundtrip",
        "bit165_write_frame",
    ],
    "156_plt_and_got_calls": [
        "plt_call_interposable",
        "plt_call_local",
        "plt_call_via_address",
        "plt_fold_calls",
        "plt_paths_agree",
        "plt_step_public",
    ],
    "157_symbol_visibility": [
        "vis_call_both",
        "vis_fold_with_biases",
        "vis_public_helper",
        "vis_read_bias",
        "vis_set_biases",
    ],
    "158_weak_symbols": [
        "weak_absent_probe",
        "weak_defined_probe",
        "weak_dispatch",
        "weak_fold",
        "weak_scale",
    ],
    "159_ifunc_resolver": [
        "ifunc_call_double",
        "ifunc_fold",
        "ifunc_lazy_double",
        "ifunc_matches_reference",
        "ifunc_paths_agree",
    ],
    "160_init_and_fini": [
        "initfini_fold",
        "initfini_order",
        "initfini_ready",
        "initfini_table",
        "initfini_witness",
    ],
    # --- obfuscation and adversarial shapes ---
    "145_control_flow_flattening": [
        "flattened_accumulate",
        "flattened_classify",
        "flattened_gcd",
        "flattened_search",
    ],
    "146_opaque_predicates": [
        "opaque_always_true",
        "opaque_guarded_store",
        "opaque_loop_filter",
        "opaque_square_residue",
        "opaque_two_way_join",
        "opaque_volatile_select",
    ],
    "147_instruction_substitution": [
        "substituted_add",
        "substituted_bitops",
        "substituted_checksum",
        "substituted_multiply",
        "substituted_negate",
        "substituted_sub",
    ],
    "148_dispatch_obfuscation": [
        "chained_table_walk",
        "computed_index_dispatch",
        "obfuscated_dispatch",
        "permuted_switch",
    ],
    "149_mba_expressions": [
        "mba_add_identities",
        "mba_bit_population",
        "mba_mix_buffer",
        "mba_select",
        "mba_sub_identity",
        "mba_zero_polynomial",
    ],
    "150_obfuscation_composite": [
        "obfuscated_digest",
        "obfuscated_predicate_chain",
        "obfuscated_transform",
    ],
    # --- systems and ABI shapes ---
    "140_thread_local_storage": [
        "tls_address_is_stable",
        "tls_increment",
        "tls_indexed",
        "tls_versus_global",
    ],
    "141_atomics": [
        "atomic_compare_exchange_loop",
        "atomic_exchange_and_or",
        "atomic_flag_round_trip",
        "atomic_increment",
    ],
    "142_nonlocal_control": [
        "longjmp_unwinds_frames",
        "setjmp_returns_twice",
    ],
    "143_dynamic_frames": [
        "alloca_dynamic_frame",
        "alloca_in_loop",
        "cleanup_on_every_exit",
    ],
    "144_inline_asm": [
        "asm_add_via_constraints",
        "asm_memory_barrier",
        "builtin_bit_intrinsics",
        "builtin_overflow_checked",
    ],
    # --- C++ runtime shapes: vtables, RTTI, unwinding, templates ---
    "132_cpp_vtable_layout": [
        "cpp_vtable_area",
        "cpp_vtable_devirtualized",
        "cpp_vtable_inherited_slot",
    ],
    "133_cpp_multiple_inheritance": [
        "cpp_mi_cross_cast",
        "cpp_mi_dispatch",
        "cpp_mi_pointer_adjustment",
    ],
    "134_cpp_virtual_inheritance": [
        "cpp_virtual_base_is_shared",
        "cpp_virtual_base_offset",
        "cpp_virtual_final_overrider",
    ],
    "135_cpp_rtti": [
        "cpp_dynamic_cast_fails",
        "cpp_dynamic_cast_succeeds",
        "cpp_typeid_compare",
    ],
    "136_cpp_exception_unwinding": [
        "cpp_catch_by_type",
        "cpp_destructors_run_while_unwinding",
        "cpp_rethrow_and_nest",
    ],
    "137_cpp_templates": [
        "cpp_template_int16",
        "cpp_template_int32",
        "cpp_template_nontype",
        "cpp_template_predicate",
        "cpp_template_uint8",
    ],
    "138_cpp_operators": [
        "cpp_operator_arithmetic",
        "cpp_operator_compound",
        "cpp_operator_conversion",
    ],
    "139_cpp_object_lifetime": [
        "cpp_array_destruction",
        "cpp_destruction_order",
        "cpp_live_object_count",
    ],
    # --- C language edge cases, gotchas, and flexible constructs ---
    "100_struct_layout": [
        "layout_offsets",
        "layout_size_delta",
        "struct_assignment_copies",
    ],
    "101_static_locals": [
        "counter_next",
        "counter_reset",
        "static_table_lookup",
    ],
    "102_duffs_device": [
        "duff_copy",
    ],
    "103_computed_goto": [
        "threaded_interpreter",
    ],
    "104_statement_expression": [
        "single_evaluation",
        "statement_expression_max",
    ],
    "105_goto_ladder": [
        "acquire_and_release",
    ],
    "106_switch_shapes_dense_sparse": [
        "dense_switch",
        "hybrid_switch",
        "sparse_switch",
    ],
    "107_short_circuit": [
        "guarded_dereference",
        "short_circuit_and",
        "short_circuit_or",
    ],
    "108_multidimensional_arrays": [
        "row_decay_span",
        "sum_flat_with_stride",
        "sum_true_2d",
    ],
    "109_subscript_commutativity": [
        "mixed_subscript_sum",
        "negative_offset_from_interior",
        "reversed_subscript",
    ],
    "110_pointer_arithmetic": [
        "byte_versus_element_step",
        "element_distance",
        "walk_until_sentinel",
    ],
    "111_self_referential_struct": [
        "link_and_sum",
    ],
    "112_recursion_shapes": [
        "mutual_parity",
        "nontail_depth",
        "recursion_entry",
        "tail_countdown",
    ],
    "113_varargs": [
        "variadic_none",
        "variadic_three",
        "variadic_weighted_four",
    ],
    "114_volatile_access": [
        "nonvolatile_control",
        "volatile_loop_bound",
        "volatile_reads_are_not_merged",
        "volatile_store_then_load",
    ],
    "115_enum_semantics": [
        "enum_arithmetic",
        "enum_sizes",
        "enum_switch",
    ],
    "116_string_literals": [
        "count_matching",
        "escape_sequences",
        "literal_index",
        "literal_size_versus_length",
    ],
    "117_modular_arithmetic": [
        "absolute_without_branch",
        "maximum_plus_one",
        "modular_exponent_of_two",
        "signed_overflow_avoided",
        "wraps_to_zero",
    ],
    "118_bit_tricks": [
        "clear_lowest_set",
        "is_power_of_two",
        "isolate_lowest_set",
        "round_up_to_power_of_two",
        "sign_without_branch",
        "xor_swap",
    ],
    "119_branch_hints": [
        "hinted_validation",
        "unhinted_validation",
    ],
    "120_const_and_literals": [
        "const_array_of_pointers",
        "pointer_to_const_still_loads",
        "reads_foldable_constant",
    ],
    "121_dense_expression": [
        "chained_assignment",
        "conditional_lvalue_select",
        "dense_fold",
    ],
    "122_compound_assignment": [
        "mixed_compound_operators",
        "narrow_compound_truncates",
        "subscript_evaluated_once",
    ],
    "123_sizeof_semantics": [
        "sizeof_after_decay",
        "sizeof_array_versus_pointer",
        "sizeof_does_not_evaluate",
        "sizeof_probe_sets_flag",
        "sizeof_vla_is_evaluated",
    ],
    "124_loop_break_continue": [
        "break_binds_to_switch",
        "continue_in_do_while",
        "nested_loop_early_exit",
    ],
    "125_loop_shapes": [
        "decrementing_loop",
        "do_while_always_once",
        "infinite_with_internal_exit",
        "while_zero_trips",
    ],
    "126_x_macros": [
        "apply_opcode",
        "opcode_weight",
        "total_weight",
    ],
    "127_inline_linkage": [
        "inline_address_taken",
        "inline_in_loop",
        "inline_used_twice",
    ],
    "128_qualifier_combinations": [
        "const_pointer_writes",
        "pointer_to_const_walks",
        "volatile_const_is_readable",
    ],
    "129_struct_by_value": [
        "pass_large_by_value",
        "pass_small_by_value",
        "returns_small_struct_field",
    ],
    "130_bitpacked_codec": [
        "codec_roundtrip",
        "pack_fields",
        "unpack_field",
    ],
    "131_obfuscated_composite": [
        "nested_conditional_matrix",
        "obfuscated_pipeline",
    ],
    "82_comma_operator": [
        "comma_chain",
        "comma_in_condition",
        "comma_in_for",
    ],
    "83_ternary_chains": [
        "classify_ladder",
        "nested_ternary_assignment",
        "ternary_mixed_types",
    ],
    "84_compound_literals": [
        "compound_literal_argument",
        "compound_literal_array",
        "compound_literal_in_loop",
    ],
    "85_designated_initializers": [
        "designated_array_out_of_order",
        "designated_struct",
        "designated_sum",
    ],
    "86_flexible_array_member": [
        "flexible_header_size",
        "flexible_sum",
    ],
    "87_variable_length_array": [
        "vla_reverse_sum",
        "vla_two_dimensional",
    ],
    "88_restrict_pointers": [
        "aliasing_accumulate",
        "restrict_accumulate",
    ],
    "89_bool_semantics": [
        "bool_arithmetic",
        "bool_normalizes",
        "bool_roundtrip_mask",
    ],
    "90_bitfields": [
        "bitfield_extract",
        "bitfield_signed_range",
        "bitfield_struct_size",
    ],
    "91_union_type_punning": [
        "pun_byte_of_word",
        "pun_halves_swapped",
        "pun_is_little_endian",
    ],
    "92_anonymous_members": [
        "anonymous_overlap_proof",
        "anonymous_select",
    ],
    "93_generic_selection": [
        "generic_dispatch",
        "generic_tag_of_int16",
        "generic_tag_of_int32",
        "generic_tag_of_int64",
    ],
    "94_alignment": [
        "alignment_of_padded",
        "offset_of_payload",
        "padded_roundtrip",
        "size_difference",
    ],
    "95_function_pointer_table": [
        "dispatch_operation",
        "fold_operations",
    ],
    "96_integer_promotion": [
        "promote_narrow_product",
        "promote_then_truncate",
        "short_promotion_sign",
        "unsigned_conversion_rank",
    ],
    "97_signed_unsigned_pitfalls": [
        "division_truncates_toward_zero",
        "negative_compares_greater",
        "size_like_loop",
        "unsigned_subtraction_wraps",
    ],
    "98_shift_semantics": [
        "arithmetic_right_shift",
        "logical_right_shift",
        "masked_left_shift",
        "rotate_left",
        "shift_wider_than_operand",
    ],
    "99_char_and_endianness": [
        "byte_swap32",
        "char_widening",
        "load_big_endian",
        "plain_char_is_signed",
    ],
    "81_call_argument_identity": [
        "argument_sink",
        "two_decrements_one_scratch",
    ],
    # --- Rust runtime shapes (rustc lanes; see matrix_for) ---
    "166_rust_generics": [
        "rust_generic_dispatch",
        "rust_generic_fill",
        "rust_generic_i16",
        "rust_generic_i32",
        "rust_generic_i8",
        "rust_generic_max",
        "rust_generic_mixed",
    ],
    "167_rust_trait_objects": [
        "rust_dyn_apply",
        "rust_dyn_boxed",
        "rust_dyn_fill",
        "rust_dyn_pass_fat",
        "rust_dyn_pipeline",
        "rust_dyn_two_slots",
    ],
    "168_rust_enum_niche": [
        "rust_enum_by_value",
        "rust_enum_discriminant",
        "rust_enum_eval",
        "rust_niche_sizes",
        "rust_option_nested",
        "rust_option_niche_fill",
        "rust_option_nonzero",
        "rust_option_ref",
        "rust_option_ref_find",
    ],
    "169_rust_slices_bounds": [
        "rust_slice_chunks",
        "rust_slice_get",
        "rust_slice_get_range",
        "rust_slice_index",
        "rust_slice_index_pair",
        "rust_slice_iter_sum",
        "rust_slice_rev_enumerate",
        "rust_slice_reverse",
        "rust_slice_split_zip",
        "rust_slice_windows",
        "rust_slice_write",
    ],
    "170_rust_panic_unwind": [
        "rust_panic_assert",
        "rust_panic_bounds",
        "rust_panic_caught",
        "rust_panic_expect",
        "rust_panic_guarded_div",
        "rust_panic_multi",
        "rust_panic_unreachable",
        "rust_panic_unwrap",
    ],
    "171_rust_overflow": [
        "rust_cast_chain",
        "rust_checked_add",
        "rust_checked_div",
        "rust_checked_mul",
        "rust_checked_rem",
        "rust_checked_shift",
        "rust_overflow_matrix",
        "rust_overflowing_add",
        "rust_overflowing_mul",
        "rust_saturating_add",
        "rust_saturating_mul",
        "rust_saturating_sub",
        "rust_shift_family",
        "rust_u32_bits",
        "rust_u32_rotate",
        "rust_u32_sub_family",
        "rust_wrapping_add",
        "rust_wrapping_mul",
        "rust_wrapping_neg_abs",
        "rust_wrapping_sub",
    ],
    # --- IEEE floating point ---
    "172_float_double_widths": [
        "accumulate_narrow",
        "accumulate_wide",
        "double_precision_horner",
        "narrow_after_double_math",
        "single_precision_horner",
        "width_disagreement",
    ],
    "173_float_int_conversions": [
        "int32_round_trip_delta",
        "round_half_away_from_zero",
        "truncate_double_to_i64",
        "truncate_to_unsigned",
        "truncate_toward_zero",
        "widen_int_to_float",
        "widen_long_to_double",
    ],
    "174_float_compare_classify": [
        "absolute_binary32",
        "classify_binary32",
        "negate_binary32",
        "ordered_compare_binary32",
        "sign_bit_of_binary32",
        "unordered_compare_flags",
        "zero_sign_from_product",
    ],
    "175_float_matrix_kernel": [
        "dot_product_f32",
        "dot_product_f64",
        "matrix2_determinant",
        "matrix2_multiply",
        "scale_series_f32",
        "sum_of_squares_f32",
    ],
    # --- coverage-directed additions ------------------------------------
    # Each of these six exists because a specific instruction or transform in
    # the product had NO lane exercising it. The header comment in each source
    # file names the target; that is the reason the fixture is here, and the
    # reason to keep it even if it passes on the day it lands.
    "181_compensated_summation": [
        "compensation_of_step",
        "difference_of_products",
        "kahan_sum_f64",
        "naive_sum_f64",
        "summation_disagrees",
    ],
    "182_cold_and_part_splits": [
        "always_reaches_the_cold_chunk",
        "mix_with_outlinable_tail",
        "scan_with_two_cold_exits",
        "validate_with_cold_path",
    ],
    "183_sentinel_list_search": [
        "find_before_either_sentinel",
        "find_byte_before_nul",
        "find_by_key",
        "find_terminated_by_sentinel",
        "length_to_nul",
    ],
    "184_rep_stos_widths": [
        "fill_bytes_and_probe",
        "fill_dwords_and_probe",
        "fill_qwords_and_probe",
        "fill_then_patch_and_probe",
        "zero_fixed_block_and_probe",
    ],
    "185_subword_signed_division": [
        "divide_short_by_seven",
        "divide_signed_bytes",
        "divide_signed_shorts",
        "divide_unsigned_bytes",
        "divide_unsigned_shorts",
        "remainder_signed_bytes",
        "remainder_signed_shorts",
    ],
    "186_defaultless_guarded_switch": [
        "dense_no_default",
        "fallthrough_no_default",
        "loop_switch_no_default",
        "returning_arms_no_default",
        "sparse_no_default",
    ],
    # --- aggregate-recovery prerequisites --------------------------------
    # A constant bias folded into a subscript (`a[i + 3]`) is the shape the
    # affine-index analysis targets, and the corpus had no lane for it: 109
    # covers subscript spelling and an interior-pointer negative offset, not a
    # constant bias on the index. The last two functions are the controls that
    # make a recovered bias meaningful — one biases the loaded value instead of
    # the address, the other displaces the index by a runtime argument.
    "187_constant_bias_index": [
        "adjacent_difference",
        "bias_backward_pair",
        "bias_forward_sum",
        "value_bias_not_index",
        "variable_bias",
    ],
    # 128-bit transports in the shapes that reach src/ir/vector_copy.rs. That
    # pass had ONE lane (09_memory_effects:clang:O2) and nothing covering two
    # INTERLEAVED transports, which is the layout clang actually emits and the
    # one a fix passed its unit tests against while still failing on a real
    # binary. `vt188_lane_math` is the control: it transforms every element, so
    # it is lane computation and must not be rejoined into a copy.
    # A side-effecting call inside a diamond select. lazy_call_select and
    # copy_prop::move_adjacent_effectful_scratch_values fold a diamond into a
    # ternary, which is sound only if the folded call is evaluated exactly as
    # often as the machine evaluated it. A fold that hoists or duplicates the
    # call still yields the right RETURN VALUE, so only counting the effect
    # catches it — the same soundness class as 188's multi-consumer bug.
    # se189_select_pure is the control: no call in either arm, so folding is
    # correct there and must still happen, or the fixture would be satisfied by
    # a decompiler that never folds.
    # An indirect call through a relocation-proven function-pointer table. The
    # registers such a call may read are not knowable from the call site, but
    # the table's entries ARE a complete callee set, so they are the union over
    # it. Each entry writes the arguments it received into the caller's buffer:
    # `95_function_pointer_table` already covers the value the dispatch returns,
    # and a witness is what catches an argument list that is wrong in a way the
    # returned value hides — the reverted 2026-08-12 patch emitted exactly that.
    # `t191_computed_args` is the near-miss control (a recovery that names
    # architectural argument registers gets plausible, wrong values), and
    # `t191_direct_control` is the degeneracy control (the same protocol through
    # a direct call, which must keep passing).
    # A relocation-fixed `const char *const` table beside an integer table of
    # address-shaped values. The name functions are the positives (the table
    # holds references, and neither "leave the load alone" nor "read the bytes
    # as numbers" recompiles); the offset functions and `mc193_scaled_constant`
    # are the controls that must stay numeric.
    "193_mapped_constant_roles": [
        "mc193_name_bytes",
        "mc193_name_length",
        "mc193_names_differ",
        "mc193_offset_matches",
        "mc193_offset_sum",
        "mc193_scaled_constant",
    ],
    # A parameter-supplied, harness-relocated linked list walked by pointer
    # chase — the shape `dormant-transforms-2026-08-12.md` isolated as the single
    # trigger for `loop_form::recover_sentinel_search_loops` and recorded as
    # unbuildable at the time. `l192_find_key` is that probe verbatim;
    # `l192_chase_keys` and `l192_stamp_chain` put the visit ORDER and the visited
    # SET in caller-owned memory; `l192_sum_until_key` is order-dependent by
    # construction. `l192_scan_index_control` walks the same nodes by INDEX: it is
    # both the degeneracy control (the affine recovery must keep working) and the
    # near-miss (it is the answer a chase-to-stride confusion produces).
    "192_pointer_chased_list": [
        "l192_chase_keys",
        "l192_find_key",
        "l192_scan_index_control",
        "l192_stamp_chain",
        "l192_sum_until_key",
    ],
    "191_indirect_table_args": [
        "t191_computed_args",
        "t191_direct_control",
        "t191_dispatch",
        "t191_fold",
    ],
    # BY-VALUE AGGREGATES. Before this lane the corpus had none: zero fixtures
    # returned a struct by value, and RecoveredOutputKind::HiddenReturn was a
    # declared variant matched in three places and constructed in none. SysV
    # gives each size class a different contract — <=8 bytes integer in rax,
    # <=16 in rax:rdx, int+double SPLIT across rax and xmm0, and >16 bytes via a
    # hidden pointer that shifts every real argument one register right. A
    # decompiler that treats those uniformly still emits C that compiles.
    # Each caller witnesses the individual fields in a caller-owned buffer with
    # distinct coefficients, so the right total from the wrong fields is caught.
    # bv195_scalar_control is the control: an ordinary scalar return that must
    # NOT acquire aggregate handling, without which a decompiler routing
    # everything through the memory-class path would satisfy the rest.
    "195_by_value_aggregates": [
        "bv195_big_roundtrip",
        "bv195_mixed_roundtrip",
        "bv195_pair_roundtrip",
        "bv195_quad_roundtrip",
        "bv195_scalar_control",
    ],
    # ALL-FLOAT AGGREGATES. 195 covers SysV's INTEGER, INTEGER-pair, split-bank
    # and MEMORY classes but has no all-SSE case, so nothing in the corpus
    # returned a value in xmm0:xmm1 — TWO SSE registers holding ONE value, a
    # different contract from the split case and from a scalar double. The same
    # structs are a different mechanism entirely on AArch64, which had no lane at
    # all: AAPCS64 returns a homogeneous float aggregate in consecutive SIMD
    # registers, so {float,float,float,float} comes back in s0-s3 — FOUR
    # registers, one value — where SysV packs it into two xmms at two floats
    # apiece. Verified by disassembling both targets, not from memory.
    # The 12-byte trio leaves the second eightbyte HALF occupied, so a recovery
    # assuming a full pair reads a fourth member that was never stored.
    # hfa197_tagged_control is the negative that makes the positives mean
    # something: it contains a float but is not homogeneous, so BOTH ABIs return
    # it in an integer register. A decompiler routing "aggregate containing
    # floating point" to the SSE bank passes every positive and fails only here.
    # hfa197_scalar_control is the second negative: a plain double occupies one
    # result register and must not acquire a second.
    "197_homogeneous_float_aggregates": [
        "hfa197_pair2d_roundtrip",
        "hfa197_quad4f_roundtrip",
        "hfa197_scalar_control",
        "hfa197_tagged_control",
        "hfa197_trio3f_roundtrip",
    ],
    # RETURNS NARROWER THAN A REGISTER. A census of all 900 function definitions
    # in this corpus found 704 that return a 32-bit integer, 22 float/double, 14
    # 64-bit, TWO uint8_t, ONE uint16_t (not required) — and zero int8_t, zero
    # int16_t, zero char and zero _Bool. So the question "what happens when only
    # the low 8 or 16 bits of the result register are architecturally defined?"
    # was asked twice, never signed, and never for a normalised boolean.
    # Each positive narrows and THEN does arithmetic the narrowing changes, so
    # the low bits differ rather than only the dead high ones. Three controls:
    # nrw194_i32_control is the same expression at full width (a recovery that
    # narrows every return fails only there); nrw194_u8_value_control has a
    # narrow VALUE and a wide RETURN, separating the two notions; and
    # nrw194_bool_wide_control spells the boolean normalisation out by hand, so
    # a failure in nrw194_bool_and localises to the _Bool conversion.
    # nrw194_char_divide is deliberately ABI-dependent: `char` is signed on
    # x86/x86-64/i386 and unsigned on both ARM targets, so the AArch64 and ARMv7
    # lanes must decline it as `incomparable` rather than compare a truncation
    # against a zero-extension.
    "194_narrow_return_widths": [
        "nrw194_bool_and",
        "nrw194_bool_bit",
        "nrw194_bool_wide_control",
        "nrw194_char_divide",
        "nrw194_i16_divide",
        "nrw194_i32_control",
        "nrw194_i8_divide",
        "nrw194_u16_mix",
        "nrw194_u8_mix",
        "nrw194_u8_value_control",
    ],
    # THE AGGREGATE RETURN CLASSES 195 AND 197 LEAVE OUT. Between them every
    # aggregate the corpus returns is 8, 12, 16 or 32 bytes and fills its
    # registers exactly. Absent: a 4-byte struct (the LOW HALF of rax); a 3-byte
    # one (not a power of two); a 12-byte all-INTEGER one (rax:rdx with rdx half
    # used — 197 has the float half of that pair and not the integer half); a
    # union, of which the corpus returns none at all, and whose SysV class MERGE
    # sends {int64_t,double} back in rax rather than xmm0; an 8-byte struct
    # whose member is an ARRAY (which `describe_struct` declines, so the harness
    # must reach it through the wrapper); and a 20-byte MEMORY case that is not
    # a multiple of eight, where 195's is exactly 32.
    # agr198_make_i64 is the negative control AND the one directly executable
    # helper: eight bytes in rax that are NOT an aggregate, so a recovery
    # classifying by "eight bytes in the result register" fails exactly there.
    # agr198_scalar_control is the second negative — the same arithmetic and the
    # same buffer writes with no aggregate anywhere.
    "198_aggregate_return_edges": [
        "agr198_arr2_roundtrip",
        "agr198_bits_roundtrip",
        "agr198_bytes3_roundtrip",
        "agr198_five_roundtrip",
        "agr198_i64_control",
        "agr198_make_i64",
        "agr198_one_roundtrip",
        "agr198_scalar_control",
        "agr198_trio_roundtrip",
    ],
    # POINTER RETURNS. The census found exactly ONE in 900 definitions —
    # 192_pointer_chased_list:l192_find_key — and it fixes a single point on one
    # axis: an address recovered from a LOAD. This adds `void *` (a pointee with
    # no width in the source, given a synthetic u8 one by
    # `src/debug/dwarf_signatures.rs`), `const T *` (the same address with
    # `konst: true`, where dropping the qualifier still compiles), and an address
    # formed by pure ARITHMETIC rather than found by a scan, which is where a
    # pointer and an integer offset are hardest to tell apart.
    # Every one is executable only because the manifest names the caller-owned
    # buffer with `pointer_return_arg`; each returns NULL or an address strictly
    # inside its own `buf`, never one-past-the-end (which `_relative_pointer`
    # reports as `external@0x...` and which would differ between the builds for
    # reasons that say nothing about the decompiler).
    # ptr199_find_index is the first control: the same scan returning the INDEX,
    # which is the most plausible mis-recovery here and the one that would
    # otherwise be indistinguishable. ptr199_edge_element is the second: its
    # result depends on WHETHER the key occurs and never on WHERE, so a recovery
    # that lets the match position reach the returned address disagrees on every
    # vector whose match is in the interior.
    "199_pointer_return_kinds": [
        "ptr199_edge_element",
        "ptr199_find_const",
        "ptr199_find_i32",
        "ptr199_find_index",
        "ptr199_find_void",
        "ptr199_offset",
    ],
    # A FLOATING VALUE STORED THROUGH INTEGER-TYPED STORAGE. The destination
    # type on a store comes from the ACCESS WIDTH, so a four-byte `movss` was
    # recovered as `*(int *)(p) = (float)(...)` — C's arithmetic conversion,
    # which wrote 1 for 1.5f where the machine wrote 0x3FC00000.
    # A census of the whole corpus found 33 such statements in 12 functions
    # (`195`, `197`, `198`, plus `172`, `174`, `175`, `181`), and NOT ONE of
    # them was directly executed: the aggregate-returning ones are recorded
    # `structural` because `exec_class` refuses their return, `174`'s
    # `fp174_float_bits` is a local symbol with no baseline row, and the rest
    # were already `fail` for unrelated reasons. So the defect had no lane that
    # could report it. Every function here is scalar-argument and
    # `int32_t`-returning, so every one of them is executed.
    # THE NEGATIVE CONTROLS ARE THE POINT, because `movss` and `cvttss2si` are
    # one instruction apart and only one of them is a reinterpretation.
    # f201_f32_slot_values and f201_f64_copy_then_convert do the same arithmetic
    # on the same values and TRUNCATE, so a recovery that satisfies the
    # positives by simply never converting fails exactly there; the second also
    # puts a bit copy and a conversion in ONE function, so deciding per-object
    # rather than per-access is wrong whichever way it decides.
    # f201_scalar_control has no floating point at all, separating a recovery
    # that damaged ordinary integer stores from one that did not.
    "201_float_bit_stores": [
        "f201_f32_single_bits",
        "f201_f32_slot_bits",
        "f201_f32_slot_values",
        "f201_f64_copy_then_convert",
        "f201_f64_slot_bits",
        "f201_scalar_control",
        "f201_store_through_pointer",
        "f201_word_to_value",
    ],
    # A pending load held across a store to a DISJOINT slot of the same frame
    # object. `dfs196_spill_web` is the positive; the three controls are stores
    # the disjointness test must refuse to see through — an aliasing pointer, a
    # runtime index, and a constant-offset overlap.
    "196_disjoint_frame_slots": [
        "dfs196_alias_control",
        "dfs196_indexed_control",
        "dfs196_overlap_control",
        "dfs196_spill_web",
    ],
    # ONE machine operation, TWO logically distinct outputs. x86-64 `div` writes
    # the quotient to rax and the remainder to rdx; AArch64 spells the same
    # dependency as `udiv` + `msub`. If value_split/call_result_split alias the
    # pair, the recovered C still compiles and still looks reasonable — it just
    # uses one value where the machine used two — so each function keeps both in
    # a caller-owned buffer and combines them with DISTINCT coefficients, where
    # a plain sum would hide a swap. Division rather than __int128 keeps i386
    # and armv7 in play; the __int128 functions in 02_integer_widths force those
    # lanes to declare the whole fixture unsupported.
    # dp190_quotient_only is the control: there the remainder IS dead and must
    # still be eliminated, so keeping every architectural output alive is not a
    # way to pass this fixture.
    "190_dual_role_products": [
        "dp190_div_and_rem",
        "dp190_mul_both_halves",
        "dp190_pair_across_join",
        "dp190_quotient_only",
        "dp190_sdiv_and_rem",
    ],
    "189_effectful_select": [
        "se189_bump",
        "se189_nested_select",
        "se189_select_call",
        "se189_select_one_arm",
        "se189_select_pure",
    ],
    "188_vector_transport": [
        "vt188_copy_backward",
        "vt188_copy_forward",
        "vt188_copy_two_streams",
        "vt188_lane_math",
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
        # .rs sources are declared in REQUIRED_FUNCTIONS but only enter the
        # matrix when GLAURUNG_FIXTURE_RUST=1 (see fixture_harness.
        # rust_lanes_enabled): rustc is not in the pinned toolchain image yet.
        for p in sorted(FIXTURE_SRC.glob("*.c"))
        + sorted(FIXTURE_SRC.glob("*.cpp"))
        + sorted(FIXTURE_SRC.glob("*.rs"))
    }
    declared = set(REQUIRED_FUNCTIONS)
    if on_disk != declared:
        raise AssertionError(
            "fixture sources and the manifest disagree: "
            f"only on disk {sorted(on_disk - declared)}, "
            f"only declared {sorted(declared - on_disk)}"
        )
