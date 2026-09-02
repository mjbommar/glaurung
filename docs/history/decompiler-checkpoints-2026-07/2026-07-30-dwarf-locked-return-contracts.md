# DWARF-locked return contracts checkpoint

> **Kind:** record · **Date:** 2026-07-30

Date: 2026-07-30

Source checkpoint: `7abdc828456d07ce09da7f429790fa6e1b3c1508`

## Verdict

Glaurung now preserves an authoritative DWARF function return contract across
machine-code output recovery and later type refinement. This restores the GCC
and Clang `-O2` behavioral lanes for `cpp_raii_guard` without weakening the
conservative result inference used for stripped binaries.

This is a real correctness gain for binaries with debug prototypes. It is not a
DecBench score gain: the blinded sample contains no applicable DWARF function
contracts, and a clean rebuild of the previous source checkpoint produces the
same blinded C payloads as this change.

## Root cause and policy

The optimized source shape computes a value, stores it through a pointer, and
returns the same value. Its machine code is observationally ambiguous with a
`void` function that performs only the store: both can leave the computed value
in the ABI return register at `RET`.

Glaurung's output-trial recovery correctly rejected that shared value as a
dedicated machine-code result. The defect was the next decision: it concluded
`Void` even when the binary's DWARF subprogram declared an `int` result.

The corrected boundary is:

1. machine-code output trials remain authoritative when no declaration exists;
2. a resolved DWARF `DW_AT_type` locks a direct output and its representable
   scalar type;
3. absence of `DW_AT_type` on a concrete subprogram locks `void`;
4. an unsupported type reference stays unknown and does not overwrite inferred
   facts;
5. locked facts carry provenance in the type map, so later width, pointer, and
   signedness refinements cannot silently replace them.

This matches the reference policy inspected locally. Ghidra's
`ActionReturnRecovery` and Kuna's port use an only-use test for machine output
trials, while Ghidra's locked `FuncProto` remains authoritative. Angr similarly
preserves an existing function prototype rather than replacing it with a later
decompiler guess.

## Real round trip

The RED test compiles a real GCC ELF with `-g -O2` containing two functions:

```c
int store_and_return(int *out, int value) {
    int result = value + 700;
    *out = result;
    return result;
}

void store_only(int *out, int value) {
    *out = value + 700;
}
```

Before the change, the first function was emitted as:

```c
void store_and_return(int * arg0, long arg1) {
    *(int *)(((long)arg0)) = (arg1 + 700);
    return;
}
```

After the change, the declared result survives through the complete native
pipeline:

```c
int store_and_return(int * arg0, long arg1) {
    int ret;
    ret = (arg1 + 700);
    *(int *)(((long)arg0)) = ret;
    return ret;
}
```

The companion remains `void store_only(...)`. Both generated functions are
recompiled together with the pinned GCC under `-std=gnu11 -Werror`. The test
uses one batch decompilation of the binary; this reduced its wall clock from
about 29 seconds to 1.6 seconds.

The existing C++ behavioral witness also returns to baseline:

- `10_cpp_runtime_shapes:clang:O2:cpp_raii_guard`: pass;
- `10_cpp_runtime_shapes:gcc:O2:cpp_raii_guard`: pass.

## Blinded DecBench audit

The 224 blinded binaries were statically analyzed only. They were never
executed, emulated, or made executable. A 16-worker extraction emitted all
250/250 requested functions across 224/224 binaries with zero adapter errors;
the slowest individual analysis was 6.17 seconds.

The immutable artifact is
`glaurung-results-7abdc82.zip`, with SHA-256
`54ae5b6098c9afbf0e3a52a49404fe5632551ce205ff2a774af29f4564d206da`.
Its metadata names the full source object above.

Its C payloads are byte-for-byte identical to a clean isolated rebuild of the
previous source checkpoint `7bee103`. Therefore this patch has zero blinded
output delta.

The older retained archive `glaurung-results-7bee103.zip` is not reproducible
from that labeled source object in the current pinned environment. It differs
in five stripped ARM files (`bin_083.c`, `bin_101.c`, `bin_111.c`,
`bin_145.c`, and `bin_172.c`) only by explicit narrow store casts. Repeating
the current run is stable, and rebuilding `7bee103` independently produces the
same payloads as the new artifact. The audit establishes the mismatch but does
not guess whether its cause was a stale native build, a different toolchain, or
another unretained environment difference.

Because the reproducible artifact differs from the previously scored archive,
the prior 127/250 compile count is not relabeled as a current measurement. The
official DecBench evaluator was unavailable locally for this checkpoint; GED,
byte match, type match, and official compile/fixup scores remain unrefreshed.

## Gates

- Rust library tests: 1,284 passed, zero failed.
- Real compiled fixture/harness file: 36 passed, zero failed.
- Full behavioral differential: 56/56 lanes, no baseline regressions.
- Focused optimized declared-output round trip: passed.
- `cargo fmt --check`: passed.
- Clippy with all targets and the `pyo3` feature: exit 0 with the existing
  warning backlog.
- Ruff on the owned Python test file: passed.
- `ty` on that file remains red on its pre-existing dynamic test-module imports
  and pytest stub limitations; no new owned diagnostic was identified.

## Submission decision

Do not submit yet. This closes one prototype-authority defect and removes two
real behavioral regressions, but it does not close the retained GED, structured
variable, full prototype, and stripped type-recovery gaps against Ghidra and
angr. The next submission-grade checkpoint needs a reproducible current
artifact and fresh official scores rather than inherited numbers.
