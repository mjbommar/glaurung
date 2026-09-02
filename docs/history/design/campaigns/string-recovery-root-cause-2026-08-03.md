# String recovery and resolved-callee root-cause pass

> **Kind:** record · **Date:** 2026-08-11

**Date:** 2026-08-03  
**Scope:** extbench Tier A string literals and resolved callees, with x86-64 as
the control architecture. This is a diagnosis, not an implementation plan
disguised as a fix. No string-recovery code was changed during this pass.

## Verdict

The recorded `1.10 vs 3.79` string result was not a per-function rate. The
report averaged each binary's per-function mean and then gave all binaries equal
weight. On the same retained output, a true function-weighted aggregation is:

| Tier A metric | Glaurung | Ghidra | RetDec |
|---|---:|---:|---:|
| strings/function, all architectures (93/75/87 produced functions) | 0.495 | 1.147 | 1.241 |
| strings/function, x86-64 (31/28/28) | 0.839 | 1.500 | 1.679 |
| strings/function, AArch64 (31/28/28) | 0.645 | 1.536 | 1.107 |
| strings/function, ARMv7 (31/19/31) | 0.000 | 0.053 | 0.968 |
| resolved callees/function, x86-64 | 3.774 | 3.893 | 4.286 |
| resolved callees/function, AArch64 | 3.516 | 3.893 | 3.893 |
| resolved callees/function, ARMv7 | 1.290 | 4.053 | 2.677 |

The string deficit is real, but its measured size and composition are different
from the headline. On x86-64 it is mostly an explicit short-string policy plus
a repeatable SSA/call-argument join failure. It is not primarily missing string
bytes or missing xrefs. Resolved-callee recovery is already near Ghidra on
x86-64, so the two metrics do not share one general x86 data/xref cause; the
remaining callee-name deficit is concentrated on ARMv7.

The ARMv7 RetDec number also needs caution. Its emitted literals include
`"hf.so.1"` suffixes from the dynamic-loader name in unrelated functions.
Extbench counts rendered literals, not correctness, and stripped ARMv7 cannot
be checked by the call probe because mapping-symbol removal makes the reference
disassembly unreliable.

## End-to-end recovery path

The current path is:

1. `collect_string_pool` scans rodata-like sections and indexes printable runs
   and suffixes of at least three characters.
2. lifting represents a reference as `Expr::Addr`, an address expression, or a
   plain constant after propagation/folding.
3. `run_ast_passes` performs expression reconstruction and `fold_constants`,
   then name resolution, tail-call and argument reconstruction, call contracts,
   and only then `fold_string_literals`.
4. string folding replaces `Addr`/`Named` expressions everywhere, but replaces
   a plain `Const` only in a direct call parameter known to be a character
   pointer.
5. extbench counts rendered quoted literals in the produced function body.

There are three distinct refusal/loss boundaries.

## Root cause A: the three-character floor explains 10/16 x86 misses

Across functions produced by both tools, Ghidra has 16 literal occurrences not
present in Glaurung. Ten are shorter than `MIN_STRING_LEN == 3`:

| literal | missed occurrences |
|---|---:|
| empty string | 5 |
| `"a"` | 1 |
| `":"` | 1 |
| `"%d"` | 1 |
| `"-"` | 1 |
| `"rb"` | 1 |

This is policy, not extraction failure. The floor prevents arbitrary small
integers from becoming strings, but it is too coarse when the use already has
strong `char *` evidence. Any change must remain context-sensitive: indexing
every NUL byte or every printable byte globally would manufacture literals.

Required RED cases before changing the policy:

- a known `const char *` call parameter recovers `""`, `"a"`, `"%d"`, and
  `"rb"` from exact rodata addresses;
- the same numeric addresses in integer arithmetic and non-pointer parameters
  do not become strings;
- merged suffix recovery remains pinned.

## Root cause B: shared-tail argument setup explains all six long x86 misses

The six missing literals of length at least three are:

- `getconf:main`: `"%s: unknown variable"` and
  `"%s: invalid variable type"`;
- `getconf:print_confstr`: `"Can't allocate %zu bytes"`;
- `iconv:main`: destination/source charset diagnostics and
  `"iconv: write error"`.

All six exist in rodata and have direct RIP-relative `lea` references in the
correct function. They are lost after lifting:

- `getconf:main` sets different `rsi`/`rdx` values in blocks at `0x2289` and
  `0x22a3`, then joins at the `errx` call at `0x22ad`. Generated C reaches the
  join without either predecessor's assignments.
- `getconf:print_confstr` sets `rsi` to the allocation error at `0x256b`; a
  different predecessor sets `rsi` to `"confstr(%ld)"` at `0x25d2`; both join
  at `err` at `0x25d9`. Generated C renders only the latter value rather than a
  control-dependent value.
- `iconv:main` chooses between two format pointers at `0x1215`/`0x1224` before
  the shared `fprintf` at `0x122d`. Generated C renders `fprintf()` without any
  recovered arguments. The write-error address at `0x145a` jumps to the shared
  `perror` block at `0x1239` and is lost the same way.

This boundary is upstream of string folding. Adding more string patterns cannot
recover an argument expression that no longer reaches the call. It overlaps the
phi-copy/coalescing work: the required fix is value-preserving SSA/phi handling
through predecessor-specific ABI assignments and shared call blocks.

Required RED fixture shape:

```c
const char *fmt;
if (condition) {
    fmt = "first diagnostic %s";
    value = left;
} else {
    fmt = "second diagnostic %s";
    value = right;
}
fprintf(stderr, fmt, value);
```

Acceptance is behavioral round-trip plus both literals and the correct
control-dependent argument in rendered C. A GED/string-count improvement alone
is insufficient.

## Root cause C: address provenance is erased before AArch64 string folding

The AArch64 lifter produces page-plus-offset address expressions, but
`run_ast_passes` invokes `fold_constants` before `fold_string_literals`.
Consequently many `Addr(page) + Const(offset)` values become plain constants
before the string pass sees them. The comment in `strings_fold.rs` says the
string pass runs before the algebraic folder; the live pipeline is the reverse.

Examples in retained output include option-string and literal addresses emitted
as assignments such as `var7 = 0x11d9`. Plain constants are folded only when
they appear directly in a call parameter whose contract proves `char *`;
constants assigned to a variable, transported through a phi, or passed to an
unrecovered call stay numeric. Shared-tail argument loss from root cause B then
removes additional AArch64 literals.

Do not fix this by universally interpreting in-range constants as pointers.
The durable boundary is typed address provenance: folding arithmetic must retain
that a value is an address in a data address space. A narrowly tested pass-order
change may be useful as an experiment, but is not by itself the architectural
acceptance criterion.

## Resolved callee names are not the same x86 root cause

Corrected x86-64 resolved-callee density is 3.774 versus Ghidra's 3.893. That
small residual does not track the x86 string misses above. AArch64 is also close
(3.516 versus 3.893). The large aggregate name deficit is ARMv7 (1.290 versus
4.053), where the descriptive metric and the reference-disassembly limitations
need a separate PLT/call-target census before any code change.

The valid shared boundary is narrower: losing an argument or address value at a
join can hide a string and can also prevent a call target from resolving. The
current evidence does not support treating all string and callee-name misses as
one data/xref reconstruction defect.

## Measurement fixes completed first

The harness now:

- micro-averages function metrics and prints denominators while retaining a
  per-binary mean for timing;
- disables ambient debuginfod network access;
- uses GNU architecture-matched objdump so stripped PLT names remain visible;
- resolves x86 indirect GOT calls from dynamic relocations;
- uses the same address-deduped even-stride target sample for whole-image tools;
- refuses an empty score instead of printing a clean-looking zero table.

On the retained corpus, Tier B call checking now completes in about 1.2 seconds
instead of hanging. Its current result is Glaurung 63% imported-callee recall
with 0/263 functions containing an invented import call. This is separate from
the descriptive `resolved callees/function` metric.

## Ordered next step and stop conditions

1. Land the instrument fixes independently and regenerate the benchmark report.
2. Add the shared-tail/phi RED fixture and diagnose the first IR stage that
   loses each predecessor's call arguments. Do not change string folding yet.
3. Add address-provenance RED cases on x86-64 and AArch64, with integer
   near-miss controls.
4. Add context-sensitive short-string RED cases with non-pointer controls.
5. Only then implement the smallest semantic fix and rerun focused behavioral
   gates, the architecture round-trip gate, Tier A, and Tier B call checking.

Stop if a change improves literal count while changing call arguments,
introducing arbitrary integer-to-string conversions, breaking any architecture
round-trip cell, or reducing imported-callee correctness. Do not credit a
rerender made with a stale Python extension.

---

# Implementation pass — 2026-08-04

The three root causes above were re-verified against the running pipeline before
any code changed. Two held, one did not, and a fourth cause was found that the
diagnosis had missed.

## Root cause C as written is wrong

The doc says `fold_constants` runs before `fold_string_literals` and therefore
"erases address provenance", leaving plain constants. Instrumenting the pass
pipeline on `strip_getconf_arm64:main` shows it does not:

```
after apply_known_call_contracts (i.e. immediately before the string pass)
  call setlocale@plt(..., (0x1000 + 3234));
  call getopt@plt(..., %x22#2);
```

and the actual AST node is

```
args=[..., Bin { op: Add, lhs: Addr(4096), rhs: Const(3234) }]
```

The `Addr` survives intact. Nothing was erased. **The renderer prints `Addr(v)`
and `Const(v)` identically**, as a bare hex number, which is why reading a pass
dump made it look like provenance had been lost.

The real blocker was in `fold_constant_string`, the only path permitted to fold a
value that is not already an `Addr`/`Named`: it matched `Expr::Const` and nothing
else, so it bailed on both AArch64 shapes — the unfolded `adrp`+`add` sum, and a
name defined by one. It never reached the length floor.

## Root cause A holds, and is not x86-only

`setlocale(LC_ALL, "")` on **AArch64** passes address `0x1ca2`, which is the NUL
terminator of the run at `0x1c9c` — the empty string, below the 3-character
floor. `getopt(argc, argv, "a")` passes a 1-character literal. Both are genuine
literals discarded by a policy meant to stop arbitrary integers from becoming
strings.

The floor is a statement about **confidence in an address**, not about the bytes,
so it moved from pool construction to the point of use:

* a bare `Addr`/`Named` still requires `MIN_STRING_LEN` — otherwise any integer
  pointing at a NUL byte would render as `""`;
* a call argument whose **callee prototype proves the parameter is `char *`** may
  go below it, because the type is authoritative.

## The fourth cause: the prototype catalogue was too small

The contract-gated path can only fire where a prototype proves `char *`. The
catalogue held 96 entries and was missing `getopt` and the **entire BSD `err.h`
family** — which is how `getconf`, `getent` and `iconv` all report errors. So for
those calls there was nothing to gate on. 18 prototypes added (`getopt`,
`getopt_long`, `err`, `errx`, `warn`, `warnx`, `dlopen`, `dlsym`, `openlog`,
`syslog`, `asprintf`, `fnmatch`, `regcomp`, `execlp`, `execvp`, `unsetenv`,
`textdomain`, `bindtextdomain`). A guard test — every contract must have a
self-contained C spelling — rejected `char * const *`, `const struct option *`
and `regex_t *`; those were retyped to renderable equivalents.

## Root cause B confirmed, with a concrete instance

`getopt`'s optstring on AArch64 still does not fold, and **should not**. The name
carrying it is assigned three times:

```
%x22#1 = 0x1000;
%x22#2 = (%x22#1 + 3313);      <- the "a" optstring
%x22#2 = *(u64)&[%x20#1+%x1#4];
%x22#2 = 0;
```

Phi coalescing merged three unrelated values into one name, so the constant no
longer reaches the call as a distinguishable value. The single-assignment guard
refuses it. On **x86-64** the same source line folds correctly, because there the
name is genuinely single-assignment. This is root cause B — the value model — and
it is not fixable in the string layer.

## Measured effect

Tier A, function-weighted, restricted to ground-truth targets:

| | before campaign | before this pass | after | Ghidra | angr | RetDec |
|---|---:|---:|---:|---:|---:|---:|
| all architectures | 0.269 | 0.570 | **0.774** | 1.147 | 1.471 | 1.241 |
| x86-64 | 0.806 | 0.839 | **1.000** | 1.500 | 1.667 | 1.679 |
| AArch64 | 0.000 | 0.677 | **0.903** | 1.536 | 1.429 | 1.107 |
| ARMv7 | 0.000 | 0.194 | **0.419** | 0.053 | 1.310 | 0.968 |

The gap to Ghidra narrows from 2.01x to **1.48x**. Tier B (real distro binaries,
263 sampled targets) moves `1.441 -> 1.532`, against angr's 1.595 and Ghidra's
1.829.

Every newly recovered literal was checked to be real: `""` from
`setlocale(LC_ALL, "")`, `"a"` from `getopt`, `"undefined"` via the new `errx`
contract. Three stripped binaries across three architectures were checked for
spurious empty-string literals in untyped positions: **zero**.

## Formats

PE is covered at the pool level and now has a regression test: a PE `.rdata`
section is described by an RVA, and a pool keyed on RVAs would miss every Windows
string. The pool keys on image-based VAs (verified against a real PE based at
`0x140000000`). Folding after that point is format-independent. Mach-O
`__cstring` / `__TEXT,__cstring` match the same section filter.

## Gates

`cargo test --lib` 1,735 passed; `fixture_harness` 656 pass / 0 fail;
`arch_roundtrip --check` matches the baseline exactly with the control lane at
328/328 — string folding changes rendering, not behaviour, and the differential
confirms it.
