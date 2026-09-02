# Stripped ELF tail-call boundaries

> **Kind:** record · **Date:** 2026-07-30

Date: 2026-07-30

Source checkpoint: `bd2d13ce4695a9311477746aa8bc3abe0d40cf58`

## Verdict

Glaurung now preserves a precise class of x86/x86-64 sibling-call boundaries
after ELF symbols have been stripped. A direct terminal jump is treated as a
tail call only when its executable target starts with the architecture-matching
CET landing pad followed by independent function-entry evidence. The exact
callee address is retained through bounded discovery, materialized as an LLIR
`Call` plus `Return` before SSA, and rendered with a deterministic anonymous
`sub_<va>` name when no stronger symbol is available.

This repairs a real DecBench function from an almost completely wrong
2,362-byte over-read to a four-instruction round trip. It is a meaningful
control-flow and interprocedural data-flow gain, not evidence that Glaurung is
already competitive with Ghidra, angr, or Kuna across the whole corpus.

## Root cause and proof boundary

The blinded `O2::libedit::libedit.so.0.0::em_inc_search_prev` target is a
25-byte wrapper:

```asm
f110: endbr64
f114: movq $0, 0x4a0(%rdi)
f11f: mov  $0x18, %esi
f124: jmp  0x15380
```

The prior CFG treated the final jump as a local successor and absorbed the
callee. That destroyed the wrapper's function boundary and let the downstream
pipeline structure thousands of unrelated bytes as one function.

The accepted proof is deliberately narrower than “a long jump probably starts
a function”:

1. the container must be ELF and the architecture x86 or x86-64;
2. the jump must be unconditional, direct, executable, and non-self;
3. the target must begin with matching `ENDBR32` or `ENDBR64`;
4. the bytes immediately after the landing pad must match a recognized
   prologue or a SysV low callee-saved-register push;
5. the target must not be one of the lifted function's local block starts.

The discovered xref is retained in `Function::callees`. The LLIR lift converts
only a successor-free terminal jump to one of those proven nonlocal targets.
This occurs before ABI annotation, SSA, and value numbering so the argument
register writes stay live.

## Argument-forwarding correction

The wrapper forwards its incoming `rdi` while defining the later `rsi` slot.
The first implementation recovered that prefix globally and the full-corpus
audit found two false forwards:

- `__ctype_b_loc()` acquired a stale argument after an earlier call; and
- ARM `IOInit` received the function's incoming `arg0` instead of the result
  currently held in `r0`.

The retained rule therefore requires both:

- the call is last in the current structured body or immediately followed by
  `return`; and
- no prior call was crossed while searching for the missing prefix, because
  ABI argument registers are caller-clobbered.

Positive tests retain a proven SysV tail forward and an untouched Win64
last-call forward. Negative tests cover a prior-call clobber and a nonterminal
structured-body call.

## Actual recovered output and round trip

The stripped binary now decompiles to:

```c
long sub_f110(long *arg0) {
    extern long sub_15380(long *, int);
    long ret;
    *(long *)((long)arg0 + 0x4a0) = 0;
    ret = sub_15380(arg0, 24);
    return ret;
}
```

The official `ByteMatchMetric` recompilation result is `1.0`: 25 original
bytes, 25 recompiled bytes, four assembly instructions on each side, zero
changed lines. On this exact sample the retained competitor results are Ghidra
`0.8`, Kuna `0.8`, and angr `0.6`.

## Full blinded DecBench evidence

The blinded binaries were statically analyzed only. They were never executed,
emulated, or made executable.

| metric | `6175a19` | `bd2d13c` proof |
|---|---:|---:|
| functions | 250 | 250 |
| compilable | 250 | 250 |
| mean byte match | 0.162065242 | 0.184211918 |
| gains | - | 115 |
| unchanged | - | 128 |
| losses | - | 7 |

The mean rises by `0.022146676` absolute, or 13.66% relative. Every loss was
inspected against both C artifacts and the original instructions. After the
two false-forward fixes, all seven remaining decreases are call-spelling/code
generation fluctuations from replacing a raw numeric address cast with an
explicit anonymous direct-call declaration; none changes the argument list or
control-flow semantics. Two of those seven improve edit distance even though
the instruction-set overlap score falls.

The archive-wide diff also exposed intended secondary improvements: proven
terminal transfers now become small direct tail calls instead of labels or
absorbed callees, and equivalent stack-canary guards are rendered in the
failure-first form.

Immutable artifact:

- path:
  `/home/mjbommar/projects/personal/decbench-evalkit-sample-set/glaurung-results-bd2d13c.zip`;
- SHA-256:
  `7e36fd14a0199f2c5cfedca49a6811410b1c677eab5258a95c32785f286efe76`;
- coverage: 224/224 binaries and 250/250 functions;
- embedded version: `bd2d13c`.

The commit-stamped archive's 224 C payloads are byte-for-byte identical to the
scored proof archive; only the submission metadata version changed.

## Gates and wall-clock workflow

- Rust library: 1,306 passed, zero failed.
- Real stripped-ELF compile/decompile/recompile fixture: passed with GCC
  `-Werror`.
- Focused structural fixture lane: 15 passed, zero failed.
- CLI and fixture-toolchain lane: passed.
- Release extension build: passed with the repository's 19-warning baseline.
- Clippy: exit 0 with the repository's existing warning backlog.
- Ruff on the owned Python fixture: passed.
- `cargo fmt --check` and `git diff --check`: passed.

The repository-wide Python suite was also run with the locked environment. It
is not green: 32 tests fail across the existing broad-suite backlog, including
LLM configuration/API drift, Windows analysis and mock contracts, stale output
expectations, and one unresolved conditional cold-switch fixture. None of
those failures is counted as a passing gate for this slice. The focused
stripped-ELF fixture and its Rust unit coverage are green, but the repository
as a whole still requires that backlog to be repaired before a full-green
claim.

The evaluation loop now uses one compiled canary per edit, a release rebuild
only after the canary is green, and parallel independent gates. Corpus
extraction was raised from the four-worker default to 12 workers and then 20
workers on the 24-core host. The final 20-worker extraction completed all 224
binaries in under a minute; byte-match recompilation completed in roughly one
second. The remaining expensive evaluator ingest is single-core and takes
roughly 90 seconds, so it is overlapped with tests and lint.
