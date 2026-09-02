# Named-callee prototype recovery checkpoint

> **Kind:** record · **Date:** 2026-07-30

Date: 2026-07-30

Source checkpoint: `7a1f3bb41822f9f8085ff0d772a856a5d0d1c23d`

## Verdict

Glaurung now emits a concrete C prototype for a resolved named callee when a
function is rendered as a standalone translation unit. On the blinded DecBench
sample, the official fixup/recompile path rises from **127/250 to 162/250**
compilable functions: **35 gains, zero compile losses, and zero byte-match
losses** under one fixed evaluator environment.

This closes the largest measured compilation failure class and is also a real
C front-end correctness improvement. It does not make Glaurung competitive
with Ghidra, angr, or Kuna overall. The remaining 88 compilation failures and
the behavioral/structural quality gaps still require a shared interprocedural
prototype and typed-value layer.

## Root cause

The middle layer already represented a resolved direct call as
`Expr::Named`, retained its arguments, and retained whether the result was used.
The standalone C renderer nevertheless emitted only the call expression:

```c
var1 = project_transform(arg0);
```

No declaration for `project_transform` accompanied it. DecBench's fairness
fixup could inject a last-resort `long project_transform();`, but the current
compiler treats that as a zero-parameter declaration and rejects calls with
arguments. The exact baseline failure census was:

- 42/123 remaining failures: too many arguments to a synthesized zero-argument
  function declaration;
- 22/123: invalid use of a void expression;
- 16/123: pointer-to-integer assignment;
- 14/123: scalar return from a pointer-returning function.

Those four classes accounted for 94 of the 123 failures.

## Reference architecture

All three reference decompilers attach prototypes to semantic call objects
before printing them:

- Ghidra stores per-call `FuncCallSpecs`, applies default/library parameters,
  and prints inputs and outputs from `FuncProto` rather than inferring a textual
  declaration at the end.
- angr's `CallSiteMaker` chooses, in order, a manually supplied call-site
  prototype, the known target function's prototype, or an automatically
  recovered call-site prototype. It then derives argument locations from the
  calling convention and handles variadic tails explicitly.
- Kuna ports the Ghidra `FuncCallSpecs`/`FuncProto` design, seeds known library
  declarations during analysis, carries per-callee prototypes in the
  decompiler context, and renders those prototypes in its C printer.

This Glaurung slice establishes the same minimum invariant at the existing AST
boundary. It gathers typed observations from every structured statement that
contains a named call. Consistent observations produce a fixed prototype;
mixed arities produce only a proven common prefix plus `...`; conflicting
return types or a missing common parameter prefix fail closed. Known library
calls remain under the authoritative library-contract boundary rather than
being overwritten by call-site guesses.

The declarations are block-scoped. That keeps each standalone function valid
C11/C23 without placing an unrelated declaration before the function signature
that DecBench's context parser is trying to recover.

## Real round trip

The RED fixture compiles a real shared ELF containing:

```c
__attribute__((noinline)) long project_transform(long value) {
    return value * 3 + 1;
}

__attribute__((noinline)) long call_project_transform(long value) {
    return project_transform(value) + 7;
}
```

It resolves and decompiles only the exported caller through the native binary,
symbol, LLIR, SSA, AST, and C-rendering pipeline. Before the change, strict GCC
recompilation failed with an implicit declaration for `project_transform`.
After the change, the relevant output is:

```c
long call_project_transform(long arg0) {
    extern long project_transform(long);
    long rsp;
    long var1;
    rsp = (rsp - 16);
    var1 = project_transform(arg0);
    return (var1 + 7);
}
```

The generated unit recompiles as a shared object with
`-std=gnu11 -Werror=implicit-function-declaration -Wstrict-prototypes
-Werror=strict-prototypes`.

The independent behavior corpus is also green: all 56/56 lanes pass, and three
previously failing wide-result call-fold lanes now pass for GCC O0, GCC O2, and
Clang O0.

## Blinded DecBench A/B

The 224 blinded binaries were statically analyzed only. They were never
executed, emulated, or made executable.

A 16-worker extraction emitted 250/250 functions across all 224 binaries with
zero adapter errors. The official upstream function splitter, context
declaration builder, matching compiler selection, producer flags, diagnostic
fixup, and byte-match implementation were then replayed with 16 workers.

| optimization | functions | baseline compile | new compile |
|---|---:|---:|---:|
| O0 | 100 | 78 | 86 |
| O2-noinline | 100 | 31 | 49 |
| O2 | 50 | 18 | 27 |
| **total** | **250** | **127** | **162** |

Under the same installed evaluator dependencies:

- compile rate: 50.8% to 64.8%;
- compile gains: 35;
- compile regressions: 0;
- mean byte match over all 250 functions: 0.0778318 to 0.1053502;
- byte-match improvements: 33;
- byte-match regressions: 0;
- perfect byte matches: 4 before and after.

An initial comparison incorrectly showed score movement in byte-for-byte
identical C files. Replaying the baseline exposed the cause: one evaluator
environment lacked `diff-match-patch` and used the metric's set-Jaccard
fallback, while the new environment used its line-diff algorithm. Compile
counts were stable, but 64 scores changed across those environments. The
numbers above compare fresh baseline and candidate overlays produced by the
same evaluator checkout, Python environment, compiler, and metric dependencies.

The immutable submission artifact is
`glaurung-results-7a1f3bb.zip`, SHA-256
`c6338c52494bcd318208c6d275e1d9a20a97880cf811c53620ed9c62acf8bf4e`.

## Remaining failure frontier

The official fixup/recompile path now has 88 failures. A fresh diagnostic replay
shows the largest remaining families are:

- about 24 residual too-many/too-few-argument conflicts, primarily calls at the
  still-separate authoritative library-contract boundary;
- about 50 pointer/integer assignment or pointer-return mismatches across several
  concrete pointer types;
- isolated array, subscript, cast-width, and malformed-expression failures.

The next architectural slice should not add another output-text repair. It
should unify authoritative library declarations and recovered project-local
callee contracts in a shared prototype table, then propagate return and
parameter constraints through exact high-variable identities.

## Gates

- Rust library tests: 1,287 passed, zero failed.
- Real compiled fixture/harness file: 37 passed, zero failed.
- Full behavior corpus: 56/56 lanes, three improvements, zero regressions.
- `cargo fmt --check`: passed.
- `cargo clippy --all-targets`: exit 0 with the existing warning backlog.
- Ruff on the owned Python test file: passed.
- Repository-wide `ty`: remains red with 3,320 existing diagnostics across
  docs, scripts, optional angr/Ghidra integrations, and other unrelated paths.
- The broad Python run was stopped after three independent failures were
  reproduced: a stale binary-size expectation, four existing DecBench-render
  parse failures caused by stack-array/`size_t` issues, and an offline-LLM test
  selecting an available LLM path. None exercises the named-prototype change.

## Wall-clock policy

Future semantic slices should use this evidence loop:

1. one real compiled RED fixture;
2. one native-extension rebuild;
3. focused Rust/Python tests in parallel;
4. one 16-worker blinded extraction per source object;
5. retain diagnostics and rebuild artifact metadata without re-extraction;
6. reuse one materialized DecBench tree and run baseline/candidate overlays in
   the same locked environment;
7. run the broad gates once, after the focused and blinded A/B gates are green;
8. commit and push the bounded slice before starting the next defect.

On this checkpoint the full blinded extraction took about 52 seconds and the
250-function official recompile pass took about 2 seconds. The native rebuild
took 15 seconds. These operations should be overlapped only when they do not
share Cargo locks, evaluator checkpoints, or output trees.

## Submission decision

Do not submit yet. A 64.8% compile rate is a material improvement, but the
remaining type/prototype failures and the unclosed GED and structured-code gaps
still prevent a credible claim of parity with Ghidra, angr, or Kuna.
