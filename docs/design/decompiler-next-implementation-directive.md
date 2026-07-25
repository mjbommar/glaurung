# Decompiler next-implementation directive

This is an implementation task, not a request for another status report,
permission check, design essay, or explanation of why the work is difficult.

## Authoritative starting state

- `origin/master` is `5b0568e`.
- The committed fixture baseline is 117 pass, 284 fail, 55 structural, and 2
  environment-missing results.
- The GitHub Decompiler Fixture Gate is red. Its matrix job failed before
  execution because `uv run maturin develop --release` could not find
  `maturin`.
- Therefore the current commit is pushed, but it is not CI-verified.
- `src/exec/state.rs` already contains the canonical x86-64/AArch64
  register-family layout and correct partial-register semantics. Do not create
  another independent register table.
- Render-time copy-chain folding is a semantic pipeline operation. A renderer
  that performs it is not pure and prevents reliable AST verification.

Work in the following order.

## Phase 1: Repair and enforce the gate

1. Fix `.github/workflows/decompiler-fixtures.yml` so `maturin` is explicitly
   provisioned. Do not assume `[build-system].requires` installs a runnable
   `maturin` command.
2. Locally verify the exact clean-environment sequence used by CI:
   - `uv sync --all-extras --dev`
   - confirm that the chosen `maturin` invocation exists;
   - build the native extension;
   - run the fast fixture tests;
   - run the slow semantic and structural tests.
3. Fix the Clang C++ baseline hole:
   - CI provisions a working Clang C++ runtime;
   - a baseline lane recorded as `env-missing` must not silently become
     runnable and then be excluded from comparisons;
   - add a regression test proving `env-missing -> runnable` requires a
     baseline refresh;
   - generate real Clang C++ baseline results in the provisioned environment.
4. Commit and push the gate repair.
5. Monitor the GitHub workflow through completion. Do not use the words
   "verified", "green", or "complete" while any required job is red, queued,
   skipped, or missing.

## Phase 2: Establish the correct verifier boundary

1. Add characterization tests for the copy-chain folding currently performed
   during rendering.
2. Move that folding into an explicit, named AST transformation executed before
   rendering.
3. Make renderers formatting-only. They must not change definitions, uses,
   control flow, or value identities.
4. Reintroduce def-before-use verification against the post-transformation AST.
5. Add tests containing:
   - a genuine use-before-definition that must fail;
   - `rt_u8`, which must not produce a false positive;
   - branch-local definitions and joined uses;
   - copy chains eliminated by the explicit folding pass.
6. Baseline existing verifier violations if necessary, but fail on every new
   violation. Do not merely log them indefinitely.
7. Preserve rendered output byte-for-byte unless a fixture differential proves
   that existing output is wrong.

## Phase 3: Prove and implement register-view semantics

Do not begin by adding another special case to `value_number.rs`, and do not
blindly edit `ssa.rs`.

1. Classify representative remaining failures with pass dumps:
   - `mul_widen`;
   - one deposit/extract failure;
   - one `sum_argN` failure.
2. For each failure, record:
   - the correct LLIR state;
   - the first pass where corruption appears;
   - the exact parent register, view, offset, width, and write behavior involved.
3. If these failures do not share the same root cause, split them. Do not force
   them into one architectural story.
4. Extract the existing register-view metadata from `src/exec/state.rs` into one
   shared, architecture-aware descriptor consumed by both execution and
   decompilation. It must represent:
   - canonical parent;
   - bit offset;
   - view width;
   - 32-bit zero-extension behavior;
   - partial-write preservation;
   - x86 high-byte registers;
   - AArch64 `xN`/`wN` relationships.
5. Add failing tests before implementation for:
   - parent write followed by narrower read;
   - narrow write followed by parent read;
   - cross-basic-block alias use;
   - `al`, `ah`, `ax`, `eax`, and `rax`;
   - `eax` zeroing the upper half of `rax`;
   - `al`, `ax`, and `ah` preserving unaffected bits;
   - AArch64 `w0` zero-extending into `x0`.
6. Represent width changes explicitly using typed IR operations such as
   `Extract`, `Trunc`, `ZExt`, and `Concat`. Do not encode width or alias
   semantics in string names such as `rax#1`.
7. Preserve SSA identity across register-family aliases and across basic blocks.
8. Deliver one bounded vertical slice first. It must fix at least one real,
   previously failing fixture, pass its unit and integration tests, and produce
   zero pass-to-fail regressions in all four lanes.
9. Refresh the baseline only after manually verifying every changed
   differential.

## Final acceptance criteria

Do not stop with "the frontier is deep". Continue until either the slice is
complete or there is a concrete, reproduced blocker.

The final report must contain only:

- commits created and pushed;
- exact baseline before and after;
- exact local verification commands and exit results;
- GitHub workflow URLs and final conclusions;
- newly passing functions;
- any regressions;
- remaining failures grouped only by demonstrated root cause.

Do not claim completion based on commit messages, partial tests, local-only
results, or skipped CI jobs. Keep generated `workspace/` artifacts out of Git.
