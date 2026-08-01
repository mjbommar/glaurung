# Test strategy

## Principle

Testing must separate deterministic software correctness, live agent behavior,
decompiler text metrics, and execution behavior. Passing one lane does not make
another green.

The repository's TDD rule applies: write the failing test before implementing
each contract. Real binary fixtures are mandatory for analysis claims.

## Test pyramid

### Layer 1: Pure contracts

Fast deterministic tests for:

- Target/address canonicalization, including ARM Thumb.
- Pydantic input/output schemas.
- Tool and evidence envelopes.
- Policy hashes and run identities.
- Validation diagnostics and repair classification.
- Atomic checkpoint parsing and compatibility.
- Package mapping and declaration collision handling.
- Secret redaction with sentinel values.

Constructed candidate C is acceptable for testing parser/validator error paths;
it is not evidence of decompilation quality.

### Layer 2: Deterministic tools on real binaries

Each approved tool is tested against checked-in, reproducibly compiled
fixtures. Cover:

- x86-64 and x86 where present.
- ARM and Thumb address semantics.
- PE imports and image-base addresses.
- GCC and Clang.
- `-O0` and optimized output.
- Functions with loops, branches, indirect dispatch, stack objects, structs,
  recursion, and imported calls.

Assertions target stable facts such as mapped addresses, edge kinds, import
identity, operand widths, and bounded output—not fragile full text.

### Layer 3: Controller integration without a model claim

Exercise real context construction, tool registration, validation,
checkpointing, and packaging. PydanticAI test models or recorded responses may
be used only if the project owner explicitly authorizes them; otherwise test
the controller pieces directly and reserve end-to-end agent behavior for a live
model lane.

No simulated response may be cited as evidence that the agent works.

### Layer 4: Live-agent fixture tests

Run the configured real model and real tools on a small fixed corpus. Required
cases:

- Straight-line arithmetic.
- Conditional branch.
- Counted and sentinel loops.
- Switch or indirect dispatch.
- Recursive function.
- Struct/array access.
- Imported libc/API calls.
- Multi-function context where a callee inspection helps.
- ARM Thumb target.
- PE target.
- Embedded prompt-injection string.

Retain tool traces, usage, C, validator results, and model identity. Do not make
these tests default unit tests if they incur network cost; provide an explicit
live gate with clear credentials and cost expectations.

### Layer 5: Source-to-binary-to-source behavioral round trip

For curriculum fixtures:

1. Compile known source with a declared toolchain/optimization.
2. Strip the binary where the lane requires it.
3. Recover the target with raw, fixed pipeline, and agent.
4. Recompile recovered C.
5. Execute original and recovered functions through the existing isolated
   harness over deterministic and fuzz inputs.
6. Compare behavior and record structural-only cases separately.

The no-execution restriction applies to blinded DecBench binaries, not to
repository-owned fixtures specifically compiled for behavioral testing.

### Layer 6: DecBench metrics

Run exact native/pipeline/agent artifacts through the same scorer revision.
Measure completion, perfect rates, distances, compile rate, failures, time,
tokens, and cost. DecBench scores do not replace Layer 5.

### Layer 7: Repository gates

- Focused new tests.
- Existing agent/tool tests.
- Full Python suite.
- Rust suite.
- Ruff format/check on owned Python paths.
- `ty` on owned Python paths.
- `git diff --check` and documentation link validation.

Repository-wide pre-existing lint/type debt is reported separately and must not
be rewritten incidentally.

## Required fixture matrix

| Feature | GCC O0 | GCC O2 | Clang O0 | Clang O2 | ARM/PE |
|---|---:|---:|---:|---:|---:|
| Arithmetic/bitwise | required | required | required | required | one |
| Branches | required | required | required | required | one |
| Loops | required | required | required | required | one Thumb |
| Switch/indirect dispatch | required | required | required | required | one |
| Arrays/structs | required | required | required | required | one |
| Calls/prototypes | required | required | required | required | PE import |
| Recursion | required | required | required | required | optional |
| Adversarial string | one | one | optional | optional | optional |

Use the curriculum corpus plan rather than creating agent-only toy programs.

## Agent-specific assertions

A live result is not enough. Tests should assert:

- Registered tool names equal the approved policy.
- The model calls only registered tools.
- Every final evidence ID exists and belongs to the target.
- Tool calls stay within address and count limits.
- At least one substantive evidence tool precedes synthesis.
- A validator failure produces bounded repair or explicit rejection.
- Usage and termination records are complete.
- No secret or private manifest data enters messages/artifacts.
- No binary execution subprocess exists.

## Flake and nondeterminism policy

- Never hide a failure with an unbounded retry.
- Retain every attempt and count it in cost.
- A live test may define a bounded success rate over repeated runs, but must
  report the denominator and exact model/settings.
- Deterministic contracts must be 100% stable.
- If model nondeterminism blocks CI, keep a small manually authorized live gate
  and rely on deterministic controller/tool gates for default CI.

## Stop conditions

Stop expanding the tool set or corpus when:

- A static policy violation occurs.
- A raw behavioral lane regresses due to shared code changes.
- Validation incorrectly accepts a known wrong-address or extra-definition case.
- Traces omit a tool call, usage, or termination event.
- Cost exceeds the declared cap.
- Improvements exist only on public fixtures and fail a retained holdout.
