# Tool surface and contracts

> **Kind:** design · **Status:** proposed

## Design rule

Register the smallest deterministic tool set that lets the agent answer the
source-recovery task. The general memory agent's 164-tool registry is a source
of wrappers and conventions, not the DecBench tool policy.

The initial set should remain below 20 tools. Every tool must be read-only,
target-scoped, typed, bounded, and independently testable on real binaries.

## Proposed v1 tool set

| Tool | Purpose | Key inputs | Required output | Initial limit |
|---|---|---|---|---:|
| `target_overview` | Orient architecture, format, sections, target bounds | none | canonical target, arch, range, confidence/warnings | 1 call |
| `view_disassembly` | Inspect decoded instructions | start VA, instruction count | address/opcode/mnemonic/operands | 160 instructions |
| `view_basic_blocks` | Recover local CFG | target VA | blocks, successors, branch kinds, loop hints | 64 blocks |
| `decompile_native` | Obtain raw Glaurung hypothesis | target VA, style | C/pseudocode plus native warnings | 24 KiB |
| `view_stack_frame` | Inspect stack slots and access widths | target VA | offsets, sizes, read/write/use facts | 128 slots |
| `view_call_sites` | Inspect target calls | target VA | site, target, args, result, prototype authority | 64 calls |
| `view_callee` | Inspect one direct callee | callee VA, detail level | bounds, prototype, summary, bounded disassembly | 8 callees |
| `view_callers` | Infer incoming argument use | target VA | caller sites and argument facts | 16 callers |
| `view_xrefs` | Inspect direct code/data references | VA, direction, kind | bounded typed references | 64 refs |
| `view_referenced_strings` | Recover strings used by target | target VA | address, encoding, escaped bytes/text | 64 strings |
| `view_imports` | Resolve imported call contracts | optional query | import address/name/library/prototype | 128 records |
| `view_constants` | Explain nontrivial immediates | target VA | value, uses, width, deterministic labels | 64 constants |
| `view_data_object` | Inspect referenced static data | VA, byte count | bounded hex/typed interpretation | 512 bytes |
| `check_c_syntax` | Validate candidate without linking/running | C source | compiler/parser diagnostics | 3 calls |
| `check_output_contract` | Preview structural acceptance checks | C source | identifier/definition/policy diagnostics | 3 calls |

The final two tools are safe feedback tools over generated text. The controller
still reruns authoritative validators after the agent returns.

## Why these are tools

A useful tool should expose new evidence or deterministic feedback the model
cannot reliably derive from the current prompt. Avoid tools that merely ask a
second model to answer a subproblem.

The following existing LLM-backed tools are **not** in v1:

- `infer_function_signature`
- `classify_function_role`
- `rewrite_function_idiomatic`
- `name_local_variable`
- `classify_constant` when configured to call an LLM
- any summarizer, critic, or nested recovery agent

Their fixed-pipeline result remains an ablation. Nesting them inside the primary
agent would obscure cost, provenance, and which model made a decision.

## Forbidden tool capabilities

The source-recovery agent must never receive:

- Arbitrary shell or subprocess execution.
- Arbitrary file read/write/list/glob.
- Binary execution, emulation, debugger, dynamic instrumentation, or loader.
- Package manager, compiler linker, or test runner for the target binary.
- Internet search, repository lookup, source download, or package metadata
  lookup.
- KB mutation, renaming, commenting, or type persistence.
- An unrestricted recursive-analysis tool that can fan out over the binary.
- Tools that return private manifest metadata or source identities.

## Common request envelope

Every tool call is normalized before invocation:

```python
class ToolRequestEnvelope(BaseModel):
    target_id: str
    call_id: str
    tool_name: str
    schema_version: int
    args: dict[str, JsonValue]
```

The controller injects `target_id`; the model cannot override binary path or
manifest identity.

## Common result envelope

```python
class ToolResultEnvelope(BaseModel):
    status: Literal["ok", "empty", "truncated", "unsupported", "error"]
    evidence_ids: list[str]
    payload: JsonValue | None
    warnings: list[str]
    retry_hint: str | None
    elapsed_ms: int
```

Expected unsupported formats, empty xrefs, and bounded truncation are typed
outcomes, not Python exceptions. Internal corruption, policy violations, and
native crashes fail the tool and enter the failure taxonomy.

## Tool-specific contracts

### Address handling

- Accept integers, not model-supplied paths or symbol names, for core lookup.
- Canonicalize ARM Thumb addresses while retaining the requested odd-bit value.
- Return the requested and canonical addresses.
- Reject unmapped and disallowed-range requests.
- Never silently substitute a nearby function.

### Disassembly

- Include raw bytes with decoded instructions where available.
- Mark decode gaps and architecture-mode changes.
- Preserve signedness/width facts without inventing types.
- Stop at explicit instruction, byte, and time limits.

### Native decompilation

- Label output as a decompiler hypothesis.
- Include native diagnostics, target bounds, style, and renderer revision.
- Do not silently call the fixed LLM pipeline.
- Return raw output even when it is malformed, with warnings.

### CFG and calls

- Represent block and edge identities explicitly.
- Distinguish fallthrough, conditional, direct, indirect, return, and tail edges.
- Record prototype authority: import, DWARF, stdlib, propagated, inferred, or
  unknown.
- Preserve unknowns instead of manufacturing callees or arguments.

### C checks

- Use generated source through stdin in an isolated scratch directory.
- Parse or run `-fsyntax-only`; never link or execute.
- Apply fixed resource and diagnostic-size limits.
- Return exact diagnostics with secrets and host paths removed.

## Registration design

Create a dedicated `register_source_recovery_tools()` function. It must:

- Register only the declared v1 set.
- Assert the resulting tool names exactly match the policy.
- Fail closed if PydanticAI's tool registry shape is not understood.
- Avoid the current best-effort private-attribute filtering used by the broad
  memory agent.
- Record a canonical tool-policy hash in every run.

## TDD requirements per tool

Before implementation, add a failing test that covers:

1. A real binary and real target address.
2. Correct typed output.
3. An out-of-scope address.
4. A limit/truncation boundary.
5. An unsupported architecture or missing fact when applicable.
6. Trace/evidence creation.
7. No mutation of the binary or KB.

Tool availability is not enough. At least one end-to-end agent fixture must
prove the model can understand and use each tool before it joins the official
policy.
