# Output validation and repair

> **Kind:** design · **Status:** proposed

## Objective

Validation is the trust boundary between model output and a DecBench result.
The model proposes C; deterministic code decides whether it can be credited.

## Structured output

The PydanticAI output type must contain more than C even though the external
package eventually retains only the source and function mapping:

| Field | Requirement |
|---|---|
| `identifier` | Exact `sub_<requested-va>` spelling selected by controller policy |
| `c_prototype` | One C declaration matching the definition |
| `c_source` | Required declarations plus exactly one target definition |
| `evidence_ids` | Nonempty references into the current target's ledger |
| `assumptions` | Explicit uncertain choices |
| `unresolved` | Facts the agent could not recover |
| `confidence` | Diagnostic in `[0,1]`; never an acceptance oracle |

## Validator chain

Run validators in this order so feedback is specific and cheap checks fail
before compiler work.

### V1: Schema and size

- Pydantic schema is valid.
- Source is nonempty and below the configured byte ceiling.
- Text is UTF-8 without NUL bytes or markdown fences.
- Required evidence references are present and known.

### V2: Target identity

- Identifier equals the controller-generated target identifier.
- ARM Thumb canonicalization is handled only in address metadata, not by
  silently changing the requested manifest address.
- The prototype and definition use the same identifier.
- No known source symbol or package-derived name leaks into the required
  placeholder identity.

### V3: Translation-unit shape

- Exactly one target function definition exists.
- No additional top-level function definitions exist.
- Supporting typedefs, enums, structs, and extern declarations are allowed.
- No `main`, constructor, inline assembly, linker directive, or generated entry
  point is present unless the requested function itself is `sub_<va>`.

### V4: Static policy

Reject source containing:

- `system`, `popen`, `fork`, `exec*`, dynamic loading, or equivalent runtime
  escape behavior introduced by the model when not evidenced as target calls.
- Inline assembly or embedded binary blobs intended to bypass scoring.
- Preprocessor includes with absolute or parent-relative paths.
- Generated commands, scripts, markdown, or prose outside C comments.
- Deliberate undefined-behavior tricks intended only to force byte identity.

Calls that genuinely exist in the target may use names such as `execve`; policy
validation must distinguish reconstructed behavior from evaluator escape. The
external package is never executed regardless.

### V5: C parsing and syntax

- Parse with the selected C parser when available.
- Run the pinned compiler in `-fsyntax-only` mode through stdin.
- Never link or execute.
- Classify diagnostics rather than storing only a return code.

Required diagnostic classes include unknown type, undeclared identifier,
undefined struct use, arity/prototype mismatch, invalid lvalue, invalid cast,
unbalanced syntax, duplicate definition, and timeout.

### V6: Evidence consistency

Use bounded deterministic checks to identify obvious contradictions:

- Returned constant or width contradicts decoded return behavior.
- Prototype argument count is incompatible with high-confidence call-site facts.
- A direct imported call is renamed to a different API without evidence.
- A claimed referenced string is absent from cited evidence.
- A cited evidence record belongs to another target.
- Major branches or returns in high-confidence CFG evidence have no counterpart
  in parsed C.

This validator is intentionally conservative. It should flag high-confidence
contradictions, not attempt to prove semantic equivalence.

### V7: Package contract

- Output can be mapped to the exact manifest function.
- C filename and binary name are deterministic.
- Aggregating multiple requested functions for one binary introduces no
  duplicate declarations or cross-function collisions.
- `results.json` remains valid against the official kit contract.

## Repair policy

Classify each failure:

| Class | Repair? | Example |
|---|---|---|
| `format` | yes | markdown fence, wrong identifier |
| `syntax` | yes | missing semicolon, unknown local typedef |
| `contract` | yes, once | extra top-level definition |
| `evidence` | yes | uncited assumption, branch contradiction |
| `policy` | usually no | shell escape or arbitrary include |
| `scope` | no | wrong target or out-of-scope evidence |
| `budget` | no | request/token/time ceiling |
| `infrastructure` | retry outside run only if policy allows | transient provider error |

The default official profile permits at most two validation repair attempts.
Repair feedback contains:

- Stable validator code.
- Minimal exact diagnostic.
- Required correction.
- Reminder that target and evidence policy are unchanged.

Do not inject hidden ground truth, suggested source code, or a raw/fixed-pipeline
answer into the repair prompt.

## Acceptance states

- `accepted`: every mandatory validator passes.
- `accepted_with_warnings`: permitted only for non-score-affecting warnings
  explicitly listed in policy; stored as `accepted` plus warnings.
- `rejected`: output violates a non-repairable contract or exhausts repair.
- `failed`: no valid structured output due to provider/tool/controller failure.
- `budget_exhausted`: the run ended at a hard resource limit.

Only `accepted` functions enter the package. Package completeness reports every
missing target rather than hiding it.

## Required validation fixtures

Use real compiled functions plus intentionally malformed candidate outputs to
test the validator itself:

- x86-64 function with branches and a libc call.
- ARM Thumb function with odd requested VA.
- PE function with imported WinAPI call.
- Function requiring a local struct declaration.
- Multi-function binary with declaration collision risk.
- Embedded prompt-injection string.
- Wrong-address result.
- Extra helper-function definition.
- Unknown type and undefined struct failures.
- Valid C that contradicts a high-confidence CFG return edge.

These tests prove validator behavior. They do not count as evidence that the
agent recovers real functions correctly; live real-agent fixtures remain a
separate gate.
