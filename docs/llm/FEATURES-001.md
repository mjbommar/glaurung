# LLM Analysis Features — Design Plan (FEATURES-001)

Status: Draft
Owner: Glaurung AI
Last updated: 2025-09-04

## 1) Goals (Think Backwards From Analyst Outcomes)

We want high-signal, DRY, composable context that lets an LLM (and a human) reliably:

- Label obvious functions (e.g., main prints a greeting → `print_hello_world`).
- Answer “what does this binary do?” using evidence: symbols, strings, calls, and CFG.
- Explain I/O/network behavior: e.g., “writes this value to this file”, “connects to this hostname:port”.

Key principles:

- DRY/Composable: all evidence is produced once, kept as modular records, reused by agents.
- Evidenced: every assertion is tied to concrete evidence (call target + arg string + section/VA).
- Budget-aware: explicit truncation metadata; never hide cuts from user/LLM.
- Human-first + Machine-first: readable ASM+comments and structured JSON exist together.

## 2) Data Products (Canonical, Reusable Records)

Define canonical Pydantic models (Python) for all analysis outputs. These are the only payloads passed between components and into LLMs (via pydantic-ai structured output).

Important: Prefer reusing existing native models from `glaurung._native` to stay DRY. The Pydantic wrappers below only add annotation fields and compose native types; they do not re‑invent instruction/function/graph models.

### 2.1 Core Models

```python
from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Tuple

class Address(BaseModel):
    kind: Literal["VA","RVA","FileOffset"]
    value: int
    bits: Literal[32,64]

class InstructionAnno(BaseModel):
    va: int
    bytes_hex: str
    text: str                     # disassembly text
    # Optional annotations
    call_target_va: Optional[int] = None
    call_target_name: Optional[str] = None    # e.g., puts@plt
    rip_mem_target_va: Optional[int] = None   # effective VA when RIP-relative
    string_text: Optional[str] = None         # recovered literal (if any)

class CallSite(BaseModel):
    va: int
    target_va: Optional[int]
    target_name: Optional[str]

class StringRef(BaseModel):
    va: int
    text: str
    section: Optional[str] = None

class CFGEdge(BaseModel):
    src_va: int
    dst_va: int
    kind: Literal["Fallthrough","Branch","Call"]

class FunctionEvidence(BaseModel):
    name: str
    entry_va: int
    instruction_count_total: Optional[int]
    instruction_count_provided: Optional[int]
    instructions: List[InstructionAnno]
    calls: List[CallSite]
    strings: List[StringRef]
    cfg_edges: Optional[List[CFGEdge]] = None
    # Derived hints (cheap heuristics, optional)
    hints: List[str] = []   # e.g., "prints constant string", "returns 0"

class SymbolsSummary(BaseModel):
    imports: List[str]
    exports: List[str]
    libs: List[str]
    plt_map: Dict[int, str]          # VA -> name@plt
    sym_va_map: Dict[int, str]       # VA -> symbol name

class BinaryEvidence(BaseModel):
    path: str
    arch: str
    format: str
    endianness: str
    symbols: SymbolsSummary
    functions: List[FunctionEvidence]
    # Optional global callgraph data
    callgraph_edges: Optional[List[Tuple[str,str]]] = None  # (caller_name, callee_name)
    notes: List[str] = []              # truncation / limits / warnings
```

Rationale:

- A single `BinaryEvidence` bundle can power naming, summarization, Q&A (DRY).
- `FunctionEvidence` isolates all data needed for naming and behavior inference.
- `InstructionAnno` carries both human-readable text and machine-usable annotations.

### 2.2 Alignment With Existing Models (DRY)

We already expose rich native models via PyO3. The plan reuses them rather than duplicating fields:

- Instructions: reuse `glaurung.Instruction` and `glaurung.Operand`. `InstructionAnno` only adds optional annotations: call target name/VA and decoded string text. The human snippet uses `Instruction.disassembly()` and `Instruction.bytes` (hex).
- Functions/CFG: reuse `glaurung.Function` and its `basic_blocks`/`edges`. The `instruction_count_total` is `sum(bb.instruction_count)`; `cfg_edges` is optional and can be derived from existing function edges when needed.
- Call graph: reuse `glaurung.CallGraph` and compress to `(caller, callee)` IDs for LLM context when helpful.
- Symbols: reuse `glaurung.symbols.SymbolSummary` and helpers already exposed:
  - `_native.symbol_address_map(path)` → `(va, name)` for defined symbols
  - `analysis.elf_plt_map_path(path)` → `(va, "name@plt")` for ELF
  - `triage.list_symbols(path)` → import/export/library name lists

Bridging strategy: the Python `evidence` module composes these native objects into `BinaryEvidence`/`FunctionEvidence` without redefining core fields.

Additional core types we will leverage:

- References: `glaurung.Reference`, `ReferenceKind`, `ReferenceTarget` in `src/core/reference.rs` represent cross-references (calls, jumps, reads/writes, data refs). When a reference producer is available in analysis, we will map these into `InstructionAnno` (call_target_va/name) and `FunctionEvidence.calls` directly instead of ad‑hoc extraction.
- String literals: `glaurung.StringLiteral` in `src/core/string_literal.rs` models extracted strings and back-references. For LLM context, we will prefer these canonical objects (and their `referenced_by`) to attribute strings to functions; until cross-references are wired, we conservatively recover RIP-relative strings for x86_64 in the annotation stage.
- Addresses: `glaurung.Address` and `AddressKind` are used consistently in all native types; evidence carries raw VAs as ints for LLM friendliness while preserving provenance via notes.

## 3) Annotation Pipeline (Composable Stages)

Stages (each a pure function that enriches evidence). All stages receive/return canonical models.

1. Identify binary & sections: format, arch, endian, sections/segments.
2. Discover functions & CFG: entry VA, basic blocks, instruction counts.
3. Disassemble functions with budgets (budget-aware):
   - For small functions (≤ 200 instr), capture entire function.
   - Else capture a large window (e.g., 100–200 instr) + mark truncation.
4. Operand fidelity & annotations (architecture-specific):
   - x86/x64 (iced): near call/branch targets, RIP-relative memory → effective VA.
   - ARM/ARM64, MIPS, PPC (capstone): mirror fidelity where possible.
5. Symbols & PLT resolution (format-specific):
   - ELF: `.plt` + `.rela.plt` → VA→name@plt; dynsym/symtab VA→name.
   - PE/Mach-O: IAT/stubs equivalents (follow-on work).
6. String resolution:
   - RIP-relative effective VA → file offset → extract C-string (UTF-8), bounded.
   - Section filter (read-only), printable heuristics.
7. Behavior hints (cheap heuristics):
   - printf/puts/write(1, …) with constant string → "prints constant string".
   - return value = 0 sequence → "returns 0".
8. Build `FunctionEvidence` and `BinaryEvidence`.

Each stage must:

- Add explicit truncation notes when budgets are exceeded.
- Never mutate raw text; add annotations alongside it.
- Produce deterministic output given the same input and budgets.

Implementation note (reuse): stages 2/5 come from `analysis.analyze_functions_path()` and symbol helpers; stage 3 uses `disasm.disassemble_window_at()`; stage 4 relies on structured operands already present in `Instruction.operands`.

## 4) LLM Agents (pydantic‑ai Structured Prompts)

All agents use pydantic‑ai (or equivalent) to require structured outputs. Inputs are the canonical models; outputs are purpose‑specific.

### 4.1 FunctionNamerAgent

- Input: `FunctionEvidence` + `SymbolsSummary`
- Output (pydantic):
  ```python
  class FunctionNameSuggestion(BaseModel):
      name: str                   # e.g., print_hello_world
      confidence: float
      rationale: str
      tags: List[str]             # e.g., ["startup","io","print"]
  ```
- Behavior: Prioritize calls/strings; detect startup stubs; prefer concise, purpose‑driven names.

### 4.2 FunctionSummarizerAgent

- Input: `FunctionEvidence`
- Output:
  ```python
  class FunctionSummary(BaseModel):
      summary: str
      inputs: List[str]           # registers/params observed
      outputs: List[str]          # return value/effects
      side_effects: List[str]     # file/network/registry/memory
  ```

### 4.3 BinarySummarizerAgent

- Input: `BinaryEvidence`
- Output:
  ```python
  class BinarySummary(BaseModel):
      purpose: str
      key_behaviors: List[str]
      risk_level: Literal["benign","low","medium","high","malicious"]
      recommendation: str
  ```

### 4.4 BehaviorQAAgent (Targeted Q&A)

- Input: `BinaryEvidence` + question
- Output:
  ```python
  class QAResult(BaseModel):
      answer: str
      supporting_evidence: List[str]   # references to specific functions/VA/strings
  ```
- Examples:
  - “Does this binary write to a file?”
  - “Does it connect to a hostname:port?”
  - “Which function prints the greeting?”

### 4.5 I/O/Network Detectors (Optional specialized agents)

- Inputs: relevant `FunctionEvidence` slices
- Outputs: normalized event records (open/write path, connect host:port), with confidence.

## 5) Prompt Formatting (LLM Readability + DRY)

Always use a consistent, sectioned prompt template (for each agent):

- Header: function name/VA; arch; truncated? (X/Y)
- Imports & PLT: short list, deduped
- Calls: resolved names (first N), with VAs
- Strings: top K unique literals
- Disassembly: ASM with inline comments for calls and strings
- Notes: truncation, budget limits

Guidelines:

- Use bounded lists (K) with explicit truncation counts.
- Prefer CSV‑like one‑liners for calls/strings in the header; full text below.
- Keep ASM panel under budget; collapse no‑op areas if needed.

## 6) CLI & API Changes

### 6.1 CLI

- `glaurung cfg <path> --annotate` → ASM + comments for prioritized functions (includes main);
  shows truncation notes.
- `glaurung cfg <path> --annotate --json` → prints `BinaryEvidence` for the prioritized functions;
  `--annotate-all` emits for all functions.
- `--ai-names` now:
  - Always includes main (if present).
  - Increases snippet budget for small functions (full function ≤ 200 instr).
  - Appends “calls: …; strings: …; truncated X/Y” to the “Suggested Name” row summary.

Implementation detail (reuse): the CLI annotate path calls a new `glaurung.llm.annotate.annotate_functions_path()` that internally uses existing native helpers (`analysis.detect_entry_path`, `analysis.analyze_functions_path`, `disasm.disassemble_window_at`, `analysis.elf_plt_map_path`, `_native.symbol_address_map`) to build the reusable `BinaryEvidence` bundle.

### 6.2 Python API (high‑level wrappers)

- `annotate_functions_path(path, *, budgets) -> BinaryEvidence`
- `annotate_functions_bytes(data, *, budgets) -> BinaryEvidence`

## 7) Reuse and DRY (Single Source of Truth)

- Annotation code produces canonical models once; every agent consumes the same objects.
- ASM+comments is derived from `InstructionAnno`; JSON emission is a direct serialization of `BinaryEvidence`.
- PLT/symbol maps are shared across all stages via `SymbolsSummary`.
 - Existing native types (`Instruction`, `Function`, `ControlFlowGraph`, `CallGraph`, `SymbolSummary`) remain the single source for low‑level data; wrappers only annotate.

## 8) Truncation and Budgets (Make Cuts Explicit)

- Function-level budgets:
  - Full function if ≤ 200 instructions; else top‑N windows (e.g., entry block + callers) with counts.
- Every function record includes:
  - `instruction_count_total` and `instruction_count_provided`.
  - Notes include “truncated snippet X/Y instrs”.
- LLM prompts must include truncation lines prominently.

## 9) Use Cases → Flows

### 9.1 Label `main` as print_hello_world

Flow:

1. Build `BinaryEvidence` with:
   - `SymbolsSummary`: imports (puts), PLT map (VA→puts@plt).
   - `FunctionEvidence` for main: RIP string → "Hello, world"; call → puts@plt.
2. `FunctionNamerAgent(FunctionEvidence(main))` → `name=print_hello_world`.

### 9.2 Explain: “writes value X to file Y”

Flow:

1. Scan all `FunctionEvidence` for file I/O APIs (open, fopen, write, fwrite) and strings (paths).
2. Behavior hints are set (e.g., "writes to file").
3. `BehaviorQAAgent(BinaryEvidence, question)`→ structured answer with referenced evidence.

### 9.3 Explain: “opens connection to host:port”

Flow:

1. Detect network APIs (connect, sendto, getaddrinfo) and strings (hostnames) in functions.
2. Summarize candidate flows via calls+strings.
3. `BehaviorQAAgent` answers and cites specific functions/lines.

## 10) Roadmap & Tasks

### R1 (Immediate)

- [ ] Add Python models (pydantic) for evidence objects.
- [ ] Implement `annotate_functions_path/bytes` producing `BinaryEvidence`.
- [ ] Expand x86/x64 operand fidelity (done) and wire ARM/ARM64 (capstone) parity.
- [ ] Harden ELF PLT + symbol VA maps (done for the sample; extend across variants).
- [ ] Update `--ai-names` to include truncation notes (partially done) and full small functions.
- [ ] Add `--annotate` and `--annotate --json` to emit ASM+comments and JSON.

### R2 (Agents)

- [ ] Implement `FunctionNamerAgent`, `FunctionSummarizerAgent` with pydantic-ai.
- [ ] Implement `BinarySummarizerAgent`, `BehaviorQAAgent`.
- [ ] Add specialized IO/Network detectors (optional micro-agents).

### R3 (UX & QA)

- [ ] Show truncation warnings prominently in all outputs.
- [ ] Add unit tests for PLT/strings/calls resolution and truncation bookkeeping.
- [ ] Golden tests: ensure main in Hello sample → `print_hello_world` consistently.

## 11) Security & Performance

- Do not log sensitive strings by default; sanitize outputs for public logs.
- Maintain bounded budgets; pre-truncate in producers not in the LLM.
- Prefer iterative enrichment (fast) then optional deep passes (slower).

## 12) Appendix: Prompt Skeletons

### FunctionNamerAgent Prompt (Sketch)

```
FUNCTION: {name} @0x{entry_va:x}  arch={arch}
INSTR: provided={instruction_count_provided} total={instruction_count_total or '?'}
IMPORTS: {', '.join(symbols.imports[:10])}
CALLS: {', '.join([c.target_name or hex(c.target_va) for c in calls[:8]])}
STRINGS: {', '.join([repr(s.text) for s in strings[:6]])}
NOTES: {truncation_note_if_any}

ASM:
{annotated_asm_snippet}

Task: Suggest a concise, purpose-driven name. If printing a constant string via puts/printf, prefer print_<slug>.
Output schema: FunctionNameSuggestion
```

### BehaviorQAAgent Prompt (Sketch)

```
QUESTION: {question}
EVIDENCE DIGEST: imports, calls, strings (top-k), CFG edge counts
LIMITS: Provide references to function names + VAs in answers.
Output schema: QAResult
```
