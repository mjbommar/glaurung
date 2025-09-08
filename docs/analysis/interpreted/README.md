# Interpreted and VM Bytecode Analysis — Support, Disassembly, Decompilation

Status: Draft
Owner: Glaurung AI
Last updated: 2025-09-04

## Overview

This document consolidates our strategy to add high-signal, bounded support for interpreted/VM bytecode artifacts with a focus on Python and Java first, followed by adjacent ecosystems (Android DEX/APK, Lua, Ruby/YARV, and .NET IL). The goal is to produce consistent, LLM‑ready evidence (functions, calls, strings, symbols/metadata) that aligns with the existing data model, CLI, and agent tooling — while being safe, fast, and easy to validate.

Key outcomes:
- Unified triage → parse/disassemble → evidence pipeline for bytecode.
- DRY alignment with `BinaryEvidence`/`FunctionEvidence` so CLI/LLM features “just work”.
- Safe, bounded parsers (no code execution) with strict resource limits.
- Clear roadmap from Python/Java MVPs to broader coverage.

## Principles

- Safety-first: never execute code; bounded recursion, size, and time limits.
- DRY data model: reuse existing evidence models (no ad-hoc types for bytecode).
- High-signal first: strings + calls + lightweight per-function disassembly.
- Deterministic outputs: version-aware decoding but deterministic evidence.
- Budget-aware: explicit truncation; never hide when we cut.

## Scope and Formats

Initial targets (tiered):
- Tier 1 (MVP): Python (.pyc/.pyo, pyz/zipapp, PyInstaller overlays), Java (.class/.jar, MRJAR basics)
- Tier 2: Android (DEX/APK), Lua (.luac), Ruby YARV (InstructionSequence), .NET IL (assemblies)
- Tier 3: Ecosystem packaging formats (.whl, .egg), obfuscators, and advanced analyses

See also:
- Python: docs/parsers/python/README.md
- Java: docs/parsers/java/README.md
- Android/DEX/APK: docs/parsers/android/README.md
- Wasm (already covered): docs/parsers/wasm/README.md

## Triage and Detection

- Magic numbers:
  - Python .pyc: `0x.. 0x0D 0x0A` (and 3.7+ bitfield per PEP 552).
  - Java .class: `0xCAFEBABE` (big‑endian); MRJAR is a ZIP/JAR container.
- Containers:
  - ZIP/JAR detection (EOCD scanning) already present; manifests (Main‑Class) extracted at jar processing.
  - Python zipapp (`.pyz`) is also ZIP; PyInstaller bundles identified via overlay/container sniffers.
- Recursion:
  - Use `src/triage/recurse.rs` + container heuristics to enumerate child artifacts under budgets.

References:
- docs/triage/headers.rs (pyc detection), docs/triage/containers.rs (zip/jar), docs/triage/recurse.rs

## Safety & Boundedness

- Byte/size limits: honor `AnnotateBudgets.max_read_bytes/max_file_size`.
- Recursion limits: cap nested code object traversal and nested container depth.
- Timeouts: keep per‑stage time budgets; avoid quadratic scans.
- No execution: Python `marshal` is used only for deserialization to code objects; no `eval/exec/import`.
- Defensive parsing: reject pathological constant pools or code objects, flag errors in `notes`.

## Data Model Integration (DRY)

We reuse the LLM evidence models in `python/glaurung/llm/evidence.py`:
- `BinaryEvidence(path, arch, format, endianness, symbols, functions, notes, ...)`
- `FunctionEvidence(name, entry_va, instructions, calls, strings, hints, ...)`
- `InstructionAnno(va, bytes_hex?, text, call_target_name?, string_text?, ...)`
- `CallSite(va, target_name?, target_va=None)` and `StringRef(va, text, ...)`

Conventions for bytecode:
- Address semantics: `entry_va` and instruction `va` are pseudo‑VAs backed by bytecode offsets or instruction indices (documented explicitly). For jar/class, we prefer method start byte offset; for Python, instruction index relative to function start.
- SymbolsSummary: leave `plt_map/import_thunk_map/got_map` empty; populate `imports` with module/class references and `libs` with runtime hints when known.
- Strings: derived from constant pools (Java) or constants/docstrings (Python); include section-like hints only when a file offset is known.

## Language Pipelines

### Python (.pyc/.pyo; pyz/zipapp; PyInstaller overlays)

Phases:
1) Header parsing (PEP 552 aware)
- Magic, bitfield (hash‑based vs timestamp), timestamp/hash, source size.

2) Marshal decoding of top‑level `code` object (bounded)
- Use `marshal` module to load code objects; enforce limits on recursion depth, object count, and max sizes (constants/strings/bytecode).

3) Code object traversal and disassembly
- Traverse nested code objects; for each function/method/code:
  - Extract metadata (co_name, filename, firstlineno, arg counts).
  - Disassemble with `dis.get_instructions` (version‑aware; handles adaptive opcodes 3.11+).
  - Build `InstructionAnno.text` as “opname argrepr”; set `va` from bytecode offset or sequential index.

4) Evidence extraction
- Strings: literal constants, docstrings; attach to `FunctionEvidence.strings`.
- Calls: detect CALL opcodes and resolve the target name via preceding LOAD_* sequences (LOAD_GLOBAL/LOAD_METHOD/LOAD_ATTR);
  - Set `CallSite.target_name` (e.g., `print`, `os.system`, `requests.get`).
- Hints: “prints constant string”, “uses requests”, “spawns process” (based on calls + literals).

5) Packaging formats
- zipapp (.pyz): iterate members; pick top‑N code objects (entry like `__main__.py`) under budgets.
- PyInstaller: surface embedded pycs; annotate top ones; record packaging in `notes`.

Status & references: docs/parsers/python/README.md, PEP 552; uncompyle6/pycdc as optional later decompilers.

### Java (.class, .jar; multi‑release basics)

Phases:
1) Class file parsing (bounded)
- Magic/version, constant pool (types: Utf8, Class, NameAndType, Methodref, Fieldref, InvokeDynamic, etc.), access flags, this/super, interfaces.
- Members: fields/methods and attributes; focus on Code attribute for methods. Enforce constant pool and method code size limits.

2) Bytecode decoding
- Decode opcodes sufficient to identify calls and strings:
  - Calls: `invokevirtual`, `invokespecial`, `invokestatic`, `invokeinterface`, `invokedynamic`.
  - Resolve `ClassName.method:descriptor` via constant pool; fill `CallSite.target_name`.
  - Literals: `ldc`/`ldc_w`/`ldc2_w` for string constants → `StringRef`.
- Build textual disassembly (mnemonic + short arg pretty‑print) for `InstructionAnno.text` with instruction byte offsets as pseudo‑VAs.

3) JAR processing
- List class members; parse `META-INF/MANIFEST.MF` for `Main-Class`; prefer annotating main and a small set of top classes/functions under budgets.
- Multi‑release JARs: select a single release directory by heuristic (e.g., highest supported version) for MVP.

4) Evidence and hints
- Strings: constant pool strings; include notable resources (paths, URLs); classify with existing string classifier for IOC hints.
- Hints: “prints constant string”, “network usage” (e.g., `java/net/URL.openConnection`).

Status & references: docs/parsers/java/README.md; JVM Spec; external decompilers (Fernflower, CFR, Procyon) for optional follow‑on.

### Android DEX/APK (follow‑on)

- See docs/parsers/android/README.md for detailed plan: APK container, DEX parsing, bytecode, exception tables, method refs. Optional decompile hints via JADX.

### Other Bytecode Targets (stubs)

- Lua (.luac): luadec/unluac references; simple constant extraction and op listing.
- Ruby/YARV: RubyVM::InstructionSequence dump (offline) for op listing; strings/calls surface.
- .NET IL: re‑use ILSpy/dnlib references; treat similarly to JVM plan.

## CLI and API Integration

- Single entrypoint: `annotate_functions_path(path, budgets)` dispatches by triage format/extension:
  - PythonBytecode → `annotate_python_pyc_path`
  - .class → `annotate_java_class_path`
  - .jar → `annotate_java_jar_path`
  - else → native path (existing)
- CLI:
  - `glaurung cfg --annotate` prints unified ASM+comments across native/bytecode.
  - `glaurung cfg --annotate-json` emits `BinaryEvidence` JSON; works for pyc/class/jar.

## Decompilation Strategy (Optional, bounded)

- Python: integrate decompyle3/uncompyle6/pycdc as optional steps to derive structured summaries; keep outputs bounded and tagged as decompiled.
- Java: integrate Fernflower/CFR/Procyon (CLI invocation) optionally under user opt‑in; parse method signatures for evidence alignment.
- Android: prefer JADX (covers APK end‑to‑end) as a reference or optional helper.
- Safety: external tools run in sandbox, with time/memory limits; we parse their outputs but do not exec any produced code.
- Data model: decompilation results enrich `FunctionEvidence.hints` and can attach a separate “decompiled” blob (kept out of `InstructionAnno` to avoid bloat), or be referenced by path in `notes`.

## Obfuscation & Anti‑Analysis

- Python: opcode remapping (custom interpreters), marshal tweaks, packed/encrypted constants; detect anomalies (impossible sequences, high entropy constants), flag in `notes`.
- Java: ProGuard/R8 obfuscation; string encryption; reflection abuse; dynamic class loading; detect patterns (short 1–2 char identifiers, reflection APIs); flag and score.
- Android: DexGuard/packing; runtime decryptors; detect reflective calls and native loads.

## Testing

- Samples: use `samples/binaries/platforms/.../export/python/*` and `.../java/*`.
- Unit tests (Python):
  - PYC evidence: header parse + strings/calls across 3.8–3.13.
  - CLASS/JAR evidence: constant pool strings + callsite names (Java 8/11/17/21 samples where available).
- Integration tests:
  - `glaurung cfg --annotate-json` round‑trip for pyc/class/jar.
- Golden outputs: keep small JSON fixtures to guard regressions; budgeted to avoid brittleness.

## Metrics & Performance

- Target parsing budget: ≤ 50ms per small artifact; ≤ 300ms for moderate jar under default budgets.
- Memory: O(file size) with caps and bounded constant pools.
- Coverage: Python 2.7 (legacy) and 3.6–3.13+ (priority 3.8+); Java 8–21 constant pool.

## Parity & Comparison (IDA/Ghidra/rizin)

- IDA/Ghidra provide rich JVM/Python plugins and decompilation; our focus differs:
  - Fast triage and LLM‑ready evidence under strict budgets.
  - Minimal configuration and portable CLI/py API.
  - Clear provenance links (calls/strings with pseudo‑VAs and offsets when known).
- Roadmap to parity features:
  - Control‑flow for bytecode (basic block edges) via offsets.
  - Cross‑reference graphs: string → function back‑refs; callgraphs compressed at name granularity.
  - Optional decompiler enrichment with external tools.

## Roadmap & Milestones

- M1 (Python MVP)
  - Implement `annotate_python_pyc_path`; unify dispatch in `annotate_functions_path`.
  - Extract strings/calls; basic hints; tests over 3.8–3.13 pyc samples.
- M2 (Java MVP)
  - Implement `annotate_java_class_path` and `.jar` handling; resolve calls/strings; tests on Java 8/11/17/21 classes/jars.
- M3 (Packaging & polish)
  - zipapp (.pyz), PyInstaller embedded pyc discovery; MRJAR selection; improved notes.
- M4 (Bytecode CFG)
  - Basic block/edge modeling for Python/Java (offset‑based), integrate into `FunctionEvidence.cfg_edges` under budgets.
- M5 (Optional Decompilers)
  - Opt‑in decompiler backends; parse results into hints and structured summaries.
- M6 (Android DEX/APK)
  - Bounded DEX parsing; map calls/strings similarly; optional JADX hints.
- M7 (Ruby/Lua/.NET stubs)
  - Minimal evidence (strings/calls) and tests; evaluate lift to full pipelines later.

## Open Issues & Next Steps

- Decide address representation policy per language (byte offset vs instruction index), document consistently in evidence JSON.
- Multi‑release JAR selection policy; tie to host JDK or highest version under budget.
- Reflection/dynamic import resolution heuristics with low false positives.
- Sandbox external tools (if used) and integrate timeouts uniformly across OSes.

## Internal Cross‑References

- Evidence and builders: `python/glaurung/llm/evidence.py`
- CLI commands: `python/glaurung/cli.py`, `python/glaurung/cli/commands/cfg.py`
- Triage: `src/triage/*` (headers, containers, recurse, format_detection, signatures)
- Strings: `src/strings/*` (classification useful for IOC tagging of constants)

## External References

- Python
  - CPython `dis` and bytecode docs: https://docs.python.org/3/library/dis.html
  - PEP 552 (deterministic pycs): https://www.python.org/dev/peps/pep-0552/
  - CPython marshal format: https://github.com/python/cpython/blob/main/Python/marshal.c
  - Decompilers: https://github.com/rocky/python-uncompyle6, https://github.com/zrax/pycdc
  - PyInstaller extractor: https://github.com/extremecoders-re/pyinstxtractor
- Java / Android
  - JVM Spec: https://docs.oracle.com/javase/specs/jvms/
  - ASM: https://asm.ow2.io/
  - JAR Spec: https://docs.oracle.com/javase/8/docs/technotes/guides/jar/
  - Dalvik/DEX: https://source.android.com/docs/core/runtime/dex-format
  - Decompilers: Fernflower, CFR, Procyon; JADX for Android
- Tools/Frameworks
  - Ghidra/IDA/rizin/Cutter for parity references
  - LIEF (parsers), goblin (Rust parsing examples)

---

This plan keeps bytecode support first‑class and consistent with the native pipeline, enabling immediate utility for triage and LLM‑driven analysis while leaving a clean path to deeper features.

