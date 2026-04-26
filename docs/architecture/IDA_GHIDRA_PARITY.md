# Glaurung ↔ IDA / Ghidra parity status

Living document tracking what Glaurung has, what's still missing, and
why each gap matters. Updated whenever a roadmap task completes.

## Tier S — Foundations (mostly complete)

| # | Task | Status | Notes |
|---|---|---|---|
| 152 | Persistent project database (SQLite `.glaurung`) | ✅ | sessions, binaries (sha256-keyed), kb_nodes/edges/tags |
| 153 | Persistent type system + retroactive apply | ✅ | struct/enum/typedef/function_proto, set_by precedence, render-as-header |
| 154 | Bidirectional persistent xref database | ✅ | call/jump/data_read/data_write/struct_field, function_names, comments per VA |
| 155 | `glaurung repl` interactive CLI | ✅ | navigation, persistence, lazy LLM, readline history |
| 156 | Function-chunk model (non-contiguous functions) | ✅ | `<fn>.cold`/`.part.N` auto-folded into parent's chunks; replaces band-aid heuristic |
| 180 | Standard type-library bundles (libc/POSIX/WinAPI) | ✅ | 75+ canonical types ship by default, auto-load on KB open |
| 191 | Stack-frame variable recovery | ✅ | persistent slots, auto-discover from disasm operands, REPL `locals` command |
| 196 | Stack-frame variable rendering in decompile output | ✅ | KB-aware post-processor; `(rbp - 272)` → `&c2_url_buffer`; typed-locals prelude block with provenance tags |
| 198 | Win32 API prototype bundle | ✅ | 110 protos covering process injection, persistence, networking, crypto, syscalls; auto-loads alongside libc |
| 219 | Cross-references panel | ✅ | `glaurung xrefs <db> <va>` + REPL `x`; from_va | from_func | kind | snippet rows. The #1 daily-use button. |
| 220 | Rename + retype keystroke flow with auto-rerender | ✅ | REPL `n`/`y` at cursor; `render_decompile_with_names` rewrites callers' bodies on next render |
| 221 | Stack-frame editor view + inline retype | ✅ | `glaurung frame <db> <fn-va>` list / rename / retype / discover |
| 228 | Undo/redo for KB writes | ✅ | `undo_log` table, `glaurung undo|redo`, wraps every analyst-set setter (set_by="manual" gate) |
| **179** | **PDB ingestion (Microsoft Program Database)** | ⏳ | Symmetric to DWARF — covers PE/Windows. Blocked by #197 (MSVC sample fixtures). |
| 197 | MSVC + .pdb sample fixtures | ⏳ | Pre-req for #179 PDB testing |
| 199 | PE format hardening (delay imports, manifest, version info, TLS callbacks) | ⏳ | Pre-req for grounded malware triage claims |

## Tier A — Major workflow gaps (largely complete)

| # | Task | Status | Notes |
|---|---|---|---|
| 157 | DWARF + PDB ingestion (DWARF v1) | ✅ | gimli-based; functions, chunks, signatures, language; DWARF 5 + addrx |
| 158 | FLIRT / FunctionID signature library + matcher | ✅ | 32-byte exact-prologue, scan-and-rename; baseline lib at `data/sigs/glaurung-base.x86_64.flirt.json` |
| 159 | Diff-verification benchmark harness | ✅ | `python -m glaurung.bench` — 10-binary CI matrix + `--packed-matrix` UPX tier; 12+ metrics, baseline at `benchmarks/baseline.{json,md}` |
| 160 | Indirect-call resolution (vtable v1) | ✅ | rodata-scan for arrays of code pointers; jump-table walker shipped as #177 |
| 163 | Auto-struct recovery (Layer-1 pass) | ✅ | `[reg+offset]` access patterns → struct candidates with set_by="auto" |
| 170 | Cross-binary symbol borrowing | ✅ | donor → target prologue match; on-the-fly FLIRT |
| 172 | Cross-function type propagation v1 | ✅ | function_prototypes table + libc/POSIX bundle (77 protos) |
| 178 | DWARF type ingestion → type_db | ✅ | struct/union/enum/typedef with field bodies and resolved c_type |
| 181 | Per-instruction comments + global data labels | ✅ | comments table per-VA (since #154); data_labels for globals |
| 182 | Demangler audit + KB-wide pass | ✅ | Itanium/Rust/MSVC; every persisted name carries raw + pretty forms |
| 195 | Type-propagation v2 (call-site arg matching) | ✅ | regex-based operand parser; SysV x86_64 ABI |
| 162 | ABI-aware argument recovery (Win64, ARM64) | ✅ | Adds Win64 (rcx/rdx/r8/r9) and AAPCS64 (x0-x7) tables; auto-dispatch from triage |
| 177 | Jump-table walker | ✅ | Detects relative-offset `i32` switch tables in rodata; seeds case bodies as discoverable functions |
| 184 | Function-level binary diff tool | ✅ | `glaurung diff a b` — pair-wise diff with same/changed/added/removed status per function; Markdown + JSON output |
| 185 | Patch / assembly editor | ✅ | `glaurung patch` with `--bytes`, `--nop`, `--jmp`, `--force-branch`, `--verify` (re-disasm post-patch) shorthands. v0 of #224 lands the mnemonic flow. |
| 193 | Switch-statement reconstruction | ✅ | `Region::Switch { dispatch, arms, join }`; structurer detects ≥3-successor blocks with shared post-dom; AST emits `switch (..) { case N: ... }` |
| 200 | Evidence-tagged tool outputs | ✅ | citation IDs across the memory-tool registry |
| 201 | Agent self-verify loop | ✅ | post-rename consistency check |
| 202 | Differential decompile-and-compile verification loop | ✅ | recovered-source compile-check + byte similarity |
| 206 | `kickoff_analysis` composite tool | ✅ | One-shot first-touch pipeline (~300ms): detect_packer + triage + analyze + index + demangle + per-function discover/propagate/recover-structs. Available as REPL command, CLI subcommand, and pydantic-ai memory tool. |
| 208 | Generic evidence-recording tool wrappers | ✅ | every memory tool auto-records to evidence_log via `_record_tool_evidence` |
| 225 | Cross-table search | ✅ | `glaurung find <query>` — unified substring/regex search across function names, comments, data labels, types, stack vars, strings, disassembly |
| 227 | Function-prototype hints at call sites | ✅ | `// proto: int printf(const char *fmt, ...)` appended to every call line where a prototype is known |

## #161 umbrella — Decompiler polish atoms ✅ DONE

| # | Atom | Status |
|---|---|---|
| 191 | Stack-frame variable recovery | ✅ |
| 192 | Control-flow structuring (gotos → if-then) | ✅ |
| 193 | Switch-statement reconstruction | ✅ |
| 194 | Type-aware re-render of pseudocode | ✅ |
| 196 | Stack-frame variable rendering in decompile output | ✅ |

## Tier B — Important but specialized (mixed)

| # | Task | Status | Notes |
|---|---|---|---|
| 162 | ABI-aware arg recovery (Win64, ARM64) | ✅ | (also tier-A) |
| 165 | Standard-format export (.h / .c / BNDB / JSON) | ✅ | `glaurung export` with json/markdown/header/ida/binja/ghidra format choices |
| 184 | Function-level binary diff | ✅ | `glaurung diff a b` |
| 185 | Patch / assembly editor | ✅ | `glaurung patch in out --va N --nop|--jmp|--force-branch|--bytes [--verify]` |
| 209 | JVM classfile + JAR triage | ✅ | `glaurung classfile <path>` — recovers class name, super class, interfaces, fields, methods (with JVM descriptors) |
| 210 | .NET CIL / CLR metadata parser | ✅ | `g.analysis.cil_methods_path` — full-name method recovery from managed PEs (via ECMA-335 metadata tables); wired into `index_callgraph` with set_by="cil" |
| 211 | Lua bytecode (.luac) recognizer | ✅ | `glaurung luac <path>` — Lua 5.1 / 5.2 / 5.3 / 5.4 + LuaJIT, source-name extraction from debug info |
| 212 | Go gopclntab walker | ✅ | `g.analysis.gopclntab_names_path`; recovers function names from stripped Go binaries (1801 names from `hello-go`) |
| 213 | Bench-harness coverage: packed binaries | ✅ | `BinaryScorecard.packer` field, `--packed-matrix` flag, markdown summary surfaces "Packed binaries: N (UPX×N)" |
| 222 | Strings window with xrefs back to code | ✅ | `glaurung strings-xrefs <db>` — IDA-style strings panel with data_read xrefs |
| 223 | Tri-pane view (hex / disasm / pseudocode) | ✅ | `glaurung view <db> <va>` |
| 226 | Bookmarks + analyst journal | ✅ | new `bookmarks` and `journal` tables; `glaurung bookmark|journal` CLIs |
| 166 | More architectures (MIPS / RISC-V / PowerPC / WASM) | ⏳ | Pick one per session |
| 168 | Plugin architecture (registerable analysis passes) | ⏳ | Surface area beyond REPL |
| 173 | C → Rust translate end-to-end demo | ⏳ | LLM-driven |
| 183 | Format loader expansion (dyld_shared_cache, kernel cache, firmware, COFF) | ⏳ | Big surface area |
| 186 | BSim-equivalent function similarity (canonical PCode hashing) | ⏳ | More robust than FLIRT |

## Tier C — Coverage / polish (mostly done)

| # | Task | Status | Notes |
|---|---|---|---|
| 169 | Multi-arch / fat-binary slicing CLI | ⏳ | Mach-O fat, dyld_shared_cache |
| 171 | Build-and-run verification for source recovery | ✅ | Closes the loop on `recover_source.py` |
| 174 | [P] Fortran rewriter: emit complete `gfc_dt` body | ⏳ | Off-track polish |
| 175 | [Q] Fortran rewriter: emit extern prototypes for libgfortran/MAIN__ | ⏳ | Off-track polish |
| 187 | Anti-obfuscation primitives — packer detection v0 | ✅ | Section/string-pool fingerprint match for UPX/Themida/VMProtect/ASPack/MPRESS/PECompact/FSG/Petite/Enigma/Obsidium + generic high-entropy fallback. CLI: `glaurung detect-packer`. v2: CFG flattening, opaque predicates, anti-disassembly stubs. |
| 188 | Headless analyzer + project management (Ghidra-style) | ⏳ | Multi-binary projects |
| 189 | Debugger integration (gdb/lldb bridge) | ⏳ | Static-only today |
| 190 | Symbol export to BNDB / IDB / Ghidra archive | ✅ | shipped as part of #165 export trio (ida / binja / ghidra script formats) |
| 214 | Adversarial-tree regression coverage | ✅ | 85-test parametrized matrix walks every adversarial sample × every parser; enforces no-panic + 3-second per-call budget |

## Daily-basics floor (the IDA/Ghidra parity floor) ✅ DONE

The ten things an analyst hits in an hour of real work — all shipped:

| # | Floor | CLI / REPL surface |
|---|---|---|
| 219 | Cross-references panel | `glaurung xrefs`, REPL `x` |
| 220 | Rename + retype keystrokes | REPL `n` / `y` (with auto-rerender preview) |
| 221 | Stack-frame editor | `glaurung frame` |
| 222 | Strings window with xrefs | `glaurung strings-xrefs` |
| 223 | Hex / disasm / pseudocode tri-pane | `glaurung view` |
| 224 | Patch shorthands | `glaurung patch --nop|--jmp|--force-branch [--verify]` |
| 225 | Search-everything | `glaurung find` |
| 226 | Bookmarks + journal | `glaurung bookmark` / `glaurung journal` |
| 227 | Function-prototype hints at call sites | inline `// proto: ...` comments in `render_decompile_with_names` |
| 228 | Undo / redo | `glaurung undo` / `glaurung redo` |

## Corpus expansion ✅ DONE

Glaurung now reads end-to-end across the four major managed-runtime
formats and the canonical native trio:

| Format | Status | Recovery surface |
|---|---|---|
| ELF (C / C++ / Fortran / Rust / Go / Zig) | ✅ | Full pipeline (DWARF / FLIRT / propagation / decompile) |
| Mach-O | ✅ | Triage + symbol extraction; decompiler shared with ELF |
| PE (native) | ✅ | Triage + symbol extraction; PE-specific hardening (#199) is the next layer |
| PE (managed / .NET / Mono) | ✅ | `g.analysis.cil_methods_path` (#210) |
| ELF (Go) | ✅ | `g.analysis.gopclntab_names_path` (#212) — recovers full namespaced names from stripped binaries |
| Java (.class / .jar / .war / .ear) | ✅ | `glaurung classfile` (#209) — class metadata + method descriptors |
| Lua bytecode (.luac, LuaJIT) | ✅ | `glaurung luac` (#211) — engine detection + source-name extraction |

Adversarial-input regression coverage (#214) ensures every parser
handles malformed magic-byte games / truncated headers / format
masquerades without panicking, with a 3-second per-call budget.

## Demo loop status

All three canonical chat-UI demo conversations from the phased plan are now reproducible from the current HEAD:

| Demo | Sample | Transcript |
|---|---|---|
| 1. Malware triage | `c2_demo-clang-O0` | [demo-1-malware-triage.md](../demos/demo-1-malware-triage.md) |
| 2. Vulnerability hunting | `vulnparse-c-gcc-O0` | [demo-2-vulnerability-hunting.md](../demos/demo-2-vulnerability-hunting.md) |
| 3. Patch analysis | `switchy-c-gcc-O2{,-v2}` | [demo-3-patch-analysis.md](../demos/demo-3-patch-analysis.md) |

`glaurung kickoff` (#206) makes the agent's first turn a single tool call (~300ms). Combined with the daily-basics floor, the deterministic backbone of the chat UI is fully in place — only the streaming web front-end (#203/#204) is gating Phase 5 launch.

## Where Glaurung *over-performs* the incumbents

1. **Persistent KB schema with explicit provenance**. Every named entity carries a `set_by` field (`manual` / `dwarf` / `stdlib` / `flirt` / `propagated` / `auto` / `borrowed` / `analyzer` / `gopclntab` / `cil`) with a precedence rule (manual always wins). Neither IDA nor Ghidra surface this cleanly.
2. **Modern type system with bundle composition**. Stdlib types ship as committed JSON bundles, layered with DWARF imports and analyst overrides — versioned, diffable, scriptable.
3. **Bench harness with per-commit regression metrics**. `python -m glaurung.bench` produces a deterministic JSON scorecard tracking 12+ dimensions across the sample matrix. Every commit can be diffed against the previous baseline; regressions surface immediately. The `--packed-matrix` tier specifically guards packer-detection regressions.
4. **First-class LLM integration**. 50+ deterministic memory tools registered with the `pydantic-ai` agent. The agent operates on the same persistent KB as the analyst; everything it learns persists across sessions.
5. **Modular Python ↔ Rust split**. Performance-critical primitives live in Rust (DWARF parser, FLIRT matcher, vtable walker, jump-table walker, gopclntab parser, CIL metadata parser, Java classfile parser, Lua bytecode recognizer, disassembly). Workflow logic, KB schema, CLI surfaces, and LLM tools live in Python where iteration is cheap.
6. **Composable daily-basics floor with end-to-end undo/redo.** Every analyst write (rename / retype / comment / data label / stack-var rename) goes through the same `_record_undo` helper, so a single `glaurung undo` reverses any analyst action regardless of which CLI surface produced it. Neither IDA nor Ghidra wire undo across all annotation types this uniformly.

These six are differentiating strengths and should keep deepening as the parity gaps close.
