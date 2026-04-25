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
| **179** | **PDB ingestion (Microsoft Program Database)** | ⏳ | Symmetric to DWARF — covers PE/Windows. Blocked by #197 (MSVC sample fixtures). |
| **192** | **Control-flow structuring (gotos → if/while/for)** | ⏳ | Multi-week project. The single biggest remaining jump in decompiler readability. |
| 197 | MSVC + .pdb sample fixtures | ⏳ | Pre-req for #179 PDB testing |
| 199 | PE format hardening (delay imports, manifest, version info, TLS callbacks) | ⏳ | Pre-req for grounded malware triage claims |

## Tier A — Major workflow gaps (largely complete)

| # | Task | Status | Notes |
|---|---|---|---|
| 157 | DWARF + PDB ingestion (DWARF v1) | ✅ | gimli-based; functions, chunks, signatures, language; DWARF 5 + addrx |
| 158 | FLIRT / FunctionID signature library + matcher | ✅ | 32-byte exact-prologue, scan-and-rename; baseline lib at `data/sigs/glaurung-base.x86_64.flirt.json` |
| 159 | Diff-verification benchmark harness | ✅ | `python -m glaurung.bench` — 10-binary CI matrix, 12 metrics, baseline at `benchmarks/baseline.{json,md}` |
| 160 | Indirect-call resolution (vtable v1) | ✅ | rodata-scan for arrays of code pointers; jump-table walker deferred to #177 |
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
| **193** | **Switch-statement reconstruction** | ⏳ | Combines with #177 jump-table walker (now shipped) — next is IR-level construct emission |

## #161 umbrella — Decompiler polish atoms

| # | Atom | Status |
|---|---|---|
| 191 | Stack-frame variable recovery | ✅ |
| 192 | Control-flow structuring | ⏳ |
| 193 | Switch-statement reconstruction | ⏳ |
| 194 | Type-aware re-render of pseudocode | ⏳ |

## Tier B — Important but specialized (pending)

| # | Task | Notes |
|---|---|---|
| 162 | ABI-aware arg recovery (Win64, ARM64) | Easy: extend #195's `_SYSV_ARG_REGS_X64` with Win64 / AAPCS register lists |
| 165 | Standard-format export (.h / .c / BNDB / JSON) | Interop with IDA / Ghidra |
| 166 | More architectures (MIPS / RISC-V / PowerPC / WASM) | Pick one per session |
| 168 | Plugin architecture (registerable analysis passes) | Surface area beyond REPL |
| 173 | C → Rust translate end-to-end demo | LLM-driven |
| 177 | Jump-table walker (#160 v2) | Pre-req for #193 |
| 183 | Format loader expansion (dyld_shared_cache, kernel cache, firmware, COFF, .NET, Java) | Big surface area |
| 184 | Function-level binary diff tool | BinDiff-style |
| 185 | Patch / assembly editor | Standard table-stakes |
| 186 | BSim-equivalent function similarity (canonical PCode hashing) | More robust than FLIRT |
| 194 | Type-aware re-render of decompiled output | Depends on #172 + #180 + xref_db field-use tracking |

## Tier C — Coverage / polish (mostly pending)

| # | Task | Status | Notes |
|---|---|---|---|
| 169 | Multi-arch / fat-binary slicing CLI | ⏳ | Mach-O fat, dyld_shared_cache |
| 171 | Build-and-run verification for source recovery | ⏳ | Closing the loop on `recover_source.py` |
| 174 | [P] Fortran rewriter: emit complete `gfc_dt` body | ⏳ | Off-track polish |
| 175 | [Q] Fortran rewriter: emit extern prototypes for libgfortran/MAIN__ | ⏳ | Off-track polish |
| 187 | Anti-obfuscation primitives — packer detection v0 | ✅ | Section/string-pool fingerprint match for UPX/Themida/VMProtect/ASPack/MPRESS/PECompact/FSG/Petite/Enigma/Obsidium + generic high-entropy fallback. CLI: `glaurung detect-packer`. v2: CFG flattening, opaque predicates, anti-disassembly stubs. |
| 188 | Headless analyzer + project management (Ghidra-style) | ⏳ | Multi-binary projects |
| 189 | Debugger integration (gdb/lldb bridge) | ⏳ | Static-only today |
| 190 | Symbol export to BNDB / IDB / Ghidra archive | ⏳ | Subset of #165 |

## Where Glaurung *over-performs* the incumbents

1. **Persistent KB schema with explicit provenance**. Every named entity carries a `set_by` field (`manual` / `dwarf` / `stdlib` / `flirt` / `propagated` / `auto` / `borrowed` / `analyzer`) with a precedence rule (manual always wins). Neither IDA nor Ghidra surface this cleanly.
2. **Modern type system with bundle composition**. Stdlib types ship as committed JSON bundles, layered with DWARF imports and analyst overrides — versioned, diffable, scriptable.
3. **Bench harness with per-commit regression metrics**. `python -m glaurung.bench` produces a deterministic JSON scorecard tracking 12 dimensions across the sample matrix. Every commit can be diffed against the previous baseline; regressions surface immediately.
4. **First-class LLM integration**. 50+ deterministic memory tools registered with the `pydantic-ai` agent. The agent operates on the same persistent KB as the analyst; everything it learns persists across sessions.
5. **Modular Python ↔ Rust split**. Performance-critical primitives live in Rust (DWARF parser, FLIRT matcher, vtable walker, disassembly). Workflow logic, KB schema, and LLM tools live in Python where iteration is cheap.

These five are differentiating strengths and should keep deepening as the parity gaps close.
