# Source Recovery LLM Tool Ladder

## Goal

Take a stripped binary and produce a **well-documented, idiomatic source tree**
in C (or Rust / Go / Python) that reads as if it had been hand-written
before compilation — named variables, recovered structs and enums,
module layout, docstrings, a working build system, and a README.

This is a decomposition problem, not a "prompt the LLM with the whole
binary" problem. Monolithic prompts produce plausible-looking garbage.
This document describes 25 small-to-medium LLM calls that stack into a
full recovery pipeline, each with bounded input, structured output, and
a clear place in the dependency order.

## Design rules that apply to every tool

- **One purpose per call.** No tool both names something *and* classifies
  it. The chain is easier to debug and cheaper to re-run.
- **Bounded prompts.** ≤ 1,500 input tokens, ≤ 500 output tokens for
  Layer 0–1 tools. Layer 2 tools may reach ~4 k / 2 k. Layer 3 tools
  are the only ones allowed to span multiple functions.
- **Structured output only.** Every tool returns a `pydantic.BaseModel`.
  The schema includes a `confidence ∈ [0, 1]` field so the orchestrator
  can threshold and re-ask.
- **Heuristic fallback on every tool.** If no API key is configured,
  return a `LOW`-confidence result. The pipeline still produces *some*
  output offline — just rougher.
- **Pure transforms.** No tool writes to the KB directly; orchestration
  code persists results. This keeps tools reusable from the CLI.
- **Deterministic tools don't belong here.** The existing
  `decompile_function`, `list_xrefs_*`, `search_byte_pattern`, etc.
  provide the input evidence. LLM calls in this document only fire when
  there is genuine semantic ambiguity a regex cannot resolve.

## The 25 tools

### Layer 0 — Atomic labelers (trivially parallel, one small unit at a time)

The foundation. Each of these runs thousands of times across a real
binary. They are what make the upper layers tractable, because every
higher layer consumes *already-named* evidence instead of raw pseudocode.

**1. `classify_string_purpose`**
- In: one string literal + its observed uses (callers, printf-style argn).
- Out: `kind ∈ {url, path, format, sql, regex, error_message,
  log_template, crypto_const, key_material, user_agent, cmdline,
  c2_beacon, benign}`, confidence.
- Why LLM: `"/tmp/%s.log"` is both path *and* format; `"\x00\x00\x00\x18"`
  could be framing or key material. Context disambiguates.

**2. `classify_constant`**
- In: integer/float literal + the instruction context using it.
- Out: `kind ∈ {char, mask, flag_or, enum_value, size, offset,
  magic_number, errno, page_size, syscall_number, timeout_ms,
  raw_numeric}`, plus the symbolic rendering (`O_RDWR | O_DIRECT`).
- Why LLM: known-constants tables cover ~70 %; the rest need semantic
  reading of the call site.

**3. `name_string_literal`**
- In: string text + uses.
- Out: `SCREAMING_SNAKE_CASE` name for the `static const char[]`, plus an
  annotated format-argument list when the string is a format template.
- Why LLM: `"error: cannot open %s (errno=%d)"` becomes `ERR_FOPEN_FMT`
  with `args: [path: const char*, errno: int]` — a regex cannot infer
  parameter intent.

**4. `classify_loop_idiom`**
- In: a loop body (usually one basic block or tight nested pair).
- Out: `idiom ∈ {strlen, memcpy, memset, strcmp, crc16, crc32, hash_update,
  parse_decimal, parse_hex, base64_decode, base64_encode, aes_round,
  rc4_prga, custom}`, plus a parameter map `(src, dst, len, …)`.
- Why LLM: optimizer unrolls and strength-reduces; shape recognition
  without semantic cues misclassifies constantly. Unlocks Layer 2 — we
  replace whole loops with library calls in the recovered source.

**5. `name_local_variable`**
- In: one variable's def/use slice within a region + its recovered type.
- Out: `{name, rationale}`.
- Why LLM: `%var3` becoming `response_len` depends on what the variable
  gets compared against, what fields it indexes, what function it is
  passed to. This is the single highest-volume LLM call in the pipeline
  and the one that makes everything above it readable.

**6. `describe_call_site`**
- In: 10–15 lines around an *indirect* call (`call %reg`, vtable
  dispatch, function-pointer in a struct field).
- Out: a one-line description plus the LLM's best guess at the callee
  ("looks like `vt->open` on an object constructed at 0x4010").
- Why LLM: the callgraph stops at indirect calls; a pattern-spotter does
  not. Feeds Layer 1 struct recovery.

### Layer 1 — Structural recovery (small windows, still single-concept)

These consume Layer 0 labels to recover the program's data model. They
run fewer times — once per candidate struct/enum — but each call is
larger because it takes all the sites that share a base pointer or a
switch target.

**7. `recover_struct_layout`**
- In: every `[base + k]` access trace that plausibly shares a struct,
  plus the types recovered at each offset.
- Out: `struct name { type field; … };` with a per-field rationale and
  inferred alignment/padding.
- Why LLM: offsets and widths are deterministic; field *purpose* ("this
  is a refcount because it is `lock xadd`ed") requires reading uses.

**8. `recover_enum`**
- In: jump-table switch pseudocode + the string printed or returned in
  each branch, or the constant used at each call site.
- Out: `enum name { VARIANT_A = 0, VARIANT_B = 1, … }` with one-line
  doc per variant.
- Why LLM: `case 0:` is useless; `case 0: puts("connecting")` names
  itself as `CS_CONNECTING`. The LLM turns label evidence into variants.

**9. `recover_error_model`**
- In: every `return -N` / `return NULL` path across the binary + the
  strings printed on those paths by callers.
- Out: a unified error enum and a `code → symbolic name → message`
  mapping.
- Why LLM: consolidating 15 ad-hoc error returns into one coherent enum
  requires reading error strings and deciding which "couldn't allocate"
  sites collapse to `ERR_NOMEM`.

**10. `infer_function_signature`**
- In: function's own pseudocode + top-N callers' pseudocode.
- Out: full C prototype with named parameters, per-parameter semantics
  (`[in]`, `[in,out]`, `[out]`, `[consumed]`, nullability, ownership).
- Why LLM: caller usage ("result of `fopen` is always passed here")
  determines that `void *` is really `FILE *`. The decompiler cannot
  cross function boundaries like this.

**11. `hypothesize_protocol`**
- In: a cluster of string literals that look protocol-related
  (`"GET "`, `"\r\n"`, `"Content-Length: "`) plus the pseudocode that
  assembles them in order.
- Out: `{protocol, version, framing, observed_fields, notes}`.
- Why LLM: the strings alone could be HTTP, SMTP, or IRC; the *sequencing*
  in the assembly code disambiguates. Anchors later module naming.

**12. `recover_cli_grammar`**
- In: argv-handling pseudocode + any `-h`/`--help` strings pulled
  verbatim.
- Out: a synopsis, long/short flags, required/optional args, subcommand
  tree, default values.
- Why LLM: handwritten argv parsers do not follow any single template;
  only an LLM reading the `strcmp` ladder can recover the grammar.

### Layer 2 — Function-level synthesis (one function, rich context)

The workhorse layer. Each tool here runs once per function, reading the
already-stabilised tables from Layer 0–1. This is where the output
source starts to look like something a human wrote.

**13. `classify_function_role`**
- In: pseudocode + signature from #10.
- Out: `role ∈ {parser, serializer, validator, crypto_core, network_io,
  file_io, dispatch_table, wrapper, entry_stub, ctor_dtor, ioctl_handler,
  state_machine_step, getter, setter, other}`, confidence.
- Why LLM: drives which rewrite style #14 uses and how aggressive #21
  can be when naming.

**14. `rewrite_function_idiomatic`**
- In: pseudocode + signature + struct table + enum table + error model +
  already-named locals + target language.
- Out: rewritten source in the target language, plus an explicit
  `assumptions: list[str]` of rewrites the LLM performed that might be
  wrong (e.g. "replaced a 16-iteration loop with `memcpy` assuming no
  aliasing").
- Why LLM: this is the central creative step. Everything else either
  feeds it or polices it.

**15. `synthesize_docstring`**
- In: rewritten source from #14 + the strings it prints + one real
  caller call-site.
- Out: Doxygen / rustdoc / godoc / Python-style docblock with
  `@param`, `@return`, error cases, thread-safety notes, and one usage
  example inferred from the real caller.
- Why LLM: the rewrite focuses on code; separating the doc pass lets
  each call stay small and lets docs be regenerated when naming changes
  without re-rewriting the body.

**16. `propose_function_name`**
- In: rewritten source from #14 + role label from #13 + strings used.
- Out: canonical name, justification, list of rejected candidates (so
  #23 can reconcile across the whole tree).
- Why LLM: *runs after rewrite*, not before. Clean source with named
  variables is radically more nameable than raw pseudocode.

**17. `verify_semantic_equivalence`**
- In: original pseudocode + rewritten source.
- Out: `{equivalent: bool, divergences: list[{kind, location, severity}]}`.
- Why LLM: cheap adversarial pass that catches rewrites where the LLM
  silently dropped an error check, changed a `malloc` size, or
  sign-extended differently. Not a proof; catches ~80 % of mistakes
  before human review.

### Layer 3 — Cross-function coherence (consumes many Layer 2 outputs)

These tools span the whole binary and produce the scaffolding that
makes the output a *project*, not a pile of files.

**18. `cluster_functions_into_modules`**
- In: all function names + roles + one-line summaries + callgraph edges.
- Out: module tree — `net/http_parser.c`, `crypto/aes_ctr.c`,
  `util/buffer.c` — each with a purpose statement and member list.
- Why LLM: graph modularity gives the skeleton; the LLM names modules
  and arbitrates ambiguous assignments (helper called from two modules).

**19. `reconcile_function_identity`**
- In: alternative names proposed for the same function by different
  runs or contexts (from #16 and the existing `suggest_function_name`).
- Out: canonical name, aliases, confidence.
- Why LLM: deterministic tie-breaks pick shortest or most common; the
  LLM picks *most specific* — `read_exact_framed` over `read_data`.

**20. `reconcile_global_naming`**
- In: every function, struct, enum, and string-symbol name in the tree.
- Out: a rename map enforcing one style (`snake_case` vs `camelCase`),
  one prefix convention, one abbreviation vocabulary. Plus a style
  report listing why each choice was made.
- Why LLM: mechanical renamers cannot decide that `tcp_ctx` and
  `tcp_context` should both become `tcp_session` given the project's
  other naming patterns.

**21. `infer_build_system`**
- In: module tree from #18 + each module's imports + platform-specific
  symbol hints (`_WIN32`, `__linux__`) + target language.
- Out: `CMakeLists.txt` / `Cargo.toml` / `go.mod` / `pyproject.toml` +
  any helper build files, with flags, targets, and dependencies.
- Why LLM: build systems are templated text but the *content* requires
  understanding which modules link against what and which targets are
  binaries vs libraries.

**22. `write_readme_and_manpage`**
- In: module tree + top-level description from strings + CLI grammar
  from #12.
- Out: `README.md` + `man/` pages.
- Why LLM: synthesis of already-good inputs; no code reasoning needed.

### Layer 4 — Adversarial review and cross-language re-targeting

Runs *after* a full tree exists. These tools gate quality and extend
reach to other languages.

**23. `audit_recovered_source`**
- In: the full recovered tree (compressed to summaries per function) +
  original binary metadata (imports, string counts, function counts).
- Out: prioritised punch list — dead code retained, error paths missing,
  functions invented without binary backing, signature mismatches with
  callers.
- Why LLM: only a single large-context call can see the tree at scale.
  The existing `audit`-style heuristics cannot cross-check semantics.

**24. `translate_language`**
- In: clean recovered C tree + target language (Rust / Go / Python / …).
- Out: translated tree + `idiom_notes` explaining every non-mechanical
  rewrite (`malloc`/`free` → `Box`/`Drop`, `-errno` → `Result<T, E>`,
  callback → closure or trait object).
- Why LLM: language-idiom translation is a different skill from
  binary-to-source rewriting. Runs on clean source (not pseudocode), so
  it stays tractable.

**25. `explain_rewrite_delta`**
- In: original pseudocode for one function + final published source
  for the same function (after all reconciliation and possibly
  translation).
- Out: a short "rewrite notes" markdown file: what the LLM did, what it
  assumed, and what a human reviewer should double-check. One per
  non-trivial function.
- Why LLM: the user-facing transparency layer. Without this, nobody can
  responsibly ship recovered source — reviewers cannot tell where
  hallucination might hide.

## Dependency graph (order of operations)

```
Per small unit (massively parallel)
──────────────────────────────────
  1. classify_string_purpose  ─┐
  2. classify_constant         ├─> feed Layer 1 & Layer 2 evidence
  3. name_string_literal       │
  4. classify_loop_idiom       │
  5. name_local_variable       │   (runs after type recovery)
  6. describe_call_site        ┘

Per candidate struct / enum / error code (iterate to fixed point)
────────────────────────────────────────────────────────────────
  7. recover_struct_layout
  8. recover_enum
  9. recover_error_model
 11. hypothesize_protocol
 12. recover_cli_grammar

Per function, in reverse-topological callgraph order
───────────────────────────────────────────────────
 10. infer_function_signature
 13. classify_function_role
 14. rewrite_function_idiomatic
 15. synthesize_docstring   ─┐
 16. propose_function_name   │ parallel after 14
 17. verify_semantic_equivalence  (blocks publish if divergent)

Once per binary (full tree)
──────────────────────────
 18. cluster_functions_into_modules
 19. reconcile_function_identity
 20. reconcile_global_naming
 21. infer_build_system
 22. write_readme_and_manpage

Gate + optional re-target
─────────────────────────
 23. audit_recovered_source
 24. translate_language       (optional; runs on clean C tree)
 25. explain_rewrite_delta    (per non-trivial function)
```

## Cost / latency profile

Back-of-envelope for a 500-function binary:

| Layer | Calls | ≈ Tokens/call | ≈ Total |
|-------|------:|--------------:|--------:|
| 0     | ~50 k (per var/string/const) | 800    | 40 M    |
| 1     | ~200  (per struct/enum/proto)| 2 500  | 0.5 M   |
| 2     | ~2 000 (500 fns × 4)         | 4 000  | 8 M     |
| 3     | 5 large                      | 30 000 | 0.15 M  |
| 4     | ~500 (per non-trivial fn) + 1 | 3 000  | 1.5 M   |
| **Sum** |                            |        | **~50 M tokens** |

Latency is dominated by Layer 2 tool #14 (one serial chain per function
in callgraph order, though siblings parallelise). Dollar cost is
dominated by Layer 0 volume despite each call being cheap. Caching
(content-addressed on `(tool_name, input_hash)`) is essential — a
second run on a slightly modified binary should reuse ~90 % of Layer 0
outputs.

## What this ladder deliberately avoids

- **No "decompile the whole binary in one prompt."** The failure mode
  of LLM reverse engineering. The ladder exists specifically to
  decompose that monolithic task.
- **No per-instruction LLM call.** Instruction-level decompilation is
  deterministic; only reassembling *meaning* from clean pseudocode
  benefits from an LLM.
- **No ground-truth assumption.** Nobody has the original source in
  practice. Quality signal comes from adversarial review (#17, #23)
  and human-facing transparency (#25), not binary-diffing against a
  reference.
- **No one-shot naming.** The ladder names things *twice* — once on
  raw pseudocode (existing `suggest_function_name`) to bootstrap and
  once on clean source (#16) for final quality. Layer 3 (#19, #20)
  reconciles them.

## Implementation notes

- Each tool lives in `python/glaurung/llm/tools/` and follows the
  `MemoryTool[In, Out]` pattern already used by the 12 tools shipped in
  the `#78–#89` batch.
- Specialised agents in `python/glaurung/llm/agents/specialized.py`
  compose these tools. One agent per recovery phase (e.g.
  `LayerZeroLabelerAgent`, `StructureRecoveryAgent`,
  `FunctionRewriteAgent`, `ProjectAssemblyAgent`, `AuditAgent`) keeps
  the orchestration surface small.
- Content-addressed caching belongs at the `MemoryTool.run` boundary,
  not inside each tool — it is a pipeline concern, not a tool concern.
- The `preferred_model()` helper in `llm/config.py` already handles
  Opus / GPT selection; tools should not hardcode model choice.
