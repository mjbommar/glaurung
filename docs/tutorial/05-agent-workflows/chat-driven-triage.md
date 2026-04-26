# §Y — Chat-driven triage

How to use the LLM agent to drive analysis. **This chapter
requires LLM credentials**; if you skipped Tier 1's optional
section, set them now:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or
export OPENAI_API_KEY=sk-...
```

Tiers 1-4 work without these. Tier 5 is where Glaurung's LLM
integration starts paying off.

> **Output here is illustrative, not captured.** Unlike Tiers
> 1-4, the agent's natural-language responses are non-deterministic
> by design — different LLM model versions and prompt variations
> will phrase things differently. The deterministic substrate
> (every memory tool the agent calls + every `evidence_log` row it
> writes) IS reproducible; that's covered in §Z. The example
> response below is what one run looked like — yours will differ
> in wording but should land on the same evidence rows.

## The agent has 50+ memory tools

Every deterministic surface you've used in Tiers 1-4 is also
registered as a `pydantic-ai` memory tool. The agent doesn't
hallucinate function names or string content — it calls the same
underlying APIs you'd call from the CLI:

- `kickoff_analysis(binary)` — same as `glaurung kickoff` (#206)
- `view_function(va)` — same as `glaurung view <db> <va>`
- `list_xrefs_to(va)` / `list_xrefs_from(va)` — same as
  `glaurung xrefs`
- `set_function_name(va, name)` — same as REPL `n`
- `set_comment(va, body)` — same as REPL `c`
- `discover_stack_vars(fn_va)` — same as `glaurung frame ... discover`
- `recover_struct_candidates(fn_va)` — same as REPL `recover-structs`
- ... 40+ more.

**Every tool call records to evidence_log** (#200) with a
`cite_id`. The agent's response can cite those rows to ground its
claims.

## The cheap chat: `glaurung ask`

```bash
glaurung ask samples/.../c2_demo-clang-O0 "what does this binary do?"
```

The agent runs kickoff, then issues whatever follow-up tool calls
it needs. A typical response:

> This is a synthetic C2-callback malware analog. Based on
> evidence collected:
>
> 1. **C2 endpoints** (cite 12, 13): Embeds two domain literals
>    `malware-c2.evil.com` and `beacon.command-control.badguys.org`
>    referenced from the global pointer table at 0x4040.
>
> 2. **Update channel** (cite 17): `https://10.10.10.10:443/malware/update`
>    is hardcoded into a stack buffer via memcpy in `main`.
>
> 3. **Persistence** (cite 22): Writes paths
>    `/etc/cron.d/evil-persistence` and
>    `/etc/systemd/system/backdoor.service` — both intended for
>    root-level persistence.
>
> 4. **Exfil** (cite 28): Mentions `stolen-data@evil-corp.com` —
>    exfil endpoint, likely a placeholder rather than a live SMTP
>    target.
>
> The behavioural surface is consistent with a stage-1 dropper or
> a research / training sample.

Each `cite N` is an `evidence_log` row id. Inspect:

```bash
sqlite3 demo.glaurung "SELECT cite_id, tool, summary FROM evidence_log WHERE cite_id IN (12,13,17);"
```

```
12 | list_strings  | found 38 strings; sampled 20
13 | view_function | main @ 0x1160 — 432-byte frame, calls printf, snprintf, memcpy
17 | view_function | main @ 0x1160 — sample with the c2 url buffer build
```

You can verify each citation against what the agent actually saw.

## The interactive chat: `glaurung repl > ask`

For multi-turn analysis, drop into the REPL:

```bash
glaurung repl samples/.../c2_demo-clang-O0 --db demo.glaurung
```

```
>>> ask "what's at 0x4040 — looks like a global pointer table?"
   ... (agent calls list_data_labels, view_function, etc) ...

>>> g 0x1160
>>> n c2_main           # YOU rename main → c2_main
>>> ask "now that main is renamed c2_main, walk through what it does"
   ... (agent picks up the new name on its next view_function call) ...
```

The agent reads the **current** KB state on each tool call. Your
manual renames between turns are visible immediately.

## When the agent helps most

**Naming functions in stripped binaries.** `glaurung name-func
<binary> <va>` asks the agent to suggest a name from the
decompiled body. Useful for "I see what this function does, name
it for me":

```bash
glaurung name-func samples/.../some-stripped.elf 0x1140
```

```
suggestion: parse_command_packet
rationale: function reads first byte to dispatch; calls handle_*
  for each command type; layout matches a TLV parser.
```

Use `glaurung repl > n parse_command_packet` to commit if you
agree.

**Hypothesis verification.** Phrase the question as a hypothesis:

```
>>> ask "is 0x1140 a TLS handshake handler?"
```

The agent looks at the body, the call sites, the strings, and
either confirms or explains why the hypothesis doesn't fit.

**Cross-cutting questions.** "What strings are referenced from
network-handling functions?" — the agent enumerates network calls
(send/recv), traces back to their callers, and lists the
referenced strings.

## When the agent hurts

**Don't ask it to invent things.** "Make up a name for this
function" — bad question. "Suggest a name based on the
decompilation and call sites" — good question. The bounded
phrasing keeps the agent grounded in citable evidence.

**Don't trust without spot-checking.** Random sample: pull two of
the agent's `cite N` ids and verify the evidence_log row says
what the response claims. Glaurung makes this easy because every
tool call is logged.

**Don't let it drive when you'd be faster.** The deterministic
CLI is faster than asking — `glaurung find <db> <query>` is
sub-second; the same question routed through the agent takes 5-10
seconds and a token budget. Use the agent for synthesis questions,
not for lookups.

## Caveats / GAPs

- **No streaming output yet** ([#204](../../architecture/IDA_GHIDRA_PARITY.md)).
  The agent buffers its full response and renders at the end.
  For long sessions this means a noticeable wait.
- **No web chat UI yet** ([#203](../../architecture/IDA_GHIDRA_PARITY.md)).
  The agent runs through the CLI / REPL today; the web front-end
  is the Phase 5 launch surface.
- **Tool-call budgets.** The agent has a per-question budget on
  tool calls. If the question is too vague, the agent may
  exhaust its budget without converging — re-phrase with more
  context.

## What's next

- [§Z `evidence-and-citations.md`](evidence-and-citations.md) —
  read the evidence_log directly.

→ [§Z `evidence-and-citations.md`](evidence-and-citations.md)
