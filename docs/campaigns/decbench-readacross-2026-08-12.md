# DecBench read-across, 2026-08-12

A read-only review of the DecBench fork and its PR #56 branch
(`codex/pr56-refresh-20260808`), looking for defects and contract mismatches
that belong on the **Glaurung** side. Nothing was written to DecBench.

DecBench integrates Glaurung as two backends (`glaurung`, `glaurung-agentic`)
by shelling out to the CLI, so its integration commits are an unusually direct
record of where Glaurung's *external contract* is ambiguous or wrong. Three
things were worth chasing; one was a real defect here.

## 1. ARM Thumb bit — already fixed, more thoroughly

DecBench carries an uncommitted fix in `decbench/utils/binfmt.py` +
`metrics/byte_match.py` for two symptoms of the same cause: bit 0 of an ARM
`STT_FUNC` symbol value is the ABI's Thumb marker, so

- slicing a function's bytes at the raw `st_value` reads **one byte late** for
  every Thumb function, and
- decoding Thumb-2 as A32 does not fail loudly — capstone returns confident
  nonsense, and both sides of a comparison get scored on it.

**Glaurung already handles both, and handles the second one better.**
`program::image::normalize_function_entry` masks the bit for ELF+ARM at 15 call
sites, including `.symtab` ingestion itself (`src/program/image.rs:251`), so no
consumer downstream of the image ever sees the odd address. Mode selection
(`analysis::arm32_mode::mode_at`) does not rely on the function-symbol bit
alone: it prefers the `$a`/`$t` **mapping symbols**, which are authoritative and
present per code region rather than per function, and falls back to bounded
decode probes in both modes when a binary is stripped of them.

No action. Recorded because the reasoning is easy to re-derive wrongly.

Loose end: `analysis::arm32_mode::normalise_entry` is now superseded by
`image::normalize_function_entry` and has no callers — only comments cite it.

## 2. `--require-llm` and the confident-heuristic skip — not a defect

Commit `83c3ab7` ("accept deterministic Glaurung role labels") widened
DecBench's accept-set for the `classify_function_role` stage from `{"llm"}` to
`{"llm", "heuristic"}`, because that stage reports `source = "heuristic"` even
under `--require-llm`. `classify_function_role.py:173` deliberately skips the
API call when the deterministic classifier is already ≥ 0.70 confident.

The question this raises is whether widening the set also lets a *genuine*
degradation through — an API outage silently scored as an agentic result. It
does not:

- under `--require-llm`, `run_structured_llm` **raises** `LLMUnavailable` rather
  than returning the fallback, and
- `explain.py`'s wrapper catches that and reports `source = "error"`, not
  `"heuristic"` (`python/glaurung/cli/commands/explain.py:136-138`).

So with `--require-llm` set, `"heuristic"` can only mean the confident skip, and
DecBench's widened set is exactly right. No code change. The `--require-llm`
help text describes the flag purely in terms of the LLM being *unreachable*,
which is what made this need verifying at all — a stage that skips the call on
purpose is a third case the flag's documentation does not mention.

## 3. `decompile --vas` silently dropped entries and exited 0 — **fixed**

Commit `7637c65` ("fail closed") changed DecBench's runner from

```python
if p.returncode != 0 and not (stdout or "").strip():   # tolerate partial output
```

to failing on any non-zero exit. Chasing what it was defending against turned up
the mirror-image defect on our side.

`decompile_many` iterates *discovered* functions and skips any requested entry
that discovery never resolved or whose lift bailed, so its result list can be
shorter than the request. The CLI's `--vas` path then returned 0 unconditionally.
Reproduced against `hello-gcc-O2`:

```
$ glaurung decompile <bin> --vas 0x999999,0x2549 --style decbench --format json
# 2 VAs requested, 1 record returned, exit 0, stderr empty
```

A batch consumer could not distinguish "this binary has no such function" from
"we asked for fewer" — and a run where *nothing* resolved looked like a clean
success with an empty array.

The fix (`_report_unresolved_vas`) keeps stdout byte-identical for callers that
parse it, and adds the missing signal on stderr:

- some entries recovered → name the missing ones, exit **0**. One unsupported
  function must not discard a whole binary's run, which is precisely the
  all-or-nothing cliff DecBench's stricter check would otherwise create.
- no entry recovered from a non-empty request → exit **2**.

Thumb-bit-bearing requests compare against the normalised address, so an ARM
caller passing `st_value` is not reported as missing.

All five in-repo `--vas` consumers were checked against the new behaviour:
`diff_decompile.decompiled_c` already mapped non-zero to `None` (and already
mapped an empty array to `None`, so exit 2 changes nothing for it),
`roundtrip_review` ignores the return code on that call, `extbench/run_glaurung`
reconciles per-VA against its own target list, and `decompiled_many_c` calls the
native binding rather than the CLI.

## 4. Gaps DecBench documents that are real, and still open

From `docs/GLAURUNG.md` "Scope / limitations", an outside integrator's view of
where we are:

- **Structured `VariableInfo` is not emitted.** DecBench's `type_match` falls
  back to text-parsing our C signature, and line-mappings are omitted entirely.
- **Struct and array types are not recovered** — an aggregate parameter still
  renders as a pointer to its element type.

Both are known frontier items rather than defects; noted here because the
scoreboard cost of the first one is concrete and measurable.
