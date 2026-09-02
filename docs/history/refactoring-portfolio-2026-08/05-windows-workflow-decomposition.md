# Mini-project 5: Windows workflow decomposition

> **Kind:** record · **Date:** 2026-08-13

## Problem

The Windows product surface has two conspicuous multi-owner files:
`python/glaurung/cli/commands/windows.py` combines argument registration,
dispatch, persistence, orchestration, and human formatting, while
`windows_function_pretty_lift.py` combines fact schemas, extraction,
heuristics, rendering, validation, and tool integration.

Splitting each file by arbitrary ranges would preserve hidden coupling and make
the behavior harder to locate.

## Target design

```text
windows/domain/       typed facts and provenance
windows/extract/      deterministic fact extraction
windows/services/     use-case orchestration
windows/render/       human, JSON, and pseudocode views
windows/validate/     preservation and evidence checks
cli/commands/windows/ thin command adapters
llm/tools/windows/    thin agent-tool adapters
```

The deterministic fact packet is the contract shared by CLI and LLM tools.
Generated prose or pretty pseudocode cannot feed back as trusted facts without
an explicit verified promotion step.

## First vertical slice

Use `windows_function_pretty_lift.py` to prove the shape:

1. move Pydantic fact/result models without behavior changes;
2. move prototype and call-site extraction behind one extractor interface;
3. move memory/data-reference and path-condition extraction;
4. isolate rendering from preservation validation;
5. leave a small compatibility import module until callers migrate.

Then split `WindowsCommand` by command families—analyst, project facts,
corpus/runner, diff, and formatting—while preserving one registry.

## Required constraints

- Extractors are deterministic and do not call an LLM.
- Every fact carries source location/evidence and confidence where applicable.
- Validation compares structured facts, not merely substrings of rendered C.
- CLI JSON schemas remain stable or are explicitly versioned.
- Tool registration stays lazy enough to respect model tool-count routes and
  avoid importing all agents for simple CLI commands.

## Exit evidence

- Command modules register/validate/dispatch but contain no domain algorithms.
- Tool adapters contain no duplicate fact extraction.
- No reorganized Python module exceeds 1,500 lines without an ownership note.
- Existing focused Windows tests pass after every slice; Windows corpus guards
  and target-pipeline workflows pass before compatibility facades are removed.
- Import-time and peak-RSS measurements do not regress.

## Stop conditions

Stop if schemas lose fields/provenance, JSON output changes unintentionally,
validation becomes text-only, or extraction begins depending on a renderer or
agent response.

