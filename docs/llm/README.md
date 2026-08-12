# LLM subsystem documentation

Glaurung's LLM layer is optional. Deterministic triage, disassembly,
decompilation, project databases, and the tutorial verifier do not require a
provider key. LLM-backed commands can incur charges and send questions plus
binary-derived context to the selected provider.

## Current operator guides

- [`glaurung ask`](../cli/ASK_COMMAND.md): current command syntax, routing,
  budgets, output, structured findings, persistence, and failure semantics.
- [Agent-workflow tutorial](../tutorial/05-agent-workflows/chat-driven-triage.md):
  safe first use over a checked-in sample.
- [Evidence and citations](../tutorial/05-agent-workflows/evidence-and-citations.md):
  what persistent tool evidence does and does not prove.
- [Runtime configuration](../development/setup.md#runtime-configuration): model,
  provider, budget, and usage-log environment variables.

The project model policy is maintained in [`CLAUDE.md`](../../CLAUDE.md), and
the executable defaults live in `python/glaurung/llm/config.py`. Do not copy a
model name or provider sketch from an older roadmap.

## Current contributor guide

- [Tool system](TOOLS.md): the implemented `MemoryTool` contract,
  `MemoryContext`, pydantic-ai wrapper, routing, persistence, testing, and
  tool-addition checklist.

Current code is organized under:

```text
python/glaurung/llm/
├── agents/          agent implementations and factories
├── kb/              in-memory and persistent knowledge bases
├── tools/           typed deterministic and LLM-assisted tools
├── config.py        provider and model configuration
├── context.py       MemoryContext and analysis budgets
├── tool_routing.py  deterministic per-question tool selection
└── usage_tracker.py cost and usage accounting
```

## Historical and design records

The remaining pages preserve decisions, proposals, or implementation history.
They are useful for rationale but are not current API references:

| Document | Role |
| --- | --- |
| [ROADMAP.md](ROADMAP.md) | Original architecture plan with a current status preface |
| [FEATURES-001.md](FEATURES-001.md) | Draft evidence/data-product design |
| [AGENT_ITERATION.md](AGENT_ITERATION.md) | Historical iteration proposal |
| [ITERATION_SUMMARY.md](ITERATION_SUMMARY.md) | Historical pre-refactor assessment |
| [AGENT_REFACTOR_GUIDE.md](AGENT_REFACTOR_GUIDE.md) | Refactor-era architecture record |
| [RE_TOOLS_OVERVIEW.md](RE_TOOLS_OVERVIEW.md) | Superseded first-generation tool overview |
| [EMBEDDED_CONTENT_TOOLS.md](EMBEDDED_CONTENT_TOOLS.md) | Embedded-content design and implementation notes |
| [SOURCE_RECOVERY_TOOLS.md](SOURCE_RECOVERY_TOOLS.md) | Source-recovery tool-ladder design |

When a record conflicts with current help, source, or tests, prefer the current
artifact and update the maintained guide rather than treating the old sketch as
an API contract.
