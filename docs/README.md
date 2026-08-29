# Glaurung documentation

Glaurung is a pre-1.0 reverse-engineering framework with a Rust analysis core,
Python bindings, a command-line interface, persistent project databases, and
optional LLM-assisted workflows. Start with the task-oriented material below;
the `design/`, `campaigns/`, and `sessions/` trees are engineering records, not
beginner guides or promises of shipped behavior.

Decompiler output is still experimental. Treat pseudocode as an analysis aid
and verify important conclusions against disassembly and runtime behavior.

## Start here

1. [Install Glaurung from source](tutorial/01-getting-started/install.md).
2. [Analyze the first checked-in binary](tutorial/01-getting-started/first-binary.md).
3. Take the [CLI tour](tutorial/01-getting-started/cli-tour.md) or
   [REPL tour](tutorial/01-getting-started/repl-tour.md).
4. Continue through the [complete tutorial track](tutorial/README.md).

For a shorter overview, supported platforms, and a Python API example, use the
[repository README](../README.md). Installation prerequisites, build modes,
configuration, and troubleshooting live in the
[development setup guide](development/setup.md).

## Find a workflow

| Goal | Read this |
| --- | --- |
| Inspect an unfamiliar binary quickly | [Triage overview](triage/README.md) and [first binary](tutorial/01-getting-started/first-binary.md) |
| Learn the CLI command surface | [CLI tour](tutorial/01-getting-started/cli-tour.md) and [CLI cheat sheet](tutorial/reference/cli-cheatsheet.md) |
| Navigate or annotate a project database | [REPL tour](tutorial/01-getting-started/repl-tour.md) and [analyst workflows](cli/analyst-ergonomics.md) |
| Make an annotation show up in the decompiled output | [The annotation loop](cli/analyst-annotation-loop.md) — `rename`/`comment`/`label`/`proto` and what `--db` changes on each surface |
| Work with names, types, xrefs, stack frames, or patches | [Daily basics](tutorial/02-daily-basics/) |
| Understand project data and provenance | [Persistent projects](architecture/PERSISTENT_PROJECT.md), [data model](architecture/data-model/README.md), and [`set_by` precedence](tutorial/reference/set-by-precedence.md) |
| See where we stand against IDA Pro, Ghidra, and angr | [Decompiler UX competitive ranking](design/decompiler-ux-competitive-ranking.md) — 18 capabilities ranked, with our column measured rather than recalled |
| Understand analysis architecture | [Analysis index](analysis/README.md), [disassembly](analysis/disassembly/README.md), and [decompiler overview](analysis/decompiler/README.md) |
| Read or test pseudocode output | [Decompiler overview](analysis/decompiler/README.md) and [decompiler testing](development/decompiler-testing.md) |
| Analyze PE files or Windows software | [Windows analysis](windows-port/README.md) and [Windows configuration](windows-port/windows-analysis-config.md) |
| Detect packers or compare binaries | [Packer configuration](triage/packer-config.md) and [similarity analysis](triage/similarity.md) |
| Use an LLM-backed command | [`ask` command](cli/ASK_COMMAND.md), [LLM subsystem](llm/README.md), and [runtime configuration](development/setup.md#runtime-configuration) |
| Reproduce a guided investigation | [Walkthroughs](tutorial/03-walkthroughs/) and [demos](demos/README.md) |
| Run source examples | [Executable examples](../examples/README.md) |
| Use or rebuild the sample corpus | [Sample corpus guide](../samples/README.md) |
| Contribute code or documentation | [Contributor policy](../CLAUDE.md), [agent policy](../AGENTS.md), and [development guidelines](development/guidelines.md) |

## Documentation by subsystem

### User and operator guides

- [`tutorial/`](tutorial/README.md): progressive, real-sample exercises from
  installation through analyst and agent workflows.
- [`cli/`](cli/): focused command and analyst-workflow guides.
- [`triage/`](triage/README.md): first-pass analysis, resource bounds, strings,
  packer signals, containers, and similarity.
- [`windows-port/`](windows-port/README.md): PE/PDB workflows, configuration,
  hardening, and Windows-specific analysis.
- [`demos/`](demos/README.md): longer malware, vulnerability, and patch-analysis
  scenarios.

### Core analysis and data model

- [`analysis/`](analysis/README.md): current analysis entry points plus clearly
  separated research checkpoints and historical proposals.
- [`architecture/`](architecture/README.md): current persistent-project and
  data-model boundaries plus dated reviews and proposals.
- [`parsers/`](parsers/README.md): native, bytecode, archive, Android, and
  managed-runtime parser documentation.
- [`formats/`](formats/README.md): format and compiler-artifact reference material.
- [`syscalls/`](syscalls/README.md): Linux and Windows syscall references used by
  analysis.

### AI-assisted and symbolic workflows

- [`llm/`](llm/README.md): maintained operator/contributor guides plus clearly
  labeled historical design and roadmap records.
- [`agentic-glaurung/`](agentic-glaurung/README.md): architecture, safety,
  evaluation, and delivery plan for autonomous source recovery. Its
  [status page](agentic-glaurung/STATUS.md) is the authority on what is actually
  implemented.
- [`axeyum-integration/`](axeyum-integration/README.md): symbolic execution and
  solver integration design, evidence, and validation material.

### Engineering records

- [`design/`](design/): active and historical design proposals. A proposal can
  describe behavior that is not implemented yet.
- [`development/`](development/): setup, repository structure, contributor
  guidance, testing, and roadmaps.
- [`campaigns/`](campaigns/): dated multi-change effort records.
- [`research/`](research/): exploratory designs and investigations.
- [`sessions/`](sessions/): dated verification or development-session notes.

## How to interpret status

Documentation in this repository serves several different purposes:

- User guides should describe commands and behavior available in the current
  checkout. A limitation should be called out next to the affected workflow.
- Design, roadmap, and plan documents describe intended work as well as shipped
  work. Check their status sections and then confirm behavior in code or tests.
- Campaign and session documents are evidence from a point in time. They may be
  useful history, but they are not a current compatibility guarantee.
- Generated pseudocode and LLM output are hypotheses. Neither is a substitute
  for binary-level evidence.

When two documents disagree, prefer current command help, current code and
tests, and the most specific maintained guide. Please file or fix the stale
document instead of silently relying on the contradiction.

## Search the documentation

Run searches from the repository root:

```bash
# Find a subsystem, command, or API.
rg -n "symbol extraction" docs python src

# Find explicit implementation-status language.
rg -n -i "implemented|in progress|planned|not implemented" docs

# Find documentation debt.
rg -n "TODO|FIXME" docs
```

## Documentation contribution rules

- Put task-oriented instructions near the user workflow and design rationale
  near the owning subsystem.
- State whether a feature is available, experimental, optional, or planned.
- Use real checked-in samples; do not invent output or APIs.
- Show repository commands with `uv run`, `uvx`, or `cargo` as appropriate.
- Test copy-paste commands from a clean checkout or clean environment before
  presenting them as supported.
- Link new pages from the nearest subsystem README and from this page when they
  introduce a top-level workflow.
- Avoid hard-coded test counts and other facts that go stale quickly.

Contributor commands and project-wide policy are maintained in
[`CLAUDE.md`](../CLAUDE.md) and [`AGENTS.md`](../AGENTS.md).
