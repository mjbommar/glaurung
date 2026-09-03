# Glaurung documentation

> **Kind:** guide · **Status:** maintained

Glaurung is a pre-1.0 reverse-engineering framework with a Rust analysis core,
Python bindings, a command-line interface, persistent project databases, and
optional LLM-assisted workflows.

The tree is organized by **kind of document**, not by subsystem: guides tell you
how to do something, references are fact tables, architecture describes how the
code is built, decisions record why, design holds proposals for work not yet
done, and `history/` is dated evidence that is never guidance. Every file says
which it is on its third line.

Decompiler output is still experimental. Treat pseudocode as an analysis aid and
verify important conclusions against disassembly and runtime behavior.

## Start here

1. [Install Glaurung from source](tutorial/01-getting-started/install.md).
2. [Analyze the first checked-in binary](tutorial/01-getting-started/first-binary.md).
3. Take the [CLI tour](tutorial/01-getting-started/cli-tour.md) or
   [REPL tour](tutorial/01-getting-started/repl-tour.md).
4. Continue through the [complete tutorial track](tutorial/README.md).

For a shorter overview and a Python API example, use the
[repository README](../README.md). Prerequisites, build modes, configuration,
and troubleshooting live in the [development setup guide](development/setup.md).

## Find a workflow

| Goal | Read this |
| --- | --- |
| Inspect an unfamiliar binary quickly | [Triage guide](guides/triage.md) and [first binary](tutorial/01-getting-started/first-binary.md) |
| Learn the CLI command surface | [CLI tour](tutorial/01-getting-started/cli-tour.md) and the [CLI reference](reference/cli.md) |
| Navigate or annotate a project database | [REPL tour](tutorial/01-getting-started/repl-tour.md) and [analyst workflows](guides/analyst-workflows.md) |
| Make an annotation reach the decompiled output | [The annotation loop](guides/annotation-loop.md) — `rename`/`comment`/`label`/`proto`, and what `--db` changes on each surface |
| Work with names, types, xrefs, stack frames, or patches | [Daily basics](tutorial/02-daily-basics/) |
| Understand project data and provenance | [Persistent projects](architecture/persistent-project.md), [data model](architecture/data-model.md), and the [`set_by` ladder](reference/provenance.md) |
| Read or test pseudocode output | [Decompiler output format](reference/decompiler-output-format.md), the [pass list](reference/decompiler-passes.md), and [decompiler testing](development/decompiler-testing.md) |
| Understand how the decompiler is built | [Decompiler pipeline](architecture/decompiler-pipeline.md) and the [architecture index](architecture/README.md) |
| Analyze PE files or Windows software | [Windows analysis](guides/windows-analysis.md) and [Windows configuration](reference/windows-analysis-config.md) |
| Work with Java, JVM bytecode, or archives | [Java and JVM analysis](guides/java-jvm.md) |
| Detect packers or compare binaries | [Packer configuration](reference/packer-config.md) and [similarity analysis](reference/similarity.md) |
| Tell which functions changed between two builds | [Structural function identity](reference/function-identity-structural.md) — the L1 control-flow invariants `glaurung diff` ranks by |
| Recognise an exact known build of a known function | [WARP function GUIDs](reference/function-identity-warp.md) — the L0 rung: a UUIDv5 over relocation-masked basic-block bytes |
| Name library functions in a stripped binary | [FLIRT-style signature libraries](reference/function-signature-libraries.md) — how the masked-byte library is built from `.a` relocations, and what it matches |
| Harvest distro packages for signature libraries over the network | [Signature sources: the `base` matrix](reference/signature-sources.md) — Debian, Ubuntu and Alpine fetch mechanics, network manners, and the cross-release overlap table |
| Get, verify or publish a signature set | [Signature-set distribution](reference/signature-distribution.md) — the signed content-addressed manifest, `glaurung sigs`, the cache, and how a maintainer cuts a release |
| Recognise the same function across compilers and optimisation levels | [The Canonical Function Representation](reference/function-identity-cfr.md) — the L2 rung: a Weisfeiler-Lehman feature multiset over the SSA dataflow graph |
| Recognise the same function across optimisation levels by what it computes | [Value fingerprints](reference/function-identity-values.md) — the L3 rung: bounded execution over the LLIR, weighted Jaccard over the values harvested |
| Improve any matcher's candidate lists using the call graph | [Context re-ranking](reference/function-identity-rerank.md) — the RevDecode Viterbi decode over a layered candidate graph, and what each of its terms is measured to be worth |
| Measure how well a function-identity scheme retrieves | [Identity measurement](development/identity-measurement.md) — the XO/XC/XM protocol, its filters, and measured AUC/MRR10 for every scheme on the identity ladder |
| Fetch or locate an external research corpus | [External corpora](development/corpora.md) — URLs, sizes, and checksums for the corpora the measurement lanes read |
| Use an LLM-backed command | [`ask` command](guides/ask.md), [LLM subsystem](architecture/llm-subsystem.md), and [runtime configuration](development/setup.md#runtime-configuration) |
| See where we stand against IDA Pro, Ghidra, and angr | [Competitive position](architecture/competitive-position.md) |
| Reproduce a guided investigation | [Walkthroughs](tutorial/03-walkthroughs/) and [demos](guides/demos/README.md) |
| Run source examples | [Executable examples](../examples/README.md) |
| Use or rebuild the sample corpus | [Sample corpus](reference/sample-corpus.md) and [`samples/README.md`](../samples/README.md) |
| Run the right test gate before pushing | [Testing gates](development/testing-gates.md) |
| Avoid a trap this project has already hit | [Traps](development/traps.md) |
| Contribute code | [Contributor policy](../CLAUDE.md) and [development guidelines](development/guidelines.md) |
| Contribute documentation | [Contributing docs](development/contributing-docs.md) |

## Documentation by directory

### [`tutorial/`](tutorial/README.md) — learn by doing

A progressive track over real checked-in samples, from installation through
daily analysis, walkthroughs, recipes, and agent workflows. Every chapter's
commands are executed and byte-compared against `_fixtures/` by
`scripts/verify_tutorial.py`, so the prose cannot drift from the CLI unnoticed.

### [`guides/`](guides/) — task-oriented, outside the tutorial track

[Triage](guides/triage.md), [analyst workflows](guides/analyst-workflows.md),
[the annotation loop](guides/annotation-loop.md), [`ask`](guides/ask.md),
[Windows analysis](guides/windows-analysis.md),
[Java and JVM](guides/java-jvm.md),
[parsers and formats](guides/parsers-and-formats.md), and longer
[demo scenarios](guides/demos/README.md).

### [`reference/`](reference/) — fact tables

[CLI surface](reference/cli.md),
[environment variables](reference/environment-variables.md),
[cargo features](reference/cargo-features.md),
[the `set_by` provenance ladder](reference/provenance.md),
[decompiler passes](reference/decompiler-passes.md),
[decompiler output format](reference/decompiler-output-format.md),
[disassembly](reference/disassembly.md),
[language detection](reference/language-detection.md),
[packer configuration](reference/packer-config.md),
[similarity](reference/similarity.md),
[structural function identity](reference/function-identity-structural.md),
[WARP function GUIDs](reference/function-identity-warp.md),
[FLIRT-style signature libraries](reference/function-signature-libraries.md),
[signature sources](reference/signature-sources.md),
[signature-set distribution](reference/signature-distribution.md),
[the Canonical Function Representation](reference/function-identity-cfr.md),
[value fingerprints](reference/function-identity-values.md),
[context re-ranking](reference/function-identity-rerank.md),
[Windows configuration](reference/windows-analysis-config.md) and
[API type sync](reference/windows-api-type-sync.md),
[the IOC validator](reference/ioc-validator.md),
[the REPL keymap](reference/repl-keymap.md),
[the sample corpus](reference/sample-corpus.md), plus
[binary formats](reference/formats/README.md) and
[syscall tables](reference/syscalls/README.md).

Several of these are generated from the code they describe and carry
`**Status:** generated`. Edit the generator, not the page —
[contributing-docs.md](development/contributing-docs.md) names each one.

### [`architecture/`](architecture/README.md) — how the code is built

The [crate and package map](architecture/README.md), the
[decompiler pipeline](architecture/decompiler-pipeline.md), the
[register model](architecture/register-model.md),
[x86 flags](architecture/x86-flags.md), the
[data model](architecture/data-model.md),
[persistent projects](architecture/persistent-project.md), the
[execution engine](architecture/execution-engine.md),
[solver backends](architecture/solver-backends.md),
[IOCTL taint](architecture/ioctl-taint.md), the
[LLM subsystem](architecture/llm-subsystem.md), and our
[competitive position](architecture/competitive-position.md). These describe
what exists; a claim here should be checkable against `src/`.

### [`decisions/`](decisions/README.md) — why, and what lost

Architecture decision records for the execution engine and the solver work.
Rejected alternatives are the part that cannot be recovered from the code, so
this is where they live.

### [`design/`](design/README.md) — proposals for work not yet built

Live proposals, and the [open questions](design/open-questions.md) each with the
experiment that would settle it. A document here describes intended behavior,
not shipped behavior.

### [`development/`](development/) — contributing

[Setup](development/setup.md), [guidelines](development/guidelines.md),
[testing gates](development/testing-gates.md), [traps](development/traps.md),
[contributing docs](development/contributing-docs.md),
[decompiler testing](development/decompiler-testing.md), the
[parity backlog](development/decompiler-parity-backlog.md), the
[curriculum corpus](development/decompiler-curriculum-corpus.md), the
[external corpora](development/corpora.md) the measurement lanes read, the
[identity measurement protocol](development/identity-measurement.md), the live
[roadmap set](development/roadmap/README.md), and the
[test estate](development/test-estate/README.md) work.

### [`test-inventory/`](test-inventory/README.md) — what the suite covers

Generated inventory of every test and what reaches it, with a
[triage of the unreachable entries](test-inventory/unreachable-triage.md).

### [`history/`](history/README.md) — dated record, never guidance

Session diaries, superseded plans, defect registers, and design records, each
declaring the date it was true. Read it for how something came to be; do not
follow it as instruction. The index says what superseded each entry.

## How to interpret status

Every live document declares two things in its header.

**Kind** says what the document is for:

| Kind | Read it as |
| --- | --- |
| `guide` | instructions for doing something now |
| `reference` | a fact table about the current code |
| `architecture` | a description of how the code is built |
| `decision` | one decision and the alternatives it beat |
| `design` | a proposal; the behavior may not exist |
| `plan` | a work order with phases and gates |
| `record` | dated evidence, in `history/` only |

**Status** says how current it is: `maintained` means someone keeps it true;
`generated` means a tool in `tools/` produces it and hand edits are lost;
`proposed` means it describes intended rather than shipped work.

Generated pseudocode and LLM output are hypotheses in either case, and neither
substitutes for binary-level evidence. When two documents disagree, prefer
current command help, current code and tests, and the most specific maintained
guide — then fix the stale document rather than relying on the contradiction.

## Search the documentation

Run searches from the repository root:

```bash
rg -n "symbol extraction" docs python src   # a subsystem, command, or API
rg -n "^> \*\*Kind:\*\* design" docs        # everything still only proposed
rg -n "TODO|FIXME" docs                     # documentation debt
```

## Documentation contribution rules

The full version, including the generators and how the tutorial harness works,
is in [contributing-docs.md](development/contributing-docs.md). The short form:

- Declare a `Kind:` and a `Status:` on line 3, and put the file in the
  directory for that kind.
- Put task-oriented instructions near the user workflow and design rationale
  near the owning subsystem.
- Use real checked-in samples; do not invent output or APIs. Show commands with
  `uv run`, `uvx`, or `cargo`, and test them from a clean checkout.
- A number in a live document comes with the command that produced it and the
  commit it was run at, or it is left out.
- No dated narrative in a live document: an incident becomes one durable rule
  plus an entry in [traps.md](development/traps.md) or `history/`.
- No dates in live filenames, and no data or executable scripts under `docs/`.
- Link a new page from the nearest index and from this page when it introduces
  a top-level workflow.

Project-wide contributor policy is in [`CLAUDE.md`](../CLAUDE.md); other agent
tooling is pointed there by [`AGENTS.md`](../AGENTS.md).
