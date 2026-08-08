# `glaurung ask` reference

`ask` sends natural-language questions about one binary to an LLM-backed
analysis agent. The agent can select Glaurung's deterministic tools, then
synthesize their results. Use it for bounded synthesis and hypothesis review;
use direct CLI commands for exact lookups and reproducible automation.

Model output is not binary-level proof. Verify consequential claims against
tool output, disassembly, project data, or runtime behavior.

## Prerequisites and data handling

The project default model is `openai:gpt-5.4-mini`, with OpenAI's `flex`
service tier. Configure the selected provider as described in the
[development setup guide](../development/setup.md#runtime-configuration).
Never commit API keys or paste them into examples.

An invocation can send the question and binary-derived context or tool results
to the provider, and it can incur charges. Do not analyze material you are not
authorized to disclose under the provider's terms.

Confirm the installed interface before scripting it:

```bash
uv run glaurung ask --help
```

## Basic forms

Set a binary once for the examples:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
```

Ask one question with `-a/--ask`:

```bash
uv run glaurung ask "$BIN" --route -a \
  "What behavior should I verify first? Distinguish observation from inference."
```

Ask related questions in one shared invocation:

```bash
uv run glaurung ask "$BIN" --route --multiple \
  "Which functions are most central?" \
  "Which strings do those functions reference?"
```

Read non-empty questions, one per line, from standard input:

```bash
printf '%s\n' \
  "Is packer detection positive?" \
  "Which imports deserve review?" |
  uv run glaurung ask "$BIN" --route --stdin
```

Run the five built-in malware-triage questions:

```bash
uv run glaurung ask "$BIN" --route --quick
```

Start an ephemeral interactive session:

```bash
uv run glaurung ask "$BIN" --interactive
```

Type `exit`, `quit`, or `q` to leave interactive mode.

Exactly one question-input mode can be selected: `--ask`, `--multiple`,
`--interactive`, or `--stdin`. `--quick` supplies its own fixed question set and
takes precedence in the current implementation.

## Route and inspect tools

```bash
uv run glaurung ask "$BIN" --route --show-routing --show-tools -a \
  "Find suspicious strings and the functions that reference them."
```

- `--route` uses deterministic keywords from the first question to choose a
  focused set of 5–30 tools from the full 163-tool registry.
- `--show-routing` prints the selected intent and a tool-subset summary.
- `--all-tools` disables focused routing and overrides `--route`.
- `--show-tools` includes captured tool calls in the formatted result. It is a
  review aid, not a guarantee that every internal helper appears.
- `--show-plan` reports iteration, confidence, and termination metadata. It
  does not expose provider chain-of-thought.

For `--multiple`, routing is selected from the first question and reused.
Separate unrelated questions into separate invocations so each can be routed
appropriately.

## Strategy and analysis budgets

`--strategy` accepts:

- `auto` (default): choose a strategy for the question;
- `single`: one analysis pass; or
- `iterative`: refinement up to the configured limits.

The related controls are:

| Option | Current default | Purpose |
| --- | ---: | --- |
| `--max-iterations` | 5 | Iterative refinement limit |
| `--min-confidence` | 0.7 | Iterative confidence threshold |
| `--timeout` | 120 seconds | Agent execution time limit |
| `--max-functions` | 5 | Functions available to bounded analysis |
| `--max-instructions` | 50,000 | Instruction budget |
| `--disasm-window` | 4,096 bytes | Maximum disassembly window |
| `--max-read-bytes` | 10,485,760 | Triage read limit |
| `--max-file-size` | 104,857,600 | Accepted binary-size limit |

Confidence is agent metadata, not a calibrated probability of correctness.
Timeout or budget exhaustion means the analysis is incomplete, not that the
requested behavior is absent.

## Model cost controls

```bash
uv run glaurung ask "$BIN" --route -a "Summarize the entry path." \
  --max-cost-usd 0.25 \
  --usage-log ./glaurung-usage.jsonl
```

`--max-cost-usd` is a circuit breaker for the invocation. It stops a subsequent
agent call after tracked cost exceeds the limit; it is not a provider quote,
reservation, or guarantee against accounting lag.

`--usage-log PATH` writes one JSONL record per model call. Without the flag,
records go under `~/.cache/glaurung/usage/`. Pass `--usage-log -` to disable
file logging while keeping in-memory accounting.

Override the model only deliberately:

```bash
uv run glaurung ask "$BIN" --route -a "Summarize the entry path." \
  --model openai:gpt-5.4-mini
```

The global `GLAURUNG_LLM_MODEL` and `GLAURUNG_OPENAI_SERVICE_TIER` variables
provide defaults; a command-line `--model` takes precedence where supported.

## Output formats

The default output format is `plain`. Select `rich`, `json`, or `jsonl` with
`--format`; `--json` is an alias for `--format json`:

```bash
uv run glaurung ask "$BIN" --route -a "Summarize the file." --format json
```

`--no-color` forces plain formatting, `--quiet` suppresses progress output, and
`--verbose` includes traceback detail on outer failures. JSONL is a record
format, not token streaming; results are formatted after analysis completes.

For automation, validate the parsed result rather than grepping prose. The
current command converts some per-question exceptions into an
`"Analysis failed: ..."` result and can still exit successfully after the outer
workflow completes. Treat that answer, missing output, timeout, or an absent
findings file as failure in your own gate.

## Structured vulnerability findings

`ask` can run a separate structured findings pass after the ordinary Q&A pass:

```bash
uv run glaurung ask "$BIN" --route -a \
  "Perform a bounded first-pass vulnerability review." \
  --findings-json ./findings.json \
  --max-cost-usd 1.00
```

`--findings-json PATH` writes a `FindingsReport`; `-` writes it to standard
output. This pass uses its own fixed vulnerability-discovery prompt, then
resolves cited references and critiques the evidence for each finding.

Current execution still requires an ordinary question source, even though the
structured pass has its own prompt. Supply `-a`, `--multiple`, `--stdin`,
`--interactive`, or `--quick`.

For a per-CWE-family sweep:

```bash
uv run glaurung ask "$BIN" --route -a "Seed a vulnerability review." \
  --cwe-sweep \
  --cwe-sweep-applies userland \
  --findings-json ./findings.json \
  --max-cost-usd 5.00
```

- `--cwe-sweep` performs one structured pass per selected CWE family and is
  substantially more expensive than one broad pass.
- `--cwe-sweep-applies` filters the catalog to `any`, `userland`, or `kernel`.
- `--skip-critique` omits the extra critique call per finding, but the
  cite-or-discard verifier still runs.
- File-backed sweeps preserve completed partial reports beside the final output
  after a crash, signal, or cost-budget abort.

Do not promote a structured finding merely because it passed schema validation.
Review evidence support, reachability, controls, and reproducibility separately.

## Persistence boundary

Standalone `ask` uses an in-memory knowledge base. Multiple questions within
one invocation share that state, but generic KB changes and evidence rows are
not saved when the process exits. `--usage-log` persists model accounting only;
it is not a project database.

Use a persistent REPL when you need durable names, comments, types, and wrapped
tool evidence:

```bash
DB="analysis.glaurung"

uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung repl "$BIN" --db "$DB"
```

The REPL's `ask` shorthand reuses that project, but it does not expose the
standalone command's routing and cost flags. See the
[agent-workflow tutorial](../tutorial/05-agent-workflows/chat-driven-triage.md)
and [evidence guide](../tutorial/05-agent-workflows/evidence-and-citations.md)
for the operational distinction.

## Exit behavior and failure handling

- `0`: the outer command completed and emitted results; inspect each result for
  embedded analysis errors.
- `1`: input validation or the outer analysis workflow failed.
- `130`: the command handled a keyboard interrupt at the outer level.

Before relying on an answer, preserve the binary hash, Glaurung revision,
selected model, exact question, tool output, usage record, and independent
validation. Do not infer “not present” from a partial or failed model run.
