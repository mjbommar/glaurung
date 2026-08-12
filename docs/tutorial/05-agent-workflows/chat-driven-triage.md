# §Y — Chat-driven triage

The `ask` command lets a model choose deterministic analysis tools and
synthesize their results. It is optional: Tiers 1–4 and `kickoff` work without
model credentials.

An agent response is a lead, not a verdict. Check the tool results, addresses,
and database rows behind material claims before using them in a report.

## Before making a provider call

The project default is `openai:gpt-5.4-mini`; OpenAI requests use the `flex`
service tier by default. You can override the model with `--model` or
`GLAURUNG_LLM_MODEL`. Do not silently switch providers merely to avoid a rate
or spend limit.

Supply credentials through your shell's secret mechanism or an untracked
`.env` file. Do not put a real key in documentation, command history, or a
tracked file. This shell pattern avoids echoing the value:

```bash
read -rsp "OpenAI API key: " OPENAI_API_KEY
export OPENAI_API_KEY
printf '\n'
```

Glaurung also recognizes `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, and
`GEMINI_API_KEY` when an explicitly selected model uses those providers. Check
provider availability without printing credentials:

```bash
uv run python - <<'PY'
from glaurung.llm.config import get_config

config = get_config()
print("model:", config.default_model)
print("service tier:", config.openai_service_tier)
print("providers configured:", config.available_models())
PY
```

Model calls can incur charges and transmit prompts plus binary-derived tool
output to the selected provider. Use only samples and case data you are
authorized to disclose under that provider's terms.

## Ask one bounded question

The positional argument is the binary. Questions use `-a/--ask`:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"

uv run glaurung ask "$BIN" --route -a \
  "Summarize the suspicious strings and cite the tool observations you used." \
  --show-routing \
  --show-tools \
  --max-cost-usd 0.25 \
  --usage-log ./glaurung-usage.jsonl
```

`--route` uses deterministic keyword matching to select a focused set of 5–30
tools rather than registering all 163. `--show-routing` prints the selected
intent, and `--show-tools` exposes calls and results for review. Use
`--all-tools` only when the focused router omitted a capability you actually
need.

`--max-cost-usd` is a circuit breaker for this invocation, not a price quote or
preauthorization. The tracker stops a subsequent agent call after recorded
spend exceeds the limit; provider accounting can lag. `--usage-log` writes one
JSONL record per model call. Its default location is under
`~/.cache/glaurung/usage/`; passing `-` disables file logging while retaining
in-memory accounting.

The documentation gate verifies the command shape and CLI options but does not
spend provider credits or bless a particular natural-language response. Model
versions, routing, tool selection, and response wording can all change.

## Know which state is persistent

The standalone `ask` uses an in-memory knowledge base. It can analyze
the binary and show tool calls, but its KB changes and generic tool evidence do
not persist to a `.glaurung` project after the process exits.

For an operator-guided session with durable project state, create a project and
use the REPL:

```bash
DB="demo.glaurung"

uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung repl "$BIN" --db "$DB"
```

Then, at the REPL prompt:

```text
ask summarize the suspicious strings and the functions that reference them
g 0x1160
d
n reviewed_main
ask reassess the current function using the persisted name and call sites
q
```

The REPL reuses the persistent project, so deterministic tools wrapped by the
evidence layer can append `evidence_log` rows and manual edits are saved. Its
`ask` shorthand does not expose standalone CLI flags such as `--route` or
`--max-cost-usd`; use standalone `ask` when those controls are mandatory.

## Ask questions that can be checked

Prefer questions with a scope and an evidence requirement:

- “List strings referenced by functions that call `connect`; include addresses
  and distinguish direct observations from inference.”
- “Does function `0x1140` behave like a TLS handler? Give evidence for and
  against the hypothesis.”
- “Suggest a name for `0x1140` from its body and callers; do not modify the
  project.”

Avoid requests for unsupported attribution, exploitability, or intent. A
suspicious domain-shaped string is not proof of network use; a dangerous API
import is not proof that a vulnerable path is reachable.

## Failure and review checklist

If a run fails or looks weak:

1. confirm the selected provider is configured without printing its key;
2. rerun `uv run glaurung ask --help` to check the current interface;
3. narrow the question and lower analysis budgets where appropriate;
4. inspect `--show-routing`, `--show-tools`, and the usage log;
5. reproduce key facts with deterministic CLI or SQLite queries; and
6. treat timeout, budget exhaustion, or a partial response as incomplete—not a
   negative finding.

Never paste a model answer into a case report without preserving the binary
hash, Glaurung revision, model name, question, relevant tool output, and your
independent validation.

Next: [§Z — Evidence and citations](evidence-and-citations.md).
