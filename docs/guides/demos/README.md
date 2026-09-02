# Glaurung deterministic demos

> **Kind:** guide · **Status:** maintained

These demos are short, reproducible investigations over binaries checked into
the repository. They show current CLI workflows and link to captured output
from `scripts/verify_tutorial.py`. They are not synthesized chat transcripts
and do not require an LLM provider.

| Demo | Core question | Verifier chapter |
| --- | --- | --- |
| [Malware-style triage](demo-1-malware-triage.md) | Which observations support suspicious-string triage without overstating behavior? | `03-c2-demo` |
| [Vulnerability review](demo-2-vulnerability-hunting.md) | How do source, xrefs, disassembly, and pseudocode jointly support a known fixture bug? | `03-vulnparse` |
| [Patch analysis](demo-3-patch-analysis.md) | Which recovered function changed across two related binaries? | `04-diff` |

Run all three evidence recipes from the repository root:

```bash
uv run python scripts/verify_tutorial.py --check \
  --chapter 03-c2-demo \
  --chapter 03-vulnparse \
  --chapter 04-diff
```

The verifier uses real checked-in binaries, requires each documented command's
expected exit status, and compares normalized output with fixtures. Timing,
repository paths, and similarly volatile fields may be normalized; substantive
analysis output is not replaced with invented prose.

For optional agent synthesis after the deterministic work, continue to the
[agent-workflow tutorial](../../tutorial/05-agent-workflows/chat-driven-triage.md).
Provider responses, cost, and privacy are outside the deterministic demo gate.
