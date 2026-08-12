# Binary triage

`glaurung triage` performs a bounded, deterministic first pass over an input
file. It does not execute the file and does not require an LLM provider. The
result can include format and architecture verdicts, entropy, strings and IOC
shapes, symbol/security metadata, similarity hashes, packer signals,
containers, overlays, parser status, budgets, and diagnostic errors.

Triage is orientation, not a malware verdict. A suspicious import or
domain-shaped string is an observation that needs reachability and behavior
analysis before it supports a security conclusion.

## Quick start

From the repository root:

```bash
SAMPLE="samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"

uv run glaurung triage "$SAMPLE"
uv run glaurung triage "$SAMPLE" --json
```

The default `plain` format gives a compact summary. `--json` is an alias for
`--format json` and preserves the full structured artifact. Use JSON for
automation; do not parse the human-readable summary.

The tutorial verifier captures the current sample result in
[`../tutorial/_fixtures/01-cli-tour/triage.out`](../tutorial/_fixtures/01-cli-tour/triage.out).

## What the result means

- `hints`: MIME and extension sniffing clues; hints are not parser confirmation.
- `verdicts`: candidate format, architecture, width, endianness, confidence,
  and contributing signals.
- `entropy` / `entropy_analysis`: whole-file and window entropy plus heuristic
  classification.
- `strings`: bounded decoded strings, language/script metadata, and IOC-shaped
  matches.
- `symbols`: imports, exports, libraries, stripping/debug state, and supported
  hardening flags.
- `similarity`: CTPH digest and PE imphash when applicable.
- `packers`: triage-level packer or packed-content signals.
- `containers`: bounded archive/container records and nested children when
  discovered.
- `overlay`: bytes detected after the format's official end, with bounded
  metadata.
- `parse_status`: structured parser success or a typed failure reason.
- `budgets`: reads, elapsed analysis time, recursion, limits, and limit-hit
  state.
- `errors`: truncation, mismatch, budget, and other nonfatal diagnostics.

Fields are format- and input-dependent. `null`, an empty collection, or no
verdict means “not produced by this pass,” not “proved absent.” Confidence is a
signal-weighted classifier score, not a calibrated probability of safety or
malice.

## Resource and recursion limits

```bash
uv run glaurung triage "$SAMPLE" --json \
  --max-read-bytes 4096 \
  --max-file-size 104857600 \
  --max-depth 1
```

| Option | Current default | Scope |
| --- | ---: | --- |
| `--max-read-bytes` | 10,485,760 | Analysis read budget |
| `--max-file-size` | 104,857,600 | Maximum accepted file size |
| `--max-depth` | 1 | Container recursion limit |

When a limit is reached, inspect both `budgets` and `errors`. Partial metadata
can still be useful, but it must not be interpreted as a complete negative
result. Internal stages may account reads cumulatively, so `bytes_read` can be
greater than `limit_bytes` when the limit diagnostic is emitted.

For container input, nested records are available in JSON under `containers`:

```bash
CONTAINER="samples/adversarial/embedded/nested_zip_in_zip.zip"
uv run glaurung triage "$CONTAINER" --json --max-depth 3
```

## String controls

```bash
uv run glaurung triage "$SAMPLE" --json \
  --str-min-len 6 \
  --str-max-samples 80 \
  --str-max-lang-detect 100 \
  --str-max-classify 200 \
  --str-max-ioc-per-string 8
```

- `--str-lang` / `--no-str-lang` enable or disable language detection.
- `--str-classify` / `--no-str-classify` enable or disable IOC-shape
  classification.
- `--strings-only-lang` filters the JSON/JSONL string list to entries with a
  detected language; it does not change extraction.

Language, script, and IOC classifiers are heuristic. A match can be a false
positive, especially in symbol tables, archive metadata, and random-looking
data. Follow candidate strings into xrefs and call paths.

## Output formats

```bash
uv run glaurung triage "$SAMPLE" --format plain
uv run glaurung triage "$SAMPLE" --format rich
uv run glaurung triage "$SAMPLE" --format json
uv run glaurung triage "$SAMPLE" --format jsonl
```

- `plain` is the default compact summary.
- `rich` is an interactive presentation with heuristic risk panels; the risk
  display is not a finding or severity score.
- `json` serializes the complete native artifact and is the preferred machine
  contract.
- `jsonl` emits metadata, verdict, symbol, string, and container records. It is
  not streaming analysis.

Pin a Glaurung revision and validate the schema before using JSON or JSONL in a
release gate.

## Packer-only check

For the narrow “does the fast detector flag this as packed?” question:

```bash
uv run glaurung detect-packer "$SAMPLE"
uv run glaurung detect-packer samples/packed/hello-go.upx9
```

Plain output returns 0 for not packed and 1 for a positive packed verdict. JSON
and JSONL currently return 0 after serializing either verdict, so automation
must inspect `is_packed` in structured output. Exit 2 means path validation
failed.

Packer detection is heuristic. A positive signal can justify unpacking or a
different analysis strategy, but it does not establish maliciousness.

## Python API

Use the package's public triage module:

```python
from pathlib import Path

from glaurung import triage

sample = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/"
    "hello-gcc-O2"
)

artifact = triage.analyze_path(str(sample))
top = artifact.verdicts[0] if artifact.verdicts else None
print(top.format if top else "unknown")
print(artifact.budgets)

from_bytes = triage.analyze_bytes(sample.read_bytes())
assert from_bytes.size_bytes == sample.stat().st_size
```

Both functions accept string-analysis and read/recursion limits. `analyze_path`
also accepts the public native `TriageConfig` as `config=...`; see
[packer configuration](packer-config.md) for a tested example.

## Exit status

For `glaurung triage`:

- `0`: analysis completed, possibly with structured warnings or partial data;
- `2`: the path is missing, unreadable, or not a regular file, or argument
  parsing failed; and
- `3`: analysis raised an outer exception.

Always inspect `errors`, `budgets`, and `parse_status` after exit 0 when
completeness matters.

## Current CLI wiring gaps

The current parser advertises `--sim`, `--no-sim`, and `--tree`, but the command
does not pass those display preferences to `TriageFormatter`:

- `--no-sim` does not currently remove `similarity` from JSON; and
- `--tree` does not currently add a tree to plain output.

Use JSON and inspect `similarity` or nested `containers` directly. These flags
should not be used as automation controls until their wiring is covered by a
test.

## Related documentation

- [Packer configuration](packer-config.md)
- [Similarity hashing](similarity.md)
- [CLI tour](../tutorial/01-getting-started/cli-tour.md)
- [Packer walkthrough](../tutorial/03-walkthroughs/06-upx-packed-binary.md)

The other files in this directory are historical proposals and implementation
plans. Their status banners identify them as design records rather than current
operator contracts.
