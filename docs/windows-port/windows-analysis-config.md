# Windows Analysis Config

> **Status: maintained operator guide.** CLI help and
> `python/glaurung/windows_config.py` are authoritative for accepted keys and
> precedence; the smoke workflow below uses a checked-in PE fixture.

`python/glaurung/windows_config.py` centralizes the Windows PE resource and
symbol defaults used by `cfg`, `decompile`, `view`, project xref indexing, and
`windows bootstrap-project-facts`.

Config resolution order:

1. Explicit `--analysis-config PATH`.
2. `$GLAURUNG_WINDOWS_ANALYSIS_CONFIG`.
3. `.glaurung/windows-analysis.yaml` when present.
4. Built-in defaults.

The checked-in project default is `.glaurung/windows-analysis.yaml`. It raises
read and analysis budgets high enough for large Windows system binaries such as
`ntoskrnl.exe`, while every CLI path still accepts narrower per-command
overrides for fast smoke tests.

Supported keys:

- `max-read-bytes`
- `max-file-size`
- `max-functions`
- `max-blocks`
- `max-instructions`
- `timeout-ms`
- `total-timeout-ms` (`0` disables the whole-analysis wall-clock ceiling)
- `pdb-cache-dir`
- `symbol-cache-dir`
- `symbol-server`
- `corpus-manifest`

Hyphenated YAML keys and Python-style underscore keys are both accepted.

The following bounded smoke test uses a PE that is checked into the repository.
It writes its project database to a new temporary directory:

```bash
WINDOWS_SMOKE_DIR=$(mktemp -d)
WINDOWS_SAMPLE=samples/binaries/platforms/windows/amd64/export/windows/x86_64/O2/hello-c-mingw64-O2.exe

uv run glaurung windows bootstrap-project-facts \
  --pe-path "$WINDOWS_SAMPLE" \
  --project-path "$WINDOWS_SMOKE_DIR/hello.glaurung" \
  --no-import-pdb-facts \
  --max-functions 128 \
  --max-blocks 10000 \
  --max-instructions 200000 \
  --timeout-ms 2000 \
  --force-reindex

uv run glaurung view "$WINDOWS_SMOKE_DIR/hello.glaurung" 0x1400079e0 \
  --binary "$WINDOWS_SAMPLE" \
  --pane pseudo
```

The Microsoft PE/PDB regression bytes are intentionally not committed. Before
using examples based on `tests/fixtures/msvc-pdb/ntoskrnl.exe`, populate and
verify that corpus as described in
[`../../tests/fixtures/msvc-pdb/README.md`](../../tests/fixtures/msvc-pdb/README.md).

Without `--no-import-pdb-facts`, the bootstrap step imports available PDB facts
first. It then scans direct PE `call rel32` xrefs independently of full CFG
recovery, records confidence-ranked function boundaries from PDB/`.pdata`/call
targets, and runs the more expensive callgraph, data-xref, CFG, dominance, and
branch-condition passes.
