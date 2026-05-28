# Windows Analysis Config

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
- `pdb-cache-dir`
- `symbol-cache-dir`
- `symbol-server`
- `corpus-manifest`

Hyphenated YAML keys and Python-style underscore keys are both accepted.

The current end-to-end Windows regression flow is:

```bash
uv run glaurung windows bootstrap-project-facts \
  --pe-path tests/fixtures/msvc-pdb/ntoskrnl.exe \
  --project-path .glaurung/windows-regression/ntoskrnl.glaurung \
  --pdb-cache-dir tests/fixtures/msvc-pdb \
  --force-reindex

uv run glaurung view tests/fixtures/msvc-pdb/ntoskrnl.exe \
  --project .glaurung/windows-regression/ntoskrnl.glaurung \
  --pdb-cache tests/fixtures/msvc-pdb \
  --pane pseudo 0x140685720
```

The bootstrap step now imports PDB facts first, scans direct PE `call rel32`
xrefs independently of full CFG recovery, records confidence-ranked function
boundaries from PDB/`.pdata`/call targets, and only then runs the more expensive
callgraph, data-xref, CFG, dominance, and branch-condition passes.
