# Packer configuration

`TriageConfig.packers` controls the packer scan used by the Python triage API.
It does not configure the standalone `glaurung detect-packer` command, and it
does not replace the API's overall file/read limits.

## Fields and defaults

- `scan_limit` (default `524288`): maximum leading bytes inspected for packer
  signatures and heuristics.
- `upx_detection_weight` (default `0.6`): confidence contribution for UPX
  signatures and section names.
- `upx_version_weight` (default `0.2`): additional contribution for a
  recognized UPX version string.
- `packer_signal_weight` (default `0.30`): contribution of generic packed-file
  signals.

Weights contribute to a heuristic score. Changing them does not turn the
detector into a proof of packing, unpackability, or maliciousness.

## Tested Python example

Use `from glaurung import triage` so the configuration and analysis functions
come from the same public native module:

```python
from pathlib import Path

from glaurung import triage

sample = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/"
    "hello-gcc-O2"
)

config = triage.TriageConfig()
config.packers.scan_limit = 256 * 1024
config.packers.upx_detection_weight = 0.7
config.packers.upx_version_weight = 0.25
config.packers.packer_signal_weight = 0.35

artifact = triage.analyze_path(
    str(sample),
    max_read_bytes=4 * 1024 * 1024,
    max_file_size=100 * 1024 * 1024,
    config=config,
)

for match in artifact.packers or []:
    print(match.name, match.confidence)
```

`analyze_bytes(data, config=config)` supports the same configuration object.
Keep the `TriageConfig` import and the analyze function on the public
`glaurung.triage` surface; do not mix private native and compatibility-wrapper
types.

The CLI currently exposes read, file-size, recursion, string, and output flags,
but not individual packer weights. Use the Python API for per-run weight
changes, or the default configuration for CLI triage.

For the separate fast verdict and its exit-status semantics, see
[Binary triage — Packer-only check](README.md#packer-only-check).
