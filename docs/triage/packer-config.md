# Packer configuration

`TriageConfig.packers` controls packer-signature scan bounds and confidence
weights for the Python triage API. These settings do not change file-size or
overall read limits.

## Fields and defaults

| Field | Default | Meaning |
|---|---:|---|
| `scan_limit` | `524288` | Maximum leading bytes inspected for packer signatures and heuristics |
| `upx_detection_weight` | `0.6` | Confidence weight for UPX signatures and section names |
| `upx_version_weight` | `0.2` | Additional weight for a recognized UPX version string |
| `packer_signal_weight` | `0.30` | Contribution of generic packed-file signals |

## Python example

```python
from glaurung import triage

config = triage.TriageConfig()
config.packers.scan_limit = 256 * 1024
config.packers.upx_detection_weight = 0.7
config.packers.upx_version_weight = 0.25
config.packers.packer_signal_weight = 0.35

artifact = triage.analyze_path("/path/to/sample.exe", config=config)
for match in artifact.packers or []:
    print(match.name, match.confidence)
```

Pass the complete `TriageConfig` to `analyze_path` or `analyze_bytes`. With no
config argument, the built-in defaults above are used. `scan_limit` only bounds
packer detection; use the analysis function's read/file-size arguments for I/O
limits.
