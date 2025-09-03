Packer Configuration

Overview
- Controls packer detection scanning bounds and weighting of individual packer signals during triage. Exposed to Python via `TriageConfig.packers` and used by `triage.analyze_bytes` / `triage.analyze_path` when an optional config is supplied.

Fields
- scan_limit: Maximum bytes scanned for packer signatures and heuristics. Keeps packer scans fast on large files. Default: 524_288 (512 KiB).
- upx_detection_weight: Weight applied when UPX signatures/section names are present. Higher values increase confidence of a “UPX” match.
- upx_version_weight: Weight applied when a specific UPX version string is identified. Reinforces detection when present.
- packer_signal_weight: Overall contribution of packer signals to triage confidence. Useful to tune how strongly packer hits influence final verdicts.

Python Usage
- Override packer detection limits and weights at runtime by creating a `TriageConfig`, adjusting `packers`, and passing it to `analyze_bytes` or `analyze_path`.

Example
```python
from glaurung import triage as g

cfg = g.TriageConfig()
cfg.packers.scan_limit = 256 * 1024       # 256 KiB
cfg.packers.upx_detection_weight = 0.7    # emphasize UPX hits
cfg.packers.upx_version_weight = 0.25
cfg.packers.packer_signal_weight = 0.35

art = g.analyze_path("/path/to/sample.exe", config=cfg)
print([p.name for p in (art.packers or [])])
```

Notes
- If no `config` is provided, built-in defaults are used.
- `scan_limit` bounds the bytes considered during detection only; overall read limits are still enforced by I/O settings.
