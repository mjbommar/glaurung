# Focused decompiler output canaries

These seven cases are the named high-risk cells from the DecBench remediation
roadmap. The four official functions cover function contracts and large-CFG
behavior; the three local matrix cells cover known GED and byte-match regressions.
The local cells contain seven exported functions, so the baseline has eleven
function observations in total.

Each observation pins the real input binary, rendered-output hash and size,
signature, final output-health counters, definition violations, and the pass that
first introduced each final violation. The canary is intentionally sensitive:
an improvement changes the baseline and therefore requires explicit review.

The local binaries are rebuilt from pinned source hashes, compiler versions, and
flags. The official binaries come from the DecBench sample-set kit and are checked
against their pinned SHA-256 values. Run the complete check with:

```bash
GLAURUNG_DECBENCH_KIT=/path/to/decbench-evalkit-sample-set
.venv/bin/python tools/decompiler_output_canaries.py \
  tests/decompiler_output_canaries/manifest.json \
  --external-root "${GLAURUNG_DECBENCH_KIT}" \
  --check tests/decompiler_output_canaries/baseline.json \
  --output /tmp/glaurung-output-canaries-current.json
```

The command fails on an input hash, compiler, function set, output, or health
change and names the exact case, function, and field that moved. Review semantic
and score evidence before replacing the baseline; never refresh it merely to make
the gate pass.
