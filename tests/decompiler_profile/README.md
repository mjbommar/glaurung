# Decompiler performance baseline

`baseline-2026-08-08.json` is a clean-tree measurement of Glaurung revision
`4b6838f91ab8bac96aa979d93c3ee0677435b625`. It records cold and warm function
times, process RSS, every native object-parse count, shared pipeline stage times,
binary hashes, and output hashes. Native allocation counts are explicitly marked
unavailable.

Three cases require the official DecBench sample-set evaluation kit. Set its root
to the directory containing `binaries/bin_039.elf` and rerun from the repository:

```bash
GLAURUNG_DECBENCH_KIT=/path/to/decbench-evalkit-sample-set
.venv/bin/python tools/decompiler_profile.py \
  --case 'small-x86=samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0@0x2549' \
  --case "stripped-x86=${GLAURUNG_DECBENCH_KIT}/binaries/bin_039.elf@0x8680" \
  --case "large-stripped-x86=${GLAURUNG_DECBENCH_KIT}/binaries/bin_093.elf@0x253e0" \
  --case "arm32=${GLAURUNG_DECBENCH_KIT}/binaries/bin_110.elf@0x80002f8" \
  --case 'debug-heavy-rust=samples/binaries/platforms/linux/amd64/export/rust/hello-rust-debug@0x22830' \
  --path-alias "${GLAURUNG_DECBENCH_KIT}=decbench-sample-set" \
  --warm-runs 3 \
  --output /tmp/glaurung-decompiler-profile.json
```

Do not compare timings across hosts as if they were a same-machine regression.
For a code comparison, run both revisions on the same idle host, retain function
coverage and output hashes, and reject any speedup caused by missing output or a
new timeout.
