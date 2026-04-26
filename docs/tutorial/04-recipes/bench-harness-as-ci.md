# §W — Recipe: bench harness as CI

Glaurung's bench harness (`python -m glaurung.bench`) produces a
deterministic JSON scorecard for a fixed set of sample binaries.
Use case: "I just refactored the structurer — did anything
regress on the standard corpus?"

## The standard CI matrix

```bash
python -m glaurung.bench --ci-matrix --output baseline.json --quiet
```

Scores 10 binaries covering language coverage (C / C++ / Fortran /
clang+gcc / debug+stripped + polymorphic C++):

```bash
head -30 baseline.md   # the markdown summary, written alongside JSON
```

```markdown
# Glaurung benchmark — 2026-04-26T...
_glaurung HEAD: `9335f28...`_

## Aggregate
- Binaries scored: **10** (errored: 0)
- Functions discovered: **103** (named: 94)
- Multi-chunk functions: **2** (cold orphans: 0)
- Decompiled OK: **103** (failed: 0)
- DWARF types: **139** (structs with fields: 15)
- Stack-frame slots: **754** (across 68 functions)
- Type-KB lift: **0** propagated, **95** auto-struct candidates

## Rates
- Symbol-name resolution (avg): **90.0%**
- Decompile success (avg): **100.0%**
- Language detection match: **80.0%**

## Per binary
| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |
|---|---:|---:|---:|---:|---:|---:|
| hello-c-gcc-O2 | 7 | 7 | 0 | 0 | 7/7 | 111 |
| hello-cpp-g++-O2 | 11 | 11 | 1 | 0 | 11/11 | 169 |
| hello-gcc-O2 | 11 | 11 | 1 | 0 | 11/11 | 163 |
| ... |
```

12 metrics across the matrix. Save `baseline.json` as the "before"
snapshot.

## Use it in CI

Two-step pattern:

```bash
# In CI: score the current commit.
python -m glaurung.bench --ci-matrix --output current.json --quiet

# Compare to the previous baseline.
python -c "
import json
prev = json.load(open('baseline.json'))
curr = json.load(open('current.json'))
prev_total = sum(s['discovery'].get('total', 0) for s in prev['scorecards'])
curr_total = sum(s['discovery'].get('total', 0) for s in curr['scorecards'])
if curr_total < prev_total:
    raise SystemExit(f'regression: {curr_total} funcs vs {prev_total} baseline')
print(f'OK: {curr_total} funcs (prev: {prev_total})')
"
```

The bench is deterministic — same commit, same bytes, same
output. Diffs in the scorecard mean the analysis changed.

## The packed-binary tier

```bash
python -m glaurung.bench --packed-matrix --output packed.json --quiet
```

Scores 10 UPX-packed samples. The aggregate line:

```
- Packed binaries: **10** (by family: UPX×10)
```

If that line ever drops below 10, the packer detector has
regressed. Wire it the same way as `--ci-matrix`.

## What the JSON looks like

```bash
jq '.scorecards[0]' baseline.json
```

```json
{
  "binary_path": "samples/.../hello-c-gcc-O2",
  "metadata_path": "samples/.../metadata/hello-c-gcc-O2.json",
  "compiler": "gcc",
  "flags": "-O2",
  "platform": "linux",
  "architecture": "x86_64",
  "triage": { ... },
  "discovery": { "total": 7, "named_from_symbols": 7, ... },
  "callgraph": { ... },
  "decompile": { "attempted": 7, "succeeded": 7, ... },
  "debug_info": { ... },
  "stack_frame": { ... },
  "type_kb": { ... },
  "packer": { "is_packed": false, ... },
  "elapsed_ms": { ... }
}
```

Pipeline-friendly. Use `jq` to extract any metric.

## Custom matrix

```bash
python -m glaurung.bench \
  --binary path/to/sample1.elf \
  --binary path/to/sample2.elf \
  --root samples/binaries/platforms/linux/amd64/some-subdir \
  --output custom.json
```

`--binary` adds individual files; `--root` recursively adds every
binary under a directory. Use this for project-specific sample
sets.

## Per-binary timing budget

```bash
jq '[.scorecards[].elapsed_ms.triage_ms] | add / length' baseline.json
```

Average triage time across the matrix. Useful for "did this
change make something slower?"

## See also

- [`reference/sample-corpus.md`](../reference/sample-corpus.md) —
  full list of CI matrix binaries.
- [§R `06-upx-packed-binary.md`](../03-walkthroughs/06-upx-packed-binary.md) —
  the packed-matrix in context.
- [#159](../../architecture/IDA_GHIDRA_PARITY.md) — bench harness
  implementation.
