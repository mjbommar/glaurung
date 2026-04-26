# §R — Walkthrough 6: UPX-packed binary

The anti-analysis chapter. We load a UPX-packed Go binary, watch
Glaurung's packer detector flag it (#187), see kickoff
short-circuit deeper analysis, and walk through the canonical
unpack → re-analyze workflow.

UPX (Ultimate Packer for eXecutables) is the most common packer
in the wild — used by both legitimate space-savers and a sizable
fraction of commodity malware. Recognising UPX-packed input
without wasting time on the packed body is the floor for any
serious malware-triage workflow.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/03-upx-packed/`](../_fixtures/03-upx-packed/).

## Sample

```bash
$ PACKED=samples/packed/hello-go.upx9
$ file $PACKED
```

```text
samples/packed/hello-go.upx9: ELF 64-bit LSB executable, x86-64,
version 1 (SYSV), statically linked, no section header
```

(Captured: [`_fixtures/03-upx-packed/file.out`](../_fixtures/03-upx-packed/file.out).)

Two giveaways even before any analysis:

- **statically linked** — the runtime loader can't see anything
  inside.
- **no section header** — UPX strips sections from the packed
  binary; only the program headers remain.

## Phase 1: Triage — packer detection (#187)

```bash
$ glaurung detect-packer $PACKED
```

```text
PACKED: UPX  (confidence 95%)
  indicator: UPX!
  overall entropy: 7.879 bits/byte
```

(Captured: [`_fixtures/03-upx-packed/detect-packer.out`](../_fixtures/03-upx-packed/detect-packer.out).)

The detector flags it as UPX with 95% confidence. The signals:

- **`UPX!` indicator string** — UPX writes its name into the
  unpacker stub. Any packer-hardened malware will obfuscate this
  signature; vanilla UPX leaves it visible.
- **overall entropy: 7.879 bits/byte** — UPX-packed binaries
  routinely run 7.8-7.95. Native unpacked code is typically
  4.5-6.0 (with rodata strings dragging it down).

If the indicator isn't present (custom-built UPX, rebranded
packers, UPX strings stripped) the entropy alone would still
flag it as suspicious — see #187's "generic high-entropy fallback"
in the implementation.

## Phase 2: Load (`kickoff`) — short-circuit on packed input

```bash
$ glaurung kickoff $PACKED --db packed.glaurung
```

```markdown
# Kickoff analysis — hello-go.upx9

⚠️  **PACKED**: UPX (confidence 95%)
  - indicator: `UPX!`

_binary detected as UPX; skipping deep analysis (re-run with skip_if_packed=False to override)_
```

(Captured: [`_fixtures/03-upx-packed/kickoff.out`](../_fixtures/03-upx-packed/kickoff.out).)

`kickoff` short-circuits. Why:

- The packer's stub is what's actually mapped — the analyst's
  target (the unpacked program) is encoded data inside the binary.
- Running function discovery / DWARF lift / type propagation on
  the stub wastes time and produces misleading output (the only
  function in the binary IS the unpacker).
- Better to fail loud and visible — print "PACKED: UPX" — than to
  silently produce a 0-named-function scorecard.

The override exists for when you *want* to look at the unpacker
itself (rare; most analysts unpack first).

## Phase 3: Unpack with the canonical tool

UPX is reversible — UPX itself ships an `-d` decompress flag:

```bash
upx -d $PACKED -o /tmp/hello-go-unpacked
```

```
                       Ultimate Packer for eXecutables
   Markus Oberhumer, Laszlo Molnar & John Reiser    [...]
File size         Ratio      Format      Name
--------------------   ------   -----------   -----------
1425560 <-    642520   45.07%   linux/amd64   hello-go-unpacked
```

You now have `/tmp/hello-go-unpacked` — the original binary the
attacker started with.

If `upx` isn't installed: `apt install upx` / `brew install upx` /
`pacman -S upx`. UPX is small, free, and ubiquitous.

> Note: A future Glaurung release will wrap this step as
> `glaurung unpack` ([#237 GAP](../../architecture/IDA_GHIDRA_PARITY.md))
> so the analyst doesn't need an external tool.

## Phase 4: Re-analyze the unpacked binary

```bash
glaurung kickoff /tmp/hello-go-unpacked --db unpacked.glaurung
```

This is the **same as §N** — a stripped Go binary. The kickoff now
runs the gopclntab walker (#212) and recovers the user package:

```
# Kickoff analysis — hello-go-unpacked
- format: **ELF**, arch: **x86_64**, size: **1425560** bytes
- ...
- name sources: gopclntab=1801
```

```bash
glaurung find unpacked.glaurung "main\.main$" --regex --kind function
```

```
function    0x4934e0        main.main  (set_by=gopclntab)
```

From here the workflow is identical to §N — find → view → xref →
annotate.

## What you've learned

The "packed binary" chapter is mostly meta-workflow, not new
commands:

1. **`glaurung detect-packer`** is the cheap first triage step.
   Run it on every fresh sample before kickoff.
2. **`glaurung kickoff` short-circuits** on packed input rather
   than producing misleading metrics. Read the warning; don't
   force-override unless you specifically want to look at the
   unpacker stub.
3. **Use the unpacker that the packer ships** (UPX has `-d`).
   Generic dynamic-unpack frameworks (e.g. `unipacker`, `qiling`)
   work for custom packers but are heavier than necessary for
   vanilla UPX.
4. **Re-run kickoff on the unpacked output** — the workflow is
   the same as for any non-packed binary of that format class.

## Bench-harness regression coverage (#213)

Glaurung's bench harness has a packed-binary tier. To run it:

```bash
python -m glaurung.bench --packed-matrix --output /tmp/packed.json
```

```markdown
- Binaries scored: **10** (errored: 0)
- Packed binaries: **10** (by family: UPX×10)

| binary | funcs | named | chunks>1 | ... | packer | entropy | ms |
|---|---:|---:|---:|---|---|---:|---:|
| hello-gfortran-O0.upx9 | 1 | 0 | 0 | ... | UPX | 7.17 | 96 |
| hello-gfortran-O1.upx9 | 1 | 0 | 0 | ... | UPX | 7.23 | 23 |
| ...                    |   |   |   |    |     |      |    |
```

Every UPX-packed sample in `samples/packed/` is detected as UPX
with entropy 7.17-7.89. If a future change to the detector misses
one of these, the bench harness flags it as a regression. See
[Tier 4 §W `bench-harness-as-ci.md`](../04-recipes/bench-harness-as-ci.md).

## Caveats / GAPs

- **`glaurung unpack`** is filed as
  [#237](../../architecture/IDA_GHIDRA_PARITY.md). Until then,
  `upx -d` is the canonical unpack step.
- **Packer detection v0** covers UPX / Themida / VMProtect /
  ASPack / MPRESS / PECompact / FSG / Petite / Enigma / Obsidium
  via signature match, plus a generic high-entropy fallback.
  Custom / re-branded variants may need signature additions.
- **Anti-debug / VM-detection / control-flow flattening** are
  out of scope for v0. Filed as part of #187 v2.

## What's next

- [§S `07-malware-c2-demo.md`](07-malware-c2-demo.md) — the
  flagship demo: a synthetic malware analog with C2 callbacks,
  hardcoded URLs / IPs, and the full kickoff → IOC scan →
  stack-frame retype → agent workflow.

→ [§S `07-malware-c2-demo.md`](07-malware-c2-demo.md)
