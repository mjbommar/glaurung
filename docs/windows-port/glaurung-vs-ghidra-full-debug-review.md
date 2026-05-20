# Glaurung vs Ghidra 30-File Debug Review

Date: 2026-05-19

Scope: all 30 vendored Windows regression fixtures under
`samples/binaries/platforms/windows/vendor/realworld/`: the original 10
small fixtures plus 20 high-volume Windows system and Windows Update
vendor DLL/SYS/EXE fixtures.

Primary artifacts:

- `docs/windows-port/glaurung_vs_ghidra_vendor_windows_30.json`
- `docs/windows-port/glaurung_vs_ghidra_vendor_windows_30.md`
- `docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json`
- `docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json`
- `docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.md`

The older 10-file
`docs/windows-port/glaurung_vs_ghidra_vendor_windows.json` remains the
small stable parity baseline. This review treats Ghidra as the reference
analyst view and asks whether each disagreement is a real missed
entrypoint, a useful local label, or an over-promoted Glaurung candidate.

## Global Read

| Metric | Value |
| --- | ---: |
| Files reviewed | 30 |
| Glaurung functions | 98,070 |
| Ghidra internal functions | 71,505 |
| Ghidra-only starts | 1,072 |
| Glaurung-only starts | 27,637 |
| Address recall vs Ghidra | 98.50% |
| Ghidra timeouts | 0 |
| Glaurung truncated files | 0 |
| `.pdata` entries parsed | 63,857 |
| `.pdata` function starts accepted | 52,407 |
| `.pdata` seeds inserted | 42,062 |
| Chained unwind records rejected | 11,450 |
| Data-reference code-pointer candidates | 132,799 |
| Data-reference function seeds | 760 |
| Tiny-stub seeds | 36,780 |
| Raw call-target seeds | 2,270 |
| Raw call-target body-split seeds | 666 |
| Code labels preserved | 633,243 |

The original 10-file suite still looks strong: exact parity remains for
`win10-vwififlt.sys`, `win10-audmigplugin.dll`, and
`windows-update-SurfacePenBleLcAddrAdaptationDriver.sys`; the remaining
original-file gaps are narrow and mostly tiny helpers or local labels.

The expanded 20-file suite changes the story. Glaurung's recall is high,
but precision is not yet Ghidra-like on larger C++/COM/vendor runtimes.
The dominant new issue is not missing `.pdata`; it is confidence and
boundary classification. We are often discovering useful code addresses,
but promoting too many of them to top-level functions.

## Gap Closure Follow-Up: Adjustor Tiny-Stub Gate

The first precision fix keeps the `mov/lea rcx, [rdx+imm]; jmp rel32`
adjustor-stub recognizer, but no longer promotes those stubs from the
blind executable scan unless the candidate VA is also seen as a PE
code-pointer target. That preserves the high-value Dism/Realtek
adjustor thunks while removing the thousands of unreferenced adjustor
starts that dominated the NPU/XRT false-positive set.

A small recall follow-up also promotes padded `48 ff 25 rel32` import
thunks. Ghidra functionizes these seven-byte no-`.pdata` thunks in the
deployment DLLs; Glaurung already classified the shape but the scanner
was previously rejecting the REX-prefixed form.

Post-fix metrics against the same cached Ghidra 30-file output:

| Metric | Before | After |
| --- | ---: | ---: |
| Glaurung functions | 98,070 | 73,580 |
| Ghidra internal functions | 71,505 | 71,505 |
| Ghidra-only starts | 1,072 | 1,041 |
| Glaurung-only starts | 27,637 | 3,116 |
| Address recall vs Ghidra | 98.50% | 98.54% |

Largest improvements:

- `windows-update-intel-npu-npu_d3d12_umd.dll`: extras `15,775 -> 107`,
  misses `30 -> 32`.
- `windows-update-amd-xilinx-xrt_coreutil.dll`: extras `7,381 -> 963`,
  misses unchanged at `8`.
- `windows-update-amd-xilinx-xrt_core.dll`: extras `2,005 -> 572`,
  misses `17 -> 16`.
- `windows-update-intel-npu-npu_level_zero_umd.dll`: extras `804 -> 139`,
  misses `107 -> 112`.
- `windows-update-intel-npu-ze_loader.dll`: extras `461 -> 96`,
  misses unchanged at `240`.
- `win10-dismcore.dll`: misses `9 -> 2`.
- `win10-wdscore.dll`: misses `9 -> 2`.
- `win11-wdscore.dll`: misses `16 -> 9`.

## Main Debug Findings

### 1. Tiny starts are the biggest recall gap

Of the 1,072 Ghidra-only starts, 799 have bodies of 32 bytes or less.
Only 55 are Ghidra thunks. This means the missing side is mostly small
helpers, scalar return helpers, import/IAT thunks, and short jump
wrappers rather than large ordinary functions.

The obvious fix is not just "scan more bytes." We already scan too much
on the extra side. The next rule needs to be provenance-aware: promote
tiny starts when there is a strong boundary/xref/table reason, otherwise
keep them as labels.

### 2. Tiny-stub over-promotion dominates false positives

Glaurung-only entries by seed class:

| Seed class | Extra starts |
| --- | ---: |
| `tiny_stub` | 26,422 |
| `tail_call` | 528 |
| `data_ref` | 346 |
| `prologue` | 240 |
| `vtable` | 60 |
| `trusted_pdata` | 37 |
| `direct_call` | 2 |
| `thunk` | 2 |

This is the largest gap exposed by the 30-file suite. The `tiny_stub`
scanner is useful on the original small suite, but on NPU/XRT/D3D
runtime files it promotes thousands of short instruction sequences that
Ghidra leaves as labels or block interiors.

### 3. COM/vtable-heavy DLLs reveal body over-merge

`webservices.dll`, `dismapi.dll`, `wdscore.dll`, `netsetupapi.dll`, and
some vendor DLLs have many Ghidra starts that Glaurung reports as
inside an existing Glaurung function, often a vtable- or `.pdata`-seeded
owner. This is not a pure seed-discovery problem. It is a function body
splitting problem: once we seed one wrapper/method, decoding can absorb
adjacent tiny methods or local helpers.

### 4. SIMD start handling needs context

Earlier SIMD suppression was necessary to stop false functions that
began on `0f 10` continuations. The NPU files show the other side:
Ghidra sometimes functionizes real no-`.pdata` starts that begin with
SIMD loads. The rule should not be "SIMD head means never a function";
it should require xref/table/boundary evidence before promotion.

### 5. Data-reference starts need stricter boundary gates

The data-reference scanner fixed the SurfacePen callback-table miss, but
the 30-file run exposes false positives in large drivers. The clearest
case is `NETwtw10.sys`, where Glaurung promotes adjacent data-ref
targets at `0x1400041a6`, `0x1400041a7`, `0x1400041a8`, and
`0x1400041a9`; the bytes are still in a `cc` padding run. Those should
be code labels at most, not functions.

## Per-File Review

### `win10-vwififlt.sys`

Verdict: exact parity.

- Glaurung/Ghidra: 141/141.
- Missing: 0.
- Extra: 0.

Debug read: clean driver baseline. `.pdata`, exports, tiny stubs, and a
few prologue seeds recover exactly what Ghidra functionizes.

### `win10-audmigplugin.dll`

Verdict: exact parity with useful non-`.pdata` coverage.

- Glaurung/Ghidra: 224/224.
- Missing: 0.
- Extra: 0.
- Non-`.pdata` seeds include vtable, direct-call, and data-ref starts.

Debug read: this remains the best proof that broader seed classes can
match Ghidra when the boundaries are clean.

### `win11-SyncInfrastructureps.dll`

Verdict: one harmless local-label promotion.

- Glaurung/Ghidra: 78/77.
- Missing: 0.
- Extra: `0x1800018a8`, `tiny_stub`, bytes `33 c0 c3 cc...`.

Debug read: Glaurung promotes a shared zero-return epilogue that Ghidra
keeps as a local label. This is useful address knowledge, but it should
not count as a strict function in parity mode.

### `win11-acledit.dll`

Verdict: same local-label policy difference.

- Glaurung/Ghidra: 40/39.
- Missing: 0.
- Extra: `0x180001688`, `tiny_stub`, bytes `33 c0 c3 cc...`.

Debug read: another zero-return epilogue label. Keep it as a label,
demote it in strict function views.

### `win8-pciidex.sys`

Verdict: one real tiny helper miss plus one suspicious data-ref extra.

- Glaurung/Ghidra: 176/174.
- Missing: `0x1c008`, Ghidra body 3, bytes `33 c0 c3 cc...`, section
  `INIT`.
- Extras: `0x13758` tail-call target, `0x13ca0` data-ref target,
  `0x18788` tiny helper-like block.

Debug read: `0x1c008` is a real missed helper. The suspicious extra is
`0x13ca0`; the local bytes look like UTF-16 digits
`30 00 31 00 32 00...`, so executable-head gating needs to reject this
data-ref promotion.

### `windows-update-keysink.exe`

Verdict: two real no-`.pdata` scalar/tail helper misses.

- Glaurung/Ghidra: 499/490.
- Missing: `0x140007c4c`, body 13, bytes
  `33 d2 33 c9 44 8d 42 01 e9...`.
- Missing: `0x140013260`, body 8, bytes `45 33 c0 e9 00 00 00 00...`.
- Extras: mostly vtable wrappers, tail-call block entries, and tiny
  local helpers.

Debug read: these are exactly the tiny no-`.pdata` starts we want to
learn from Ghidra. They should be seeded from xref/tail-call evidence,
not from broad blind scanning.

### `windows-update-SurfacePenBleLcAddrAdaptationDriver.sys`

Verdict: exact parity; former callback-table gap is fixed.

- Glaurung/Ghidra: 775/775.
- Missing: 0.
- Extra: 0.
- Data-ref seeds: 14.

Debug read: this remains the strongest positive regression. Ghidra's
callback/table function starts are recovered from code-pointer table
evidence without producing extra starts.

### `sqfs-amd-clinfo.exe`

Verdict: high recall, moderate extra label/candidate noise.

- Glaurung/Ghidra: 981/932.
- Missing: `0x140018608`, body 28.
- Missing: `0x140027b0c`, body 405.
- Extras: 51, mostly tail-call, tiny-stub, vtable, and some `.pdata`
  policy differences.

Debug read: the 405-byte miss is still worth manual attention because
it is not just a tiny helper. The extra side is not catastrophic, but it
shows that tail-call and vtable starts need confidence labels.

### `sqfs-intel-DptfParticipantDisplayService.exe`

Verdict: no misses, small extra-label set.

- Glaurung/Ghidra: 354/342.
- Missing: 0.
- Extra: 12, mostly tiny epilogues, tail-call targets, and one data-ref.

Debug read: good for bug-hunting. Extra starts are explainable labels or
helpers; Ghidra recall is complete.

### `sqfs-intel-DptfDevGen.sys`

Verdict: one real `INIT` function miss.

- Glaurung/Ghidra: 146/140.
- Missing: `0x140015000`, Ghidra body 46, section `INIT`.
- Extras: 7, mostly epilogue labels and prologue/tiny policy starts.

Debug read: seed discovery should consider non-`.text` executable
sections like `INIT` more carefully. This looks like a genuine function
start, not a label-only disagreement.

### `win10-dismapi.dll`

Verdict: good recall, but many Ghidra tiny/thunk starts still missing.

- Glaurung/Ghidra: 4,965/4,975.
- Missing: 33; 17 are <=32 bytes; 7 are thunks.
- Extra: 23, mostly tiny epilogue labels and tail-call labels.
- Sample missing: `0x18001a470`, bytes
  `48 8d 0d ... e9 ...`; `0x180080afe`, bytes
  `48 8b 8a 40 00 00 00 48 ff 25...`.

Debug read: `dismapi` is primarily a tiny-wrapper/thunk problem. The
extras are less concerning than the missed Ghidra starts because most
extras already look like local labels.

### `win10-dismcore.dll`

Verdict: missing import/IAT thunks.

- Glaurung/Ghidra: 963/953.
- Missing: 9; all 9 are <=32 bytes; 7 are thunks.
- Extra: 19, mostly tiny epilogues.
- Sample missing: `0x18001f590`, bytes `48 ff 25 ...`, Ghidra thunk.

Debug read: add a dedicated PE import-thunk scanner for no-`.pdata`
`jmp [rip+imm32]` and related patterns. These are cheap, high-value
Ghidra parity wins.

### `win10-webservices.dll`

Verdict: worst Windows system DLL; strong signal for body splitting work.

- Glaurung/Ghidra: 4,395/4,518.
- Missing: 145; 84 are <=32 bytes.
- Extra: 22.
- Sample misses are often inside a vtable-seeded owner such as
  `0x180001f40`.

Debug read: this is not just a missing-seed problem. Ghidra splits many
small methods/helpers that Glaurung keeps inside a larger vtable-rooted
body. We need a boundary pass that can split at strong internal starts
instead of only adding more seeds.

### `win10-netsetupapi.dll`

Verdict: one missing thunk; otherwise good.

- Glaurung/Ghidra: 578/549.
- Missing: `0x1800033d0`, body 7, Ghidra thunk, bytes `48 ff 25...`.
- Extra: 30, mostly tail-call and tiny-label promotions.

Debug read: import thunk recovery should close the only recall miss.
The extra set should be demoted in strict mode but is useful as label
coverage.

### `win10-wdscore.dll`

Verdict: same deployment-DLL thunk/helper pattern.

- Glaurung/Ghidra: 1,002/996.
- Missing: 9; all <=32 bytes; 7 thunks.
- Extra: 15, mostly epilogue labels.

Debug read: another clear input for the no-`.pdata` thunk/helper rule.
The paired Win11 file below shows the same family behavior.

### `win11-dismapi.dll`

Verdict: more missing tiny methods than Win10.

- Glaurung/Ghidra: 5,566/5,606.
- Missing: 64; 47 are <=32 bytes; 7 are thunks.
- Extra: 24, mostly label promotions.
- Sample misses include `33 c0 c3` helpers and small wrappers inside
  a broad trusted `.pdata` owner.

Debug read: the Win11 binary makes the body-splitting issue more
obvious. Some starts are true tiny helpers; others are Ghidra method
boundaries inside a body that Glaurung currently absorbs.

### `win11-webservices.dll`

Verdict: largest OS-side recall gap.

- Glaurung/Ghidra: 4,954/5,097.
- Missing: 191; 123 are <=32 bytes; 14 are thunks.
- Extra: 48, including 20 data-ref promotions.

Debug read: this is the Win11 version of the `webservices` issue. The
main missing class is Ghidra-recognized method/helper starts inside
vtable-rooted functions. It also shows that data-ref promotion needs
stricter confidence scoring on COM-heavy binaries.

### `win11-netsetupapi.dll`

Verdict: small but representative boundary gap.

- Glaurung/Ghidra: 600/578.
- Missing: 8; all <=32 bytes.
- Extra: 30.

Debug read: Ghidra splits short address-materialization helpers and
wrappers that Glaurung sees inside a vtable owner. Treat this as another
body-boundary regression case rather than a raw parser failure.

### `windows-update-intel-npu-ze_loader.dll`

Verdict: worst recall in the suite and a SIMD/context test case.

- Glaurung/Ghidra: 2,879/2,658.
- Missing: 240; 226 are <=32 bytes.
- Extra: 461; 412 are `tiny_stub`.
- Sample missing: `0x180033b20`, bytes
  `0f 10 02 49 8b c9 66 48 0f 7e...`.

Debug read: Ghidra treats many short SIMD-headed starts as functions.
Our SIMD false-positive suppression helped the old suite, but this file
shows the rule needs context. A SIMD head can be a real function if
there is xref/table/boundary evidence.

### `windows-update-intel-npu-npu_level_zero_umd.dll`

Verdict: high recall but large tiny-stub over-promotion.

- Glaurung/Ghidra: 4,682/3,985.
- Missing: 107; 68 are <=32 bytes.
- Extra: 804; 712 are `tiny_stub`.

Debug read: this file is mostly a confidence problem. Glaurung finds
lots of short code starts, but Ghidra does not elevate most of them to
functions. The fix is to demote weak tiny-stub starts unless they have
strong provenance.

### `windows-update-intel-npu-npu_d3d12_umd.dll`

Verdict: recall is good, precision is unusable without confidence tiers.

- Glaurung/Ghidra: 18,656/2,911.
- Missing: 30; 23 are <=32 bytes.
- Extra: 15,775; 15,700 are `tiny_stub`.

Debug read: this is the strongest evidence that `tiny_stub` cannot mean
"function" by default. Glaurung's current output would bury a human
analyst in false function starts even though it actually recalls most
Ghidra functions. This file should drive the next precision work.

### `windows-update-intel-ipf-ipfcore.dll`

Verdict: good recall, noisy tiny/prologue extras.

- Glaurung/Ghidra: 2,856/2,322.
- Missing: 8.
- Extra: 542; 476 are `tiny_stub`, 39 are `prologue`.

Debug read: small number of real misses, large number of weak promoted
starts. The prologue scanner also needs stricter "function boundary"
evidence on this family.

### `windows-update-intel-audio-IntcSST.sys`

Verdict: strong driver result.

- Glaurung/Ghidra: 1,828/1,822.
- Missing: 0.
- Extra: 6, all labels/prologue/tiny policy starts.

Debug read: good bug-hunting target. The driver is large enough to be
interesting and Glaurung has complete Ghidra recall with low noise.

### `windows-update-intel-audio-MultiChannelWoV.dll`

Verdict: moderate missing tiny-helper gap, modest noise.

- Glaurung/Ghidra: 2,716/2,722.
- Missing: 43; 40 are <=32 bytes.
- Extra: 37.

Debug read: most misses are tiny wrappers or data-ref candidates that
did not cross the promotion threshold. This is a balanced target for
testing improved tiny-start seeding without reopening a huge false
positive class.

### `windows-update-realtek-RtkApi64U.dll`

Verdict: good recall, small mixed extra set.

- Glaurung/Ghidra: 2,137/2,114.
- Missing: 9; 7 are <=32 bytes.
- Extra: 32.

Debug read: a useful application/vendor DLL case. Misses include short
data-ref or unseeded wrappers; extras are mostly epilogue/block labels
and a few prologue starts.

### `windows-update-realtek-RtkAudUService64.exe`

Verdict: significant recall gap with low extra noise.

- Glaurung/Ghidra: 2,347/2,435.
- Missing: 101; 80 are <=32 bytes.
- Extra: 13.

Debug read: unlike the NPU/XRT files, this is an under-discovery case.
Many Ghidra starts are tiny wrappers inside a broad trusted `.pdata`
owner. This should be a primary body-splitting regression target.

### `windows-update-amd-xilinx-xrt_core.dll`

Verdict: high recall, large tiny-stub over-promotion.

- Glaurung/Ghidra: 5,143/3,155.
- Missing: 17.
- Extra: 2,005; 1,789 are `tiny_stub`.

Debug read: the file has many genuinely useful short helpers, but
Ghidra does not call most of Glaurung's tiny starts functions. Use this
as a precision target for tiny stubs, tail calls, and data-ref starts.

### `windows-update-amd-xilinx-xrt_coreutil.dll`

Verdict: excellent recall, very poor precision.

- Glaurung/Ghidra: 15,108/7,735.
- Missing: 8.
- Extra: 7,381; 6,983 are `tiny_stub`.

Debug read: this mirrors `npu_d3d12_umd.dll`: Glaurung recalls Ghidra
almost completely, but the function list is too noisy for analyst use.
This file should be part of any precision gating benchmark.

### `windows-update-intel-wifi-NETwtw10.sys`

Verdict: strong large-driver result with one clear data-ref false
positive class.

- Glaurung/Ghidra: 12,253/12,017.
- Missing: 27; 15 are <=32 bytes.
- Extra: 263; 153 `tiny_stub`, 73 `data_ref`, 27 `prologue`.
- Suspicious extras: `0x1400041a6`, `0x1400041a7`, `0x1400041a8`,
  `0x1400041a9`, all starting in `cc` padding.

Debug read: this is a good stress target because it is large, important,
and not wildly noisy. The data-ref padding promotions are concrete
false positives to fix with alignment and boundary checks.

### `win11-wdscore.dll`

Verdict: paired Win11 deployment-DLL helper/thunk gap.

- Glaurung/Ghidra: 1,028/1,023.
- Missing: 16; all are <=32 bytes; 7 are thunks.
- Extra: 21.

Debug read: this completes the 30-file suite and reinforces the
deployment-DLL pattern: missing Ghidra starts are tiny wrappers, import
thunks, and short helpers inside broader owners.

## Priorities From This Review

1. Split "function" from "code label" and "candidate start" in the
   public output. The current all-functions list is too noisy on
   NPU/XRT/D3D workloads even when recall is good.
2. Retune `tiny_stub` promotion. Require strong provenance such as
   direct xref, table membership, export/import thunk shape, padding
   boundary, or `.pdata` relation. Weak tiny starts should become labels
   or low-confidence candidates.
3. Add a PE import-thunk scanner for no-`.pdata` thunk shapes such as
   `48 ff 25 rel32` and closely related IAT jump wrappers.
4. Add a function-body split pass. When a strong internal start appears
   inside a vtable/`.pdata` owner, split instead of absorbing adjacent
   Ghidra-like functions into one broad body.
5. Make SIMD suppression evidence-based. SIMD-headed starts should be
   rejected when they look like interior continuations, but accepted when
   xrefs/table/boundaries make them real starts.
6. Harden data-ref code-pointer promotion with target alignment,
   executable-section, padding-run, table-consistency, and preceding-byte
   gates. `NETwtw10.sys` has concrete padding-run false positives.
7. Report parity by seed class: recall and precision for `.pdata`,
   `tiny_stub`, `data_ref`, `tail_call`, `prologue`, and `vtable` should
   be first-class dashboard metrics.
8. Keep two suites: the original 10-file fast parity baseline and the
   30-file stress suite. The stress suite is where precision regressions
   show up, but it is too heavy to treat as the only quick check.

## Bottom Line

For defensive bug hunting, Glaurung is now useful at broad PE function
surface recovery and catches many Ghidra-recognized starts, including
the former SurfacePen data-reference gap. It is not yet a Ghidra-grade
functionization layer for large Windows C++/driver/vendor binaries. The
next quality jump is confidence separation and boundary splitting, not
more blind discovery.
