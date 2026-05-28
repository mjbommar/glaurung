# Glaurung vs Ghidra Windows Regression Review

Date: 2026-05-19

Scope: the 10 vendored Windows PE regression fixtures in
`samples/binaries/platforms/windows/vendor/realworld/`, using the
regenerated dashboard in
`docs/windows-port/glaurung_vs_ghidra_vendor_windows.json`.

## Topline

| Metric | Count |
| --- | ---: |
| Glaurung functions | 3414 |
| Ghidra internal functions | 3334 |
| Ghidra-only entry points | 6 |
| Glaurung-only entry points | 86 |
| PE code-pointer candidates | 3303 |
| PE data-reference function seeds | 20 |
| `.pdata` body-overlap starts honored | 10 |
| Code labels preserved separately | 32978 |
| SIMD-like Glaurung-only starts | 0 |

The main recall gap from the earlier review is closed. The
SurfacePen driver had eight Ghidra-only callback/helper starts that
were present as 32-bit RVA entries in `.rdata`; Glaurung now reports
those as code-pointer facts and promotes the high-confidence table
targets as `data_ref` function starts. SurfacePen is exact against
Ghidra at the function-entry level: 775 vs 775, with zero missing and
zero extras.

The remaining gap is no longer broad function discovery. It is mostly
policy:

- Should a branch target, shared epilogue, or switch case be a function
  or a code label?
- Which no-`.pdata` scalar call targets are safe to promote?
- How should a broad decoded body be split when it swallows a tiny
  helper in another section?
- Which data-pointer candidates are strong enough to seed functions
  instead of staying as low-confidence facts?

## Current Capability Changes

The current run exercises these new primitives:

- PE code-pointer scanner over readable non-executable sections,
  including both 64-bit VA slots and 32-bit RVA slots.
- Conservative function promotion for 32-bit RVA tables: substantial
  boundary-aligned tables can seed `data_ref` starts, while isolated
  chance values remain facts only.
- Function-start taxonomy in `seed_kind_counts`, including
  `trusted_pdata`, `export`, `direct_call`, `direct_call_body_split`,
  `data_ref`, `tiny_stub`, `thunk`, `prologue`, `vtable`, and
  `entrypoint`.
- First-class code labels in `code_labels`, currently split into
  `block_label`, `epilogue_label`, and SIMD-like block labels.
- `.pdata` starts are no longer suppressed merely because a speculative
  decoded body already covers the address.
- `glaurung windows diff-ghidra ...` can explain missing and extra
  starts with bytes, section, containing function, labels, provenance,
  code-pointer refs, and suspected cause.

## Per-File Status

| File | Glaurung | Ghidra | Missing | Extra | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `win10-vwififlt.sys` | 141 | 141 | 0 | 0 | Exact parity. |
| `win10-audmigplugin.dll` | 224 | 224 | 0 | 0 | Exact parity, including thunk count. |
| `win11-SyncInfrastructureps.dll` | 78 | 77 | 0 | 1 | One shared `xor eax,eax; ret` block that Ghidra keeps as `LAB_*`. |
| `win11-acledit.dll` | 40 | 39 | 0 | 1 | Same shared zero-return label pattern. |
| `win8-pciidex.sys` | 176 | 174 | 1 | 3 | One tiny helper at `0x1c008` is still swallowed by a broad decoded body. |
| `windows-update-keysink.exe` | 499 | 490 | 2 | 11 | Remaining misses are no-`.pdata` direct-call/tail-jump helpers. |
| `windows-update-SurfacePenBleLcAddrAdaptationDriver.sys` | 775 | 775 | 0 | 0 | Former callback-table gap is closed by 32-bit RVA code-pointer seeding. |
| `sqfs-amd-clinfo.exe` | 981 | 932 | 2 | 51 | Stress case; extras are mostly label/function policy, misses are unseeded scalar starts. |
| `sqfs-intel-DptfParticipantDisplayService.exe` | 354 | 342 | 0 | 12 | No recall misses; extras are policy labels/stubs. |
| `sqfs-intel-DptfDevGen.sys` | 146 | 140 | 1 | 7 | One unseeded no-`.pdata` `INIT` start remains. |

## Remaining Ghidra-Only Starts

| File | VA | Bytes | Current cause |
| --- | --- | --- | --- |
| `win8-pciidex.sys` | `0x1c008` | `33 c0 c3 cc ...` | Tiny helper inside an existing broad Glaurung function body; should become a label or force a split. |
| `windows-update-keysink.exe` | `0x140007c4c` | `33 d2 33 c9 44 8d 42 01 e9 ...` | No-`.pdata` scalar helper reached by call; raw-call acceptance remains too narrow. |
| `windows-update-keysink.exe` | `0x140013260` | `45 33 c0 e9 00 00 00 00 ...` | Tiny tail-jump helper; should be a low-confidence call-target start. |
| `sqfs-amd-clinfo.exe` | `0x140018608` | `8b 05 26 34 02 00 44 8b c2 ...` | Unseeded scalar start with no current `.pdata` or code-pointer provenance. |
| `sqfs-amd-clinfo.exe` | `0x140027b0c` | `ba 30 00 00 00 66 3b ca ...` | Large Ghidra function start not currently seeded by `.pdata`, code pointers, or calls. |
| `sqfs-intel-DptfDevGen.sys` | `0x140015000` | `48 8b 05 29 c0 ff ff ...` | No-`.pdata` `INIT` start without current provenance. |

## Interpretation

The PE code-pointer work is worth keeping conservative. The scanner now
finds thousands of executable-looking data slots, but only 20 become
function seeds across the corpus. That is the right default for an
automated defensive layer: isolated 32-bit values are useful facts, not
automatic functions. The SurfacePen table proves the high-confidence
path works when a real callback table is present.

The 86 Glaurung-only starts are less concerning than the old raw count
made them look. The new `code_labels` fact stream preserves the useful
addresses that Ghidra would name as `LAB_*`, `caseD_*`, or shared
epilogues without forcing them all to be top-level functions. The next
quality pass should consume those labels in reports and rules instead
of treating every Glaurung-only address as a discovery error.

## Next Debugging Targets

1. Add a direct-call no-`.pdata` scalar helper classifier for the two
   `keysink.exe` misses.
2. Split or cap broad decoded bodies when a tiny helper lands in a
   separate section, as in `win8-pciidex.sys:0x1c008`.
3. Investigate the two `sqfs-amd-clinfo.exe` misses with the new
   `windows diff-ghidra` command and decide whether they need another
   seed source or should remain Ghidra-only policy differences.
4. Use code labels in downstream reports so shared epilogues and switch
   cases remain available to bug-hunting scripts without inflating
   function counts.
5. Extend code-pointer provenance with relocation information when the
   relocation table is available, so smaller callback arrays can be
   promoted safely without reopening the chance-RVA false-positive class.
