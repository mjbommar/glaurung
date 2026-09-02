# DecBench full-run failure taxonomy — 2026-08-31

> **Kind:** record · **Date:** 2026-09-01

This is the complete accounting of every function for which the pinned full
DecBench run did not emit a Glaurung body. It is an internal engineering
artifact, not a submission claim and not a corpus to tune against.

## Provenance and scope

| item | value |
|---|---|
| Glaurung revision under test | `7bc7353923cc659d3e970dbde8455b2b9b503a6d` |
| DecBench revision | `f76dae075d4d82004fb21132b3f15e43b680e179` |
| Dataset revision | `noelo-lab/decbench-dataset@e5eb576d66ee36793b800a4dd45e291e0add4472` |
| Configuration | full: 803 binaries, 94,575 manifest functions |
| Run root | `~/.cache/glaurung/decbench-submission/20260831T180316Z` |
| Primary evidence | 803 `checkpoints/decompile/*.json` records and stderr logs |

The repository has moved since this measurement. Do not attribute these counts
to current `master` without rerunning; this document is a pinned classification
and a source of independent fixture requirements.

## Executive result

| outcome | functions | share of manifest |
|---|---:|---:|
| Body returned | 94,358 | 99.7705% |
| No body returned | 217 | 0.2295% |
| Total | 94,575 | 100% |

The 217 are not crashes, command failures, JSON failures, timeouts, or C/TOML
conversion errors. All 803 commands returned zero and all checkpoints are
terminal with status `ok`. There were zero parse errors, conversion errors,
duplicate manifest addresses, duplicate returned addresses, and returned
addresses outside the request.

There are exactly two observed mechanisms:

| class | count | observed evidence |
|---|---:|---|
| F1 — name did not resolve to a requested VA | 186 | Function is in `unresolved_symbols`; it was never placed in the `--vas` target file. |
| F2 — requested VA returned no body | 31 | Address was requested, the command returned zero, and stderr says `no body recovered` for that VA. |

F1 is primarily a manifest-to-image identity problem. F2 reached the
decompiler and is a body-recovery problem. Calling all 217 “decompiler
failures” sends work to the wrong subsystem.

Further tracing proves two subcauses:

| subclass | count | proof |
|---|---:|---|
| F1a — i386 stdcall decoration not normalized | 33 | The original PE symbol map contains `_name@N` at a nonzero code address, while the resolver tries only `name` and `_name`. Canonicalizing leading underscores and a terminal `@N` matches 33/186 F1 rows exactly. |
| F1b — import-only identity, no local body | 63 | Canonical name exists in the PE import table, but not as a local function symbol. These cannot yield an ordinary local function body. |
| F1c — manifest-only identity | 88 | Name is in the full-config binary manifest but absent from the published source-CFG map, exposed function map, full object function table, and import table. |
| F1d — source-CFG-only identity | 2 | gzip `__printf__` has a one-node source CFG but no binary function/import identity. |
| F2a — Cortex-M special-register lift gap | 31 | All 31 bodies begin with or immediately require `MRS`/`MSR` over `BASEPRI`, `BASEPRI_MAX`, `IPSR`, or `PSP`; ARM32 lift source has no implementation for those operations. |

F1a includes all 15 x0r-usb worker procedures, twelve Mydoom worker
procedures, and six Dexter functions (`DetectShutdown` and `DllEntryPoint`
across three presets). Representative symbols are `_RemoteUSBThread@4`,
`_massmail_main_th@4`, `_DetectShutdown@16`, and `_DllEntryPoint@12`.

F2a is not a generic Thumb-address failure. `cfg` discovers, for example,
`SysTick_Handler` at normalized VA `0x08023dac`, but body lowering returns
nothing. `prepareDshotPacket` is absent from discovery at `0x08021484`; both
functions begin `mrs ..., BASEPRI` and use `msr BASEPRI[_MAX], ...`. The same
signature holds for all 14 unique F2 names and all 31 occurrences.

F1b contains 49 Mydoom and 14 Dexter occurrences. It includes CRT and Win32
imports such as `malloc`, `memcpy`, `vfprintf`, `CreateToolhelp32Snapshot`, and
`Process32First`. A source CFG may legitimately mention these callees, but the
image contains an import slot/thunk relationship rather than their bodies.
Their correct disposition is “external/import,” not fabricated C and not a
local-body recovery failure.

F1c contains 75 PE entry/TLS/SEH-style aliases, ten U-Boot synthetic
veneer/start labels, and three Crazyflie `start` labels. They are absent not
only from the image but also from that binary's published source-CFG map. This
is a dataset-manifest consistency class, not recoverable local code under the
available evidence.

F1d is exactly gzip `__printf__` at O2 and O2-noinline. Its published source
CFG is a single node with `FUNCTION_START`, fourteen unsupported statements,
`return retval`, and `FUNCTION_END`; the image has neither a `__printf__`
function symbol nor import. This is consistent with a source/preprocessor
wrapper eliminated or renamed before the final image, but that explanation
remains provisional until build/source provenance is inspected.

## Distribution

### By mechanism and binary family

| family | F1 unresolved | F2 no body | total |
|---|---:|---:|---:|
| PE32/i386 | 171 | 0 | 171 |
| ELF32/ARM | 13 | 31 | 44 |
| ELF64/x86-64 | 2 | 0 | 2 |
| **Total** | **186** | **31** | **217** |

PE32/i386 is 78.8% of all missing bodies, but every one is F1. Conversely, all
31 F2 failures are ARM firmware functions.

### By optimization preset

| preset | affected binaries | failures |
|---|---:|---:|
| O0 | 10 | 60 |
| O2 | 13 | 72 |
| O2-noinline | 12 | 85 |
| **Total** | **35** | **217** |

### By project

| project | failures | share |
|---|---:|---:|
| mydoom | 88 | 40.6% |
| dexter | 41 | 18.9% |
| minipig | 27 | 12.4% |
| x0r-usb | 15 | 6.9% |
| nuttx | 13 | 6.0% |
| u-boot | 10 | 4.6% |
| crazyflie | 9 | 4.1% |
| betaflight | 4 | 1.8% |
| chibios | 4 | 1.8% |
| gzip | 2 | 0.9% |
| cleanflight | 2 | 0.9% |
| freertos | 1 | 0.5% |
| riot-os | 1 | 0.5% |

Four PE malware projects account for 171/217 rows. Six ARM firmware/RTOS
projects account for all 31 F2 events. The remaining F1 tail is ten U-Boot
veneer/start names, three Crazyflie `start` names, and two GNU `__printf__`
aliases.

## Root-cause hypotheses, kept separate from facts

These are useful work queues, but remain hypotheses until a minimal
reproduction demonstrates each cause.

| hypothesis family | evidence | next proof |
|---|---|---|
| ~~PE imports and CRT aliases are treated as source functions~~ **Proven F1b** | 63 rows have import-table identities and no local function symbol | Record as external/import facts; coordinate whether DecBench should exclude them from local-body coverage. |
| PE entry/TLS/SEH aliases collapse onto identities not preserved after stripping | Repeated `entry`, TLS callback aliases, `DllEntryPoint`, and `TopLevelExceptionFilter` across all presets | Record original and stripped symbol/import/export identities and test address-first lookup with alias preservation. |
| ~~PE application procedures are lost during identity transfer~~ **Proven F1a** | All 27 x0r-usb/Mydoom worker occurrences have `_name@4` symbols; six Dexter rows have `_name@12`/`@16` | Add bounded i386 decoration normalization with collision tests. |
| ~~ARM exception handlers use noncanonical entry encodings or aliases~~ **Superseded by F2a** | All exception handlers begin with Cortex-M system-register operations; some are correctly discovered at normalized VAs | Add explicit ARM32 special-register lift semantics and preserve unsupported-register refusal. |
| ~~Optimized inline/header helpers have no independently recoverable body~~ **Superseded by F2a** | NuttX helpers and `prepareDshotPacket` also begin/use the same MRS/MSR family | The independent fixture must cover ordinary helpers as well as vector handlers. |
| Linker veneers are represented as source functions | U-Boot `j_*sub_*` names are F1 | Determine whether the manifest points at veneers and model veneer identity explicitly. |
| ~~GNU alias normalization misses `__printf__`~~ **Narrowed to F1d** | Source CFG exists, but no object/import identity exists; ordinary alias normalization cannot resolve it | Trace gzip source/preprocessor/build provenance; separately retain an ELF alias fixture so real aliases stay distinct from eliminated wrappers. |

## Complete affected-binary ledger

`F1` and `F2` count occurrences, not unique names. This is the complete
35-checkpoint/217-function inventory.

| Opt | Project | Binary | Format | F1 | F2 | Missing manifest functions |
|---|---|---|---|---:|---:|---|
| O0 | betaflight | betaflight_STM32F405 | ELF32/ARM | 0 | 2 | `SysTick_Handler`, `prepareDshotPacket` |
| O0 | cleanflight | cleanflight_DALRCF405 | ELF32/ARM | 0 | 1 | `SysTick_Handler` |
| O0 | crazyflie | CMSIS_DAP | ELF32/ARM | 1 | 0 | `start` |
| O0 | crazyflie | cf2 | ELF32/ARM | 0 | 1 | `PendSV_Handler` |
| O0 | crazyflie | firmware | ELF32/ARM | 0 | 1 | `PendSV_Handler` |
| O0 | dexter | dexter | PE32/i386 | 9 | 0 | `DetectShutdown`, `DllEntryPoint`, `TlsCallback_0`, `TlsCallback_1`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `tls_callback_0`, `tls_callback_1` |
| O0 | freertos | RTOSDemo | ELF32/ARM | 0 | 1 | `xPortPendSVHandler` |
| O0 | minipig | minipig | PE32/i386 | 9 | 0 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| O0 | mydoom | mydoom | PE32/i386 | 30 | 0 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `__WSAFDIsSet`, `__p__acmdln`, `__set_app_type`, `_amsg_exit`, `_cexit`, `_initterm`, `_ismbblead`, `_onexit`, `abort`, `entry`, `exit`, `free`, `fwrite`, `malloc`, `massmail_main_th`, `memcpy`, `memset`, `mmsender_th`, `scodos_th`, `start`, `strlen`, `sync_visual_th`, `tls_callback_0`, `tls_callback_1`, `vfprintf` |
| O0 | x0r-usb | x0r-usb | PE32/i386 | 5 | 0 | `RemoteDDOSThread`, `RemoteDownloadThread`, `RemoteREGThread`, `RemoteStartThread`, `RemoteUSBThread` |
| O2-noinline | chibios | ch | ELF32/ARM | 0 | 2 | `SVC_Handler`, `chSysGetStatusAndLockX` |
| O2-noinline | crazyflie | CMSIS_DAP | ELF32/ARM | 1 | 0 | `start` |
| O2-noinline | crazyflie | cf2 | ELF32/ARM | 0 | 1 | `PendSV_Handler` |
| O2-noinline | crazyflie | firmware | ELF32/ARM | 0 | 1 | `PendSV_Handler` |
| O2-noinline | dexter | dexter | PE32/i386 | 23 | 0 | `CreateToolhelp32Snapshot`, `DetectShutdown`, `DllEntryPoint`, `ObtainUserAgentString`, `Process32First`, `Process32Next`, `TlsCallback_0`, `TlsCallback_1`, `_TLS_Entry_0`, `_TLS_Entry_1`, `_amsg_exit`, `_initterm`, `_lock`, `_unlock`, `abort`, `calloc`, `entry`, `free`, `fwrite`, `realloc`, `tls_callback_0`, `tls_callback_1`, `vfprintf` |
| O2-noinline | gzip | gzip | ELF64/x86-64 | 1 | 0 | `__printf__` |
| O2-noinline | minipig | minipig | PE32/i386 | 9 | 0 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| O2-noinline | mydoom | mydoom | PE32/i386 | 29 | 0 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `__WSAFDIsSet`, `__p__acmdln`, `_amsg_exit`, `_cexit`, `_initterm`, `_ismbblead`, `_onexit`, `abort`, `entry`, `exit`, `free`, `fwrite`, `malloc`, `massmail_main_th`, `memcpy`, `memset`, `mmsender_th`, `scodos_th`, `start`, `strlen`, `sync_visual_th`, `tls_callback_0`, `tls_callback_1`, `vfprintf` |
| O2-noinline | nuttx | nuttx | ELF32/ARM | 0 | 7 | `mm_lock_irq`, `mm_unlock`, `mm_unlock_irq`, `modifyreg32`, `nxsched_releasepid`, `nxsem_recover`, `nxsig_alloc_pendingsigaction` |
| O2-noinline | riot-os | hello-world | ELF32/ARM | 0 | 1 | `print_ipsr` |
| O2-noinline | u-boot | u-boot | ELF32/ARM | 5 | 0 | `j_j_j_sub_608002ec`, `j_j_sub_608002ec`, `j_sub_608002ec`, `j_sub_60802af4`, `start` |
| O2-noinline | x0r-usb | x0r-usb | PE32/i386 | 5 | 0 | `RemoteDDOSThread`, `RemoteDownloadThread`, `RemoteREGThread`, `RemoteStartThread`, `RemoteUSBThread` |
| O2 | betaflight | betaflight_STM32F405 | ELF32/ARM | 0 | 2 | `SysTick_Handler`, `prepareDshotPacket` |
| O2 | chibios | ch | ELF32/ARM | 0 | 2 | `SVC_Handler`, `chSysGetStatusAndLockX` |
| O2 | cleanflight | cleanflight_DALRCF405 | ELF32/ARM | 0 | 1 | `SysTick_Handler` |
| O2 | crazyflie | CMSIS_DAP | ELF32/ARM | 1 | 0 | `start` |
| O2 | crazyflie | cf2 | ELF32/ARM | 0 | 1 | `PendSV_Handler` |
| O2 | crazyflie | firmware | ELF32/ARM | 0 | 1 | `PendSV_Handler` |
| O2 | dexter | dexter | PE32/i386 | 9 | 0 | `DetectShutdown`, `DllEntryPoint`, `TlsCallback_0`, `TlsCallback_1`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `tls_callback_0`, `tls_callback_1` |
| O2 | gzip | gzip | ELF64/x86-64 | 1 | 0 | `__printf__` |
| O2 | minipig | minipig | PE32/i386 | 9 | 0 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| O2 | mydoom | mydoom | PE32/i386 | 29 | 0 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `__WSAFDIsSet`, `__p__acmdln`, `_amsg_exit`, `_cexit`, `_initterm`, `_ismbblead`, `_onexit`, `abort`, `entry`, `exit`, `free`, `fwrite`, `malloc`, `massmail_main_th`, `memcpy`, `memset`, `mmsender_th`, `scodos_th`, `start`, `strlen`, `sync_visual_th`, `tls_callback_0`, `tls_callback_1`, `vfprintf` |
| O2 | nuttx | nuttx | ELF32/ARM | 0 | 6 | `mm_lock_irq`, `mm_unlock`, `mm_unlock_irq`, `modifyreg32`, `nxsem_recover`, `nxsig_alloc_pendingsigaction` |
| O2 | u-boot | u-boot | ELF32/ARM | 5 | 0 | `j_j_j_sub_608002ec`, `j_j_sub_608002ec`, `j_sub_608002ec`, `j_sub_60802a44`, `start` |
| O2 | x0r-usb | x0r-usb | PE32/i386 | 5 | 0 | `RemoteDDOSThread`, `RemoteDownloadThread`, `RemoteREGThread`, `RemoteStartThread`, `RemoteUSBThread` |

## Separate 13-function compile-evidence gap

Thirteen O2 Dexter functions have decompiled bodies and byte-match values but
no `compiles` fact because DecBench could not extract the original PE function
bytes needed for its compile comparison. They are not among the 217 and are not
Glaurung body failures:

`DigitsLen`, `GetDownloadFileSize`, `IsDigit`, `IsEndDataValid`, `IsNameChar`,
`Reflect`, `SkipProcess`, `_rand`, `_srand`, `check_digit`, `do_rand`,
`from_hex`, and `ny_toLower`.

Track this as E1 — evaluator byte-extraction gap. It belongs in submission
completeness reporting, not in the product failure denominator.

## Remediation and fixture requirements

1. **F1a stdcall normalization.** In TDD order, add a PE symbol fixture with
   `_name@4`, `_name@12`, `_name@16`, an undecorated collision, and a data
   symbol lookalike. Resolve only unambiguous function symbols. This addresses
   33 pinned rows by mechanism; rerun before claiming 33 recovered bodies.
2. **F1b import disposition.** Emit an external/import record with DLL,
   ordinal/name, IAT VA, and thunk VA where present. Do not manufacture a local
   body. Define with DecBench whether these 63 rows are excluded or scored as
   explicit external declarations.
3. **F1c manifest consistency.** Mark the 88 manifest-only rows as
   `no_source_cfg_no_binary_identity`; do not ask a decompiler to invent an
   address. Add a dataset validator requiring every manifest function to have
   at least one admissible identity/oracle path.
4. **F1d provenance trace.** Locate the gzip `__printf__` source/preprocessor
   definition and determine whether optimization, macro renaming, or dataset
   extraction created the source-only row.
5. **PE identity fixtures.** Add a hermetic clang-cl fixture containing an
   entry point, `DllMain`, TLS callbacks with aliases, SEH filter, imported CRT
   and Win32 calls, and named worker procedures. Preserve source and linker
   map/PDB as oracles.
6. **F2a ARM special-register fixture.** Add Cortex-M functions using MRS/MSR
   for `BASEPRI`, `BASEPRI_MAX`, `IPSR`, and `PSP`, both vector handlers and
   ordinary helpers. Assert discovery and a body at each normalized Thumb VA;
   give unknown system registers an explicit intrinsic/refusal rather than
   silently dropping the function.
7. **Veneer and alias fixtures.** Add ARM linker veneers and an ELF
   `__printf__` alias fixture. Assert identity before C output.
8. **Failure ratchet.** Persist counts by mechanism and proven subclass. A new command failure,
   parse failure, conversion error, or F2 body loss turns the gate red.
7. **No benchmark leakage.** Use these rows to choose defect classes, then
   construct independent fixtures. Keep full DecBench held out.

## Definition of done

This observation ledger is complete now. Remediation is done only when every
F1 row has a proven identity disposition; every F2 row is recovered or proven
to name code absent from the image; independent fixtures guard each proven
class; a fresh pinned run has zero unexplained missing bodies; and the 13 E1
rows are scored or accepted by DecBench as evaluator exclusions.
