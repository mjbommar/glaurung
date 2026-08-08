# Windows system calls

> **Status: maintained analysis reference.** This page describes build-bound
> syscall evidence and the current Glaurung Windows tools. It does not present a
> universal service-number table or instructions for bypassing security controls.

The supported application boundary on Windows is the documented Win32 API.
Lower-level Native API entry points, commonly exported by `ntdll.dll` and
`win32u.dll`, lead to kernel services. Microsoft documents some `Nt*` functions,
but the numeric service identifiers and stub layouts are not a stable public ABI
across Windows builds and architectures.

Treat the exact user-mode module as evidence. Static tooling can extract a
service number from that artifact; the analyzed program does not have to perform
runtime resolution. Conversely, a hard-coded number without build identity is
not portable evidence.

Microsoft's
[NtCreateFile reference](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
shows a documented user-mode Native API entry point in `ntdll.dll`. The WDK's
[Nt and Zw guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)
explains the user-mode system-call boundary and the different kernel-mode
parameter semantics of `Nt*` and `Zw*` calls.

## Evidence to preserve

For each recovered service, record:

- the exact Windows build and architecture, when known;
- source module, file hash, export name, RVA/VA, and file offset;
- the service number and byte or lifted-IR evidence supporting it;
- dispatch shape, including any compatibility fallback;
- whether the bytes appear patched or disagree with a trusted clean artifact;
  and
- the source of any kernel-handler name or address correlation.

An x64 stub often contains a move of `rcx` to `r10`, a service number loaded into
`eax`, and a `syscall` instruction, but Glaurung recognizes several lifted,
assembly, and raw-byte shapes. Do not require one canonical byte sequence.

## Current Glaurung support

The Windows tool surface includes:

- `windows_syscall_stub_atlas`, which scans lifted text, assembly, raw x64 stub
  bytes, and named PE exports;
- `windows_syscall_atlas_diff`, which compares two build-bound atlas snapshots;
- `windows_syscall_handler_correlate`, which joins stubs to PDB-backed project
  function names or an explicit handler map; and
- `windows_live_kernel_snapshot`, which imports external read-only runtime facts
  and checks handler/module relationships.

The implementations live under `python/glaurung/llm/tools/`. The
[Windows analysis status](../windows-port/README.md) is the capability authority.
True live SSDT acquisition/comparison is still future work; the current live
snapshot tool consumes externally collected facts and does not hook or modify a
system.

## Validation

Focused tests cover reduced fixtures and a checked-in real `ntdll` fixture:

```bash
uv run pytest python/tests/test_windows_syscall_stub_atlas_tool.py -q
uv run pytest python/tests/test_windows_syscall_atlas_diff_tool.py -q
uv run pytest python/tests/test_windows_syscall_handler_correlate_tool.py -q
uv run pytest python/tests/test_windows_live_kernel_snapshot_tool.py -q
```

Do not infer completeness from one build. For a finding, corroborate static stub
evidence with exact build identity and, when handler integrity matters, trusted
runtime or symbol evidence.
