# System-call references

> **Kind:** reference · **Status:** maintained

- [Linux system calls](linux.md) covers architecture-specific ABI lookup and the
  limited instruction-level support in the current checkout.
- [Windows system calls](windows.md) covers build-bound service numbers,
  `ntdll`/`win32u` stubs, and the shipped Windows syscall-atlas tools.

The execution-engine documents under `docs/design/` include proposed syscall
dispatch and OS models. A design document is not evidence that those models are
implemented. For shipped Windows coverage, use the
[Windows analysis status](../../guides/windows-analysis.md).

## Analysis rule

Bind a syscall claim to an exact OS, release/build, architecture, ABI, and
source artifact. Names, numbers, calling conventions, compatibility layers, and
entry mechanisms are not portable across those dimensions.
