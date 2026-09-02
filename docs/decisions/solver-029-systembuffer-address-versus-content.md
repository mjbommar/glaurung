# Solver ADR-029 — Separate WDM SystemBuffer address ownership from content taint

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** ADR-028 selected complete x64 Windows 11 `usbprint.sys` as the first
nonzero producer-confidence population: five Z3 versus four Axeyum rows, with
one Z3-only `SystemBuffer` null dereference. Public symbols and disassembly place
all five in `HPUsbIOCTLVendorGetCommand`, behind explicit non-null and
three-byte length guards for IOCTL `0x0022003c` (`METHOD_BUFFERED`). Windows owns
the kernel SystemBuffer pointer and allocates the larger input/output size; the
old IRP seed instead made that pointer a free attacker-controlled 64-bit value.
**Decision:** Store a fixed, chaseable synthetic kernel address in
`AssociatedIrp.SystemBuffer`. Extend `TaintSpec` with stable concrete memory
regions so uninitialized data loaded from that allocation remains exactly
`*SystemBuffer`-tainted without tainting the address. Preserve symbolic
`Type3InputBuffer` and `UserBuffer` pointers for genuine `METHOD_NEITHER`
pointer-control checks. Keep request-length-aware out-of-bounds analysis a
separate future primitive; never approximate it by calling the kernel pointer
attacker-selected.
**Evidence:** The exact reduced regression first emitted the same three
controlled reads and two null dereferences as the real driver and now emits
none. All 22 focused IOCTL tests pass independently with Z3 and Axeyum; positive
write/read/null controls now use raw `METHOD_NEITHER` pointers, while downstream
dangerous-value controls load attacker bytes from SystemBuffer. Ordered traces
show Z3 selecting `SystemBuffer+2 = 1` and Axeyum selecting `3`; only Z3's
representative makes the next synthetic `+1` address wrap to zero. On the
complete 18-of-21 real boundary, both corrected release binaries execute 16,537
solves and emit 214 raw diagnostics, zero high-confidence rows, and zero
accepted-row difference. The only raw-set difference is one generic-`ArgN`
`memcpy` implementation store per authority (`0x140009793` versus
`0x14000969a`).
**Consequences:** The prior five-versus-four result is retained as evidence of
an environment-model defect and AnyModel steering, not finding recall. Usbprint
is retired as the nonzero policy-sweep target; a new independently labeled
positive population is required before preregistration. A0 remains one cheap
configuration mechanism, and symbolic memory remains conditional. The KMDF
retrieve-buffer summary still needs the same address/content correction before
its SystemBuffer rows can be treated as validated positives.
**Alternatives rejected:** canonicalize both solvers to Z3's representative;
special-case the five instruction addresses; suppress only null dereferences;
keep pointer taint and call the rows high confidence; make the buffer constant
and discard content taint; or treat OutputBufferLength guards as proof for
unrelated METHOD_NEITHER pointers.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
