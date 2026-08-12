# Format and compiler-artifact references

> **Status: maintained reference index.** These pages describe current parser
> capabilities or explicitly bounded implementation research. Source and tests
> remain authoritative when a page and the checkout disagree.

Use the parser guides for user-facing format coverage. This directory records
cross-format behavior and the lower-level evidence used by detection code.

## References

- [Android ecosystem support](android.md) separates implemented DEX, AXML,
  APK/AAB/JAR, native ELF, IOCTL, and SELinux-policy capabilities from missing
  work.
- [Compiler and language-detection evidence](compiler-artifacts.md) documents
  the current heuristics in `src/triage/compiler_detection.rs`, their public
  functions, and their limits.
- [SELinux policydb format](sepolicy-policydb-format.md) is an implementation
  specification. It distinguishes the shipped header parser from validated
  body-layout research that has not been implemented.

For task-oriented parser status, start with the
[parser index](../parsers/README.md). For fixture provenance and rebuild
instructions, use [`tests/fixtures/android/README.md`](../../tests/fixtures/android/README.md)
and the [sample corpus guide](../../samples/README.md).

## Validation boundary

A format claim is current only when it is supported by all three of:

1. a live module exported from `src/formats/mod.rs` or another named source;
2. a real checked-in fixture or a documented fixture-build recipe; and
3. a focused test that exercises the behavior.

Magic-byte recognition is not full parsing. Header parsing is not semantic
recovery. A research layout marked as decoded is not a shipped query API.
