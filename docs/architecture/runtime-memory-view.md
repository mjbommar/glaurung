# Runtime memory view

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/memory.rs` provides a read-only, process-scoped view over
the sparse page evidence in a validated `ProcessCapsule`. It never fills absent
runtime bytes from `ProgramImage` and never mutates either model.

The detailed `read_runtime_bytes` path distinguishes invalid capsules,
unsupported address forms, overflow, unmapped ranges, overlapping mappings,
mapping-boundary reads, unreadable mappings, absent or overlapping pages,
provider omissions, unavailable payloads, and payload identity failures. A
read may span adjacent captured pages inside one readable mapping. Every payload
is checked against its declared length and SHA-256 before bytes are returned.

`RuntimeMemoryView` also implements the shared `analysis::MemoryView` trait so
existing bounded-read analyses can consume captured bytes. That compatibility
surface maps the detailed runtime failure into `MemoryError::Translation`;
runtime findings should use the detailed method when completeness and omission
provenance must be preserved.

Static file fallback remains a future explicit policy. It may only be offered
after exact module identity and byte-origin checks, and a result must continue
to state which bytes were captured and which came from the file image.
