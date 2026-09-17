# Runtime evidence packet

> **Kind:** architecture · **Status:** maintained

`runtime_evidence_packet_json` and `glaurung runtime evidence` export
`glaurung-runtime-evidence-packet-v1` from one exact persisted capture. Export
does not reacquire a process, rerun an analyzer, or copy runtime facts into the
static program model.

The default `redacted` policy carries the capture summary, capsule and
executable identities, payload identities and sensitivity labels, completeness
states, analysis-report identities, the claim kinds present in each report, and
an explicit omission list. It excludes capsule and report documents, payload
bytes, free-text completeness reasons, and executable bytes. An omitted value
is represented as omitted; it is never replaced by zero or interpreted as
absence of behavior.

`--include-sensitive` is an explicit analyst-controlled boundary. It adds the
exact persisted capsule document, typed analysis-report documents, and payload
bytes encoded as base64. It still omits executable bytes because the exact
binary is identified by SHA-256 and remains a separately controlled artifact.
This mode is not exposed to the default LLM runtime-project tool.

Before either packet is emitted, the exporter recomputes the stored capsule,
report, and payload hashes and checks payload lengths. A disagreement fails
closed. Canonical key ordering, stable row ordering, and exclusion of database
primary keys and import timestamps make reopening the same project reproduce
identical JSON.

The packet is an evidence transport, not a new source of truth. Observed,
inferred, static, replayed, symbolic, and unknown claims remain owned by their
typed report documents. The redacted packet inventories those kinds without
promoting one into another; the sensitive packet embeds the documents without
rewriting them.
