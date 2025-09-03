# Nested Binaries & Recursion Tree — Data Model Proposal

This document proposes how to represent “nesting” (containers, embedded children, overlays) as a deterministic, budget-aware tree in the triage data model. It balances fidelity with safety, keeps the default artifact lightweight, and allows progressive disclosure of deeper nodes on demand.

Goals

- Deterministic, bounded representation of nested content (no unbounded expansion).
- Stable IDs and paths for nodes, so downstream tools can address children reliably.
- Minimal default payload in `TriagedArtifact`; richer trees are optional.
- Clear separation of contiguous embedded children vs. container entries vs. overlays.
- Preserve safety budgets (time/bytes/depth) per node and at the tree level.

Non‑Goals (for this milestone)

- Full archive extraction or filesystem emulation.
- Lossless modeling of non-contiguous children beyond coarse “spans” when needed.
- Deep validation of code signatures, compression streams, or crypto.

Terminology

- Parent/Child: A node (parent) that contains or references another node (child).
- Embedded child: A child that occupies a contiguous byte span within the parent.
- Container entry: A child that is referenced by container metadata (may be contiguous or virtual) within the parent.
- Overlay: Bytes appended beyond the “official end” of the parent binary format.
- Span: A file-relative offset and size (u64) of interest within a node.

Core Concepts

1) Node

- id: Stable identifier for this node (content-based if available; otherwise deterministic composite).
- kind: The coarse type of node: one of [format, container, overlay, unknown].
- type_name: Human-readable subtype (e.g., "zip", "pe", "elf", "macho-fat", "gzip").
- label: Optional name (e.g., ZIP entry path, Mach-O slice arch, section name).
- location: One of
  - span: { offset: u64, size: u64 } for embedded/contiguous children
  - spans: [{ offset, size }, …] for rare, non-contiguous cases (optional; default empty)
- format_hint: Optional triage-inferred format for this node’s payload.
- confidence: Float in [0,1] describing detection confidence for this node.
- budgets: Optional per-node budget instrumentation (bytes_read, time_ms, hit_byte_limit, etc.).
- truncated: Bool noting if discovery of this node or its boundaries was truncated by budgets.

2) Edge

- parent_id → child_id, with edge_kind in [embedded, container_entry, overlay].
- ordering: edges are emitted in deterministic order (see “Determinism” below).
- notes: Optional origin notes (e.g., "magic signature at offset 0x1234").

3) Tree

- A forest rooted at the analyzed artifact, represented as a parent-first adjacency list.
- Depth is bounded by `max_recursion_depth` in budgets; nodes beyond depth are elided with a placeholder.
- Overlays are modeled as a special edge (parent → overlay region node) to unify traversal.

Identity & Addressing

- Prefer content-based IDs (`bin:sha256:<hex>`) when a full payload slice is accessible within budgets.
- If content-based ID is not feasible (budgeted/partial), derive a deterministic composite ID:
  - `bin:derived:<parent-id>@<offset>+<size>[:<type_name>]`
  - For containers with entry names: append `:<label>` (normalized to a stable form).
- Provide a stable “triage path” (tpath) for UI/debugging: `/0` for root, then `/0/child[2]/child[1]` by deterministic index ordering.

Determinism

- Child ordering per parent: sort by (offset ascending, then type_name, then label) with stable tie-breakers; container entries without offsets sort after embedded children by (label, then type_name).
- JSON keys are serialized in a stable order (serde+feature or pre-sorted before emit).
- Avoid RNG; all detection that can produce multiple candidates applies stable ordering.

Schema Additions (TriagedArtifact)

Add an optional, lightweight summary and an optional, richer tree payload.

- recursion_summary: { total_children: u32, max_depth: u32, dangerous_child_present: bool }
- children: Optional<Vec<RecursionChild>> — immediate children only (1-depth), for quick consumers.
- recursion_tree: Optional<RecursionTree> — full (bounded) tree when requested.

RecursionChild (immediate children)

```jsonc
// Pure-JSON shape (field order shown for readability only)
{
  "id": "bin:derived:bin:sha256:abc...@0x200+4096:zip:payload.exe",
  "kind": "container_entry",
  "type_name": "zip",
  "label": "payload.exe",
  "span": { "offset": 512, "size": 4096 },
  "format_hint": "PE",
  "confidence": 0.96,
  "truncated": false
}
```

RecursionTree (adjacency list)

```jsonc
{
  "nodes": [
    {
      "id": "bin:sha256:...",           // root
      "parent": null,
      "kind": "format",
      "type_name": "pe",
      "label": null,
      "span": { "offset": 0, "size": 217088 },
      "format_hint": "PE",
      "confidence": 1.0,
      "budgets": { "bytes_read": 8192, "time_ms": 9, "hit_byte_limit": false },
      "truncated": false,
      "children": [1, 2]                 // indices into this array, deterministic
    },
    {
      "id": "bin:derived:...@217088+4096:overlay",
      "parent": 0,
      "kind": "overlay",
      "type_name": "overlay",
      "label": null,
      "span": { "offset": 217088, "size": 4096 },
      "format_hint": null,
      "confidence": 0.99,
      "truncated": false,
      "children": []
    },
    {
      "id": "bin:derived:...@512+4096:zip:payload.exe",
      "parent": 0,
      "kind": "container_entry",
      "type_name": "zip",
      "label": "payload.exe",
      "span": { "offset": 512, "size": 4096 },
      "format_hint": "PE",
      "confidence": 0.96,
      "truncated": false,
      "children": []                      // or [3] if deeply explored within budgets
    }
  ]
}
```

Compatibility & Migration

- Existing `containers: Option<Vec<ContainerChild>>` remains supported for one release as a shallow alias of `children` (immediate children only) with the same fields (`type_name`, `offset`, `size`, limited metadata).
- `overlay` remains supported; internally we will also surface an overlay node as part of the tree for consistency.
- Introduce `schema_version` bump when `children` and `recursion_tree` land (e.g., 1.1 → 1.2), and document field stability.

Budgets & Safety

- The tree builder receives explicit caps: `max_depth`, `max_nodes`, `max_child_spans_per_node`, and per-node I/O/time caps.
- Each node’s `budgets` is summarized; the root’s `Budgets` continues to reflect the full run.
- When caps cause elision, set `truncated: true` and, if helpful, add a synthetic placeholder child with `type_name: "elided"` and a `note` about limits.

Detection & Construction

1) Parent format detection → root node (kind=format, type_name=pe/elf/mach-o/etc.).
2) Embedded detection pass (bounded scan) to find children at non-zero offsets:
   - Signatures for common embedded binaries (PE/Mach-O slices, ELF, ZIP, gzip, tar, 7z, ar, cpio, xz, bzip2, zstd),
   - Avoid offset 0 (handled by root),
   - Reject overlaps and cycles using an interval set per parent.
3) Container probe pass (bounded) to add container entries:
   - Lightweight listing for archives, adding children with labels; do not decompress; populate `span` if cheaply available; else omit `span` and rely on `label`.
4) Overlay detection → overlay node for trailing bytes beyond the declared logical end of the parent format.
5) Depth-first recursion:
   - Deterministic order, budgets enforced per-node; early exit with `truncated` on budget hit.
   - Optional on-demand deepening per consumer request.

Overlaps, Cycles, and Validation

- Maintain a per-parent interval set of occupied spans; reject or split overlaps (prefer reject to avoid ambiguity at triage stage).
- Track visited (parent_id, offset, size, type_name, label) tuples to detect cycles from self-referential containers; abort recursion branch on repetition.
- Emit minimal `notes` on elisions (e.g., "overlapping span elided").

Query Aids (Rollups)

- recursion_summary
  - total_children: number of nodes with `parent != null` in the bounded tree
  - max_depth: 0=root only, 1=immediate children present, etc.
  - dangerous_child_present: true if any node triggers a high-risk signal (e.g., suspicious imports, packer hints) — computed from available summaries for nodes that were explored.

Examples

1) PE with overlay and embedded ZIP at offset 0x200

- Root (pe), Child A (overlay @ end), Child B (zip entry "payload.exe" @0x200, format_hint=PE)
- Deterministic child order: B (offset 0x200) before A (offset at end), then container-only entries without spans.

2) Mach-O FAT (universal) with x86_64 and arm64 slices

- Root (macho-fat), children per slice as embedded nodes (kind=embedded, type_name="macho-thin", label="x86_64" / "arm64").
- Each thin slice can optionally recurse to list its imported dylibs.

3) ZIP with nested TAR that contains an ELF

- Root (zip), child: container_entry (label="inner.tar") → embedded child (tar) → embedded child (elf) … bounded by depth.

Python & CLI Exposure (Incremental)

- Python: add typed stubs for `RecursionChild`, `RecursionTree`, and `recursion_summary` getters on `TriagedArtifact`.
- CLI: `--tree` option prints a budgeted, indented view; `--max-depth` caps; `--tree-json` outputs `recursion_tree` JSON.

Testing Strategy

- Unit tests on synthetic buffers for: ordering, cycle prevention, overlap rejection, placeholder elision.
- Integration tests using safe samples: ZIP-in-PE, PE overlay, Mach-O FAT, and archive entry labels.
- Fuzz: short-run fuzzers for container signature detection and embedded scan bounds.

Phased Delivery

1) M3a (Minimal Tree):
   - Add `recursion_summary` and `children` (immediate only), populate from existing `ContainerChild` and embedded detectors.
   - Keep `overlay` as-is; also surface it as a child node for consistency.

2) M3b (Adjacency Tree):
   - Add `recursion_tree` with bounded depth and node caps; expose CLI `--tree`.
   - Introduce content-based IDs for children when spans are available.

3) M3c (Non-Contiguous & Labels):
   - Add optional `spans` for non-contiguous entries and populate `label` for container entries that lack spans.

4) Stabilization:
   - Bump `schema_version`; freeze field names; publish examples in docs.

