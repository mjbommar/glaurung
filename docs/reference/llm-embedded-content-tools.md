# Embedded Content Extraction (Layers 1.5–3.5)

> **Kind:** reference · **Status:** maintained

> **Design and implementation record.** The plan below is largely built: 19 of
> the 21 numbered tools are shipped as `MemoryTool` objects under
> `python/glaurung/llm/tools/` and registered in `register_analysis_tools`
> (`python/glaurung/llm/agents/memory_agent.py`). See
> [`llm-tool-contract.md`](llm-tool-contract.md) for the maintained tool
> contract and how to verify any one tool's current registration.

## Shipped tools

| File | Registered tool names |
| --- | --- |
| `extract_archive.py` | `enumerate_archive`, `extract_archive_entry`, `extract_archive_all`, `recursive_unpack` |
| `find_embedded_executables.py` | `find_embedded_executables` |
| `find_encoded_blobs.py` | `find_base64_blobs`, `find_hex_blobs`, `find_pem_blocks`, `try_xor_brute`, `scan_xor_encoded_strings`, `find_compressed_blobs` |
| `find_structured_blobs.py` | `find_embedded_images`, `find_xml_blobs`, `find_json_blobs`, `find_plist_blobs`, `find_ini_blobs`, `extract_pe_overlay`, `extract_elf_section` |
| `analyze_recursively.py` | `analyze_recursively` |
| `pe_list_resources.py` | `pe_list_resources` (ships instead of the `extract_pe_resources` name below) |

Not shipped under the names proposed below: `extract_pe_resources` (use
`pe_list_resources`, a different result shape) and `extract_macho_section`;
`decode_at` (tool 14) has no standalone mechanical-decoder tool — decoding is
folded into the individual `find_*` tools instead.

## The gap

Glaurung's pipeline assumes the file you hand it *is* the binary you
want to analyse. Real-world targets violate that assumption constantly:

- A malware sample is a ZIP/RAR with the real payload inside.
- An installer is a PE with a CAB or 7z appended after the formal end
  of the executable.
- A dropper carries its second-stage as a base64 string in `.rodata`,
  XOR-decoded at runtime.
- A document parser carries icons, manifests, version info, embedded
  PDFs/images in resource sections.
- Some samples are *recursively* nested — a base64-encoded zip
  containing an XOR-encoded executable.

These cases need extraction *before* you can run the rest of Glaurung's
analysis, and they need it composably enough to handle nesting.

## What this layer adds

A set of focused tools that find, validate, and extract *content
contained within* a primary file. Output of every tool is either:

1. A byte range (offset, length) in the parent file.
2. A standalone bytes blob (when extraction is unambiguous).
3. A reference to a temp file that the extracted bytes were written
   to (when the consumer needs a path).

Each tool is small, deterministic, and composable. The orchestrator
(or the agent) recurses: if the extracted bytes look like another
container or another binary, run the next round of tools on them.
Recursion has a hard depth cap (default 4) and a cumulative-size cap
(default 256 MB) so a malformed sample can't fork-bomb us.

The LLM is *not* needed for most of this — these are mechanical
operations. The LLM only enters for ambiguous cases (which of the
five candidate XOR keys is right? what's the role of this extracted
config file?).

## Tool list

### Tier A — Container archives (deterministic)

**1. `enumerate_archive(path) → [{name, size, offset, mtime, encrypted}]`**
List entries in a zip / tar / gz / bz2 / xz / 7z / rar / zstd / cpio
without extracting bodies. Reports encryption status when the format
distinguishes it.

**2. `extract_archive_entry(path, entry_name, out_path?) → bytes | path`**
Extract one named entry. Streams to a temp file when output is large.

**3. `extract_archive_all(path, out_dir, max_files=64, max_bytes=256MB) → [path]`**
Bulk extract with bounds.

**4. `recursive_unpack(path, out_dir, max_depth=4) → tree`**
Apply 1+2 recursively until everything is "primitive" (a file that's
not a recognised archive). Reports a tree of extraction steps for
auditability.

### Tier B — Embedded binaries (in-file scan)

**5. `find_embedded_executables(bytes) → [{format, offset, size, signature_bytes}]`**
Scan for inner ELF/PE/Mach-O magics anywhere in the parent's body —
not just at offset 0. Useful for installers (NSIS/MSI), droppers, and
self-extracting archives. Returns offsets the caller can `dd` from.

**6. `extract_pe_overlay(path) → {offset, size, bytes}`**
Pull the data appended after a PE's formal section table — the
classic "installer payload appended to a stub" pattern.

**7. `extract_pe_resources(path) → [{type, name, language, bytes}]`**
Walk a PE's `.rsrc` directory: icons, manifests, version info, custom
RT_RCDATA blobs. Each entry reports its type ID (ICON, RT_VERSION,
…) plus the raw bytes.

**8. `extract_elf_section(path, name) → bytes`**
Pull a named ELF section's raw bytes. Convenience for `.rodata`,
`.comment`, `.note.go.buildid`, `.gopclntab`, `.go.buildinfo`,
`.tbss`, `.text.cold`, …

**9. `extract_macho_section(path, segment, section) → bytes`**
Same for Mach-O `__TEXT,__cstring`, `__DATA,__objc_methname`, etc.

### Tier C — Encoded blobs (heuristic + decode)

**10. `find_base64_blobs(bytes, min_len=32) → [{offset, length, decoded_size, looks_like}]`**
Scan for runs of base64 alphabet characters that are quad-aligned
(or nearly so) and decode them. The `looks_like` field is the result
of running magic detection on the decoded bytes — usually `unknown`,
sometimes `ELF executable` or `gzip stream`.

**11. `find_hex_blobs(bytes, min_len=64) → [{offset, length, decoded_bytes}]`**
Long even-length runs of `[0-9A-Fa-f]` likely to be hex-encoded data.

**12. `find_pem_blocks(bytes) → [{offset, type, body_bytes}]`**
PEM-armored blocks (`-----BEGIN ...-----` / `-----END ...-----`).
Detects keys, certs, and arbitrary `BEGIN <TYPE>` payloads.

**13. `try_xor_brute(bytes, range, key_lengths=[1,2,4,8]) → [{key, score, decoded}]`**
Single/multi-byte XOR brute force over a byte range. Scores by
plausibility of the result (printable-ASCII fraction, English-like
trigram score, presence of magic bytes). Top-3 candidates only.

**14. `decode_at(path, offset, length, encoding)`**
Mechanical decoder — `base64`, `hex`, `xor:KEY_HEX`, `gzip`, `zlib`,
`zstd`, `lz4`, `lzma`. The agent picks based on the heuristic scan's
suggestion.

### Tier D — Embedded media (image / config / structured)

**15. `find_embedded_images(bytes) → [{format, offset, length}]`**
Scan for PNG / JPEG / GIF / BMP / WEBP / ICO / SVG magics, follow
the format's length field to confirm a complete payload, return
ranges. Avoids the false-positive case where a magic byte
coincidentally appears in code.

**16. `find_xml_blobs(bytes) → [{offset, length, root_element}]`**
Scan for `<?xml ...?>` or balanced `<tag>...</tag>` runs that parse
cleanly with a streaming XML parser. Reports the root element name
so the caller can decide if it's an Android manifest, RSS, plist, …

**17. `find_json_blobs(bytes, min_size=64) → [{offset, length, top_level_kind}]`**
Detect `{` or `[` that opens a parseable JSON document. Bounded-depth
parser to avoid pathological nesting.

**18. `find_plist_blobs(bytes) → [{offset, length, format}]`**
Apple property lists in either `bplist00` binary form or XML form.

**19. `find_ini_blobs(bytes) → [{offset, length, section_count}]`**
`[section]` + `key=value` heuristic.

**20. `find_compressed_blobs(bytes) → [{offset, length, format, decompressed_size?}]`**
Detect gzip / zlib / xz / bz2 / lz4 / zstd / lzma streams by header
+ trial-decompress of a small prefix.

### Tier E — Recursive analysis driver

**21. `analyze_recursively(path, max_depth=4, max_total_bytes=256MB) → tree`**
The orchestrator entry point. Runs:

1. Triage on `path` — what kind of file is this?
2. If container (Tier A): unpack and recurse on every entry.
3. If executable (any format): run the existing analysis pipeline.
4. Run Tier B–D scanners on the body and recurse on every found blob.
5. Bookkeep visited content hashes to break cycles.
6. Emit a tree report — what was found, where, what we did with it.

The tree is the answer to "what's actually inside this file?" — the
question the user usually has when they hand a sample to Glaurung.

## Adversarial sample plan

Most of this corpus now exists under `samples/adversarial/embedded/`
(`nested_zip_in_zip.zip`, `pe_with_overlay.exe`, `b64_payload_in_elf.elf`,
`xor_url_in_elf.elf`, `recursively_nested.bin`); confirm any individual path
against the current checkout before citing it, and see
[`sample-corpus.md`](sample-corpus.md). Full proposed list, status marked:

- `nested_zip_in_zip.zip` — a zip containing a zip containing the
  hello binary. **shipped.**
- `pe_with_overlay.exe` — Windows hello followed by an appended zip. **shipped.**
- `b64_payload_in_elf.elf` — Linux hello with a base64-encoded ELF
  embedded in `.rodata`. **shipped.**
- `xor_encoded_url_in_elf.elf` — XOR-encoded C2 URL in `.rodata`. **shipped as
  `xor_url_in_elf.elf`.**
- `png_in_pe.exe` — PE with an embedded PNG resource. not shipped.
- `manifest_in_pe.exe` — PE with an XML manifest in `.rsrc`. not shipped.
- `gzip_in_string_table.elf` — gzipped payload spliced into the
  string table. not shipped.
- `recursively_nested.bin` — base64(zip(xor(hello))) for the
  end-to-end Tier E test. **shipped.**

Each sample is small (≤ a few hundred KB), built from existing hello
samples plus a synthesizer script under `samples/adversarial/`. The
synthesizer is committed; the binaries are derived artifacts.

## Implementation plan

**Sprint 1 — minimum viable extraction** (1 day)

- Tools 1, 2, 3, 4 (Tier A). Pure Python on top of `zipfile`,
  `tarfile`, `gzip`, plus `py7zr` / `zstandard` if available.
- Tool 5 (Tier B, just embedded-magic scan).
- Wire into `register_analysis_tools` in `memory_agent`.
- Build the basic adversarial samples (`nested_zip_in_zip`,
  `pe_with_overlay`).
- Integration test: `enumerate_archive` on `nested_zip_in_zip.zip`
  reports the inner zip as an entry.

**Sprint 2 — encoded blob detection** (1 day)

- Tools 10 (base64), 11 (hex), 12 (PEM).
- Tool 13 (XOR brute) — small implementation, frequency-table scoring.
- Tool 20 (compressed blob detect+probe).
- Build `b64_payload_in_elf.elf` and `xor_encoded_url_in_elf.elf`.
- Test: round-trip `b64_payload` → decode → executable detected.

**Sprint 3 — resource extraction & images** (1 day)

- Tools 6, 7 (PE overlay + resources). Use `pefile` if available, fall
  back to manual COFF walk.
- Tool 8 (ELF section), 9 (Mach-O section).
- Tool 15 (embedded images).
- Tool 16, 17, 18 (XML, JSON, plist).

**Sprint 4 — orchestrator** (1 day)

- Tool 21 (`analyze_recursively`). Ties together Sprint 1–3, emits a
  tree report.
- Wire into the existing `BinaryTriageAgent` so the triage step now
  unwraps containers automatically.
- End-to-end test on `recursively_nested.bin`.

## Where these tools live

- Extractors and scanners: `python/glaurung/llm/tools/{extract_archive,
  find_embedded_executables,find_encoded_blobs,find_structured_blobs,
  analyze_recursively,pe_list_resources}.py`, the same `MemoryTool[Args,
  Result]` pattern documented in [`llm-tool-contract.md`](llm-tool-contract.md).
- Recursive driver: `analyze_recursively` is itself one more `MemoryTool`
  (`python/glaurung/llm/tools/analyze_recursively.py`), registered directly
  into `register_analysis_tools`. There is no separate `recursive_triage.py`
  agent or `BinaryTriageAgent` class — that part of the original plan was not
  built as a distinct agent.
- Adversarial samples: `samples/adversarial/` (see
  [`sample-corpus.md`](sample-corpus.md)); confirm any specific nested-sample
  path against the current checkout before citing it.

## Why most of this is not LLM-driven

Container extraction, magic-byte scanning, base64 decoding, gzip
header probing — these are *exact, well-defined operations*. Asking
an LLM to "find a base64 string and decode it" is wasteful: the LLM
can't possibly do the byte work better than `re.compile` + `b64decode`.
The LLM's role here is the *navigation* layer:

- Given a tree of extracted artifacts, decide which to investigate.
- Given multiple XOR-key candidates, judge which result looks
  meaningful.
- Given an extracted XML, classify what kind of config it is and
  which fields matter.

That's why this layer is described as 1.5–3.5: it slots between
"what is this file?" (Phase 1, deterministic) and "what does this
function do?" (Phase 4, LLM-heavy), expanding the surface of what
Phase 4 can be applied to.
