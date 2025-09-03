Adversarial and pathological samples for triage robustness tests.

Scope:
- Small, hand-crafted byte sequences designed to exercise edge-cases.
- No decompression or extraction required; all files are bounded in size.

Files:
- magic_dope_mz_elf.bin: Starts with MZ then ELF text, otherwise junk.
- elf_truncated_phdr.bin: ELF magic + header fields suggesting program headers, but truncated data.
- pe_bad_optional_header.bin: MZ + fake PE header offset with insufficient optional header.
- zip_masquerade_exe.exe: ZIP local header masquerading with .exe extension.
- gzip_truncated.gz: GZIP magic with a minimal, truncated body.

Use these in tests to ensure no panics and correct TriageError kinds or container detection behavior.

