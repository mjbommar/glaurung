# Binary Format Specifications Reference

This directory contains canonical specifications and documentation for binary formats, collected for the GLAURUNG project's triage and analysis implementation.

## Collection Statistics
- **Total Files**: 110+ files
- **Total Size**: 31MB
- **Categories**: 16 specialized directories
- **Last Updated**: 2025-08-31

## Directory Structure

```
specifications/
├── architecture/   # CPU instruction sets and opcodes
├── archive/        # Archive formats (zip, tar, ar)
├── compression/    # Compression formats (gzip, deflate, xz, etc.)
├── debugging/      # Debug interfaces (ptrace, GDB)
├── dotnet/         # .NET CLR format
├── dynamic-linking/# Dynamic linker implementations
├── elf/            # ELF (Executable and Linkable Format)
├── firmware/       # Firmware formats (UEFI, Android, embedded)
├── java/           # JVM class file format
├── kernel/         # System call tables
├── macho/          # Mach-O (macOS/iOS executables)
├── pe-coff/        # PE/COFF (Portable Executable)
├── samples/        # Minimal test binaries
├── security/       # Packers, protectors, and obfuscators
├── tools/          # RE tool formats and signatures
└── wasm/           # WebAssembly
```

## Detailed Directory Contents

### `/elf/` - ELF Format (30+ files)
**Official Specifications:**
- `ELF_Format.pdf` - System V ABI specification
- `gabi41.pdf` - Generic ABI documentation
- `DWARF5.pdf` - DWARF debugging format

**Implementation Headers:**
- `linux_elf.h`, `linux_elf-em.h`, `linux_auxvec.h` - Linux kernel
- `android_elf.h` - Android Bionic
- `qemu_elf.h` - QEMU emulator
- `netbsd_exec_elf.h` - NetBSD
- `patchelf_elf.h` - PatchELF tool
- `binutils_elf_common.h`, `binutils_elf_internal.h` - GNU binutils

**Parser Implementations:**
- `golang_elf.go`, `golang_elf_file.go` - Go standard library
- `elftoc.c` - ELF to C converter
- `elf101-64.pdf` - Educational material
- `exploit_education_example.c` - Security education example

### `/pe-coff/` - PE/COFF Format (15+ files)
**Specifications:**
- `ECMA-335_CLI.pdf` - .NET CLI specification
- `PE_Format_Microsoft.md` - Microsoft official docs
- `dotnet_PE_COFF.md` - .NET extensions

**Headers:**
- `winnt.h` - Wine project
- `reactos_winnt.h` - ReactOS
- `mingw_winnt.h` - MinGW-w64
- `dotnet_corinfo.h` - .NET CoreCLR

**Implementations:**
- `golang_pe.go`, `golang_pe_file.go` - Go parsers

### `/macho/` - Mach-O Format (10+ files)
**Apple Headers:**
- `loader.h` - Core loader definitions
- `fat.h` - Universal binary format
- `nlist.h` - Symbol tables
- `reloc.h` - Relocations
- `dyld.h` - Dynamic linker
- `ranlib.h` - Archive index

**Implementations:**
- `golang_macho.go`, `golang_macho_file.go` - Go parsers

### `/wasm/` - WebAssembly (5+ files)
- `wasm_binary_format.rst` - Binary encoding
- `wasm_modules.rst` - Module structure
- `wasm_types.rst` - Type system
- `wasm_instructions.rst` - Instruction encoding

### `/architecture/` - CPU Instructions (15+ files)
**LLVM TableGen Definitions:**
- `x86_instr_info.td` - x86/x86-64
- `aarch64_instr_info.td` - ARM64
- `arm_instr_info.td` - ARM32
- `riscv_instr_info.td` - RISC-V
- `mips_instr_info.td` - MIPS

**Opcode Databases:**
- `x86_64_opcodes.xml` - Comprehensive x86-64 opcodes
- `capstone_x86_tables.inc` - Capstone disassembler
- `golang_x86_opcodes.go`, `golang_arm64_opcodes.go` - Go assembler opcodes

**System Programming:**
- `xv6_x86.h` - xv6 OS x86 definitions
- `linux_msr_index.h` - x86 MSR registers
- `linux_arm64_sysreg.h` - ARM64 system registers

**RISC-V:**
- `riscv_rv32.adoc` - RV32 specification
- `riscv_rv64.adoc` - RV64 specification

### `/compression/` - Compression Formats (10+ files)
**RFCs:**
- `rfc1951_deflate.txt` - DEFLATE
- `rfc1952_gzip.txt` - GZIP
- `rfc8878_zstandard.txt` - Zstandard

**Format Specs:**
- `xz-file-format.txt` - XZ/LZMA2
- `lz4_frame_format.md` - LZ4

**Headers:**
- `zlib.h` - zlib interface
- `zstd.h` - Zstandard interface

### `/archive/` - Archive Formats (8+ files)
- `ZIP_APPNOTE.TXT` - PKWARE ZIP specification
- `tar_format.html` - GNU tar
- `pax_format.html` - POSIX pax
- `magic_archive_signatures.txt` - libmagic signatures
- `archive.h`, `archive_entry.h` - libarchive headers

### `/security/` - Packers & Protection (15+ files)
**Signatures:**
- `die_packers.sg` - Detect-It-Easy packers
- `die_protectors.sg` - Protectors
- `die_cryptors.sg` - Cryptors
- `die_binary_protectors.sg` - Binary protectors

**Documentation:**
- `upx_format.pod` - UPX packer
- `awesome_executable_packing.md` - Comprehensive list
- `packing_formats.md` - Format descriptions
- `packing_techniques.md` - Techniques overview
- `mal_unpack.md` - Unpacking methods
- `pe_to_shellcode.md` - PE conversion
- `ember_features.md` - EMBER malware features

**YARA Modules:**
- `yara_pe_module.c` - PE pattern matching
- `yara_elf_module.c` - ELF pattern matching

### `/firmware/` - Embedded & IoT (8+ files)
- `android_bootimg.h` - Android boot images
- `android_abi.md` - Android ABI docs
- `uefi_spec.h` - UEFI firmware
- `uboot_image.h` - U-Boot images
- `linux_firmware.h` - Linux firmware loading
- `esp32_flash_format.rst` - ESP32 firmware
- `stm32_hal_conf.h` - STM32 configuration

### `/kernel/` - System Calls (4+ files)
- `linux_syscalls.h` - Linux syscall definitions
- `syscall_64.tbl` - x86-64 syscall table
- `freebsd_syscalls.master` - FreeBSD syscalls
- `darwin_syscalls.master` - macOS/Darwin syscalls

### `/dynamic-linking/` - Loaders (4+ files)
- `glibc_dl_load.c` - GNU libc dynamic loader
- `glibc_link.h` - Link structures
- `dyld_MachOFile.h` - Apple dyld

### `/debugging/` - Debug Interfaces (3+ files)
- `linux_ptrace.h` - Linux ptrace
- `glibc_ptrace.h` - glibc ptrace
- `gdb_mi_protocol.html` - GDB Machine Interface

### `/java/` - JVM Format (2+ files)
- `jvm_classfile_constants.h` - Class file constants

### `/dotnet/` - .NET CLR (2+ files)
- `dotnet_cor.h` - Core runtime
- `dotnet_corhdr.h` - CLR headers

### `/tools/` - RE Tool Formats (10+ files)
**libmagic Signatures:**
- `magic_elf.txt` - ELF detection
- `magic_msdos.txt` - DOS/PE detection
- `magic_mach.txt` - Mach-O detection
- `magic_compress.txt` - Compression detection
- `magic_executable.txt` - Executable detection

**Tool Headers:**
- `ghidra_elf_constants.java` - Ghidra ELF
- `ghidra_pe_ntheader.java` - Ghidra PE
- `radare2_elf.h` - radare2 ELF
- `radare2_pe.h` - radare2 PE
- `radare2_mach0.h` - radare2 Mach-O
- `rizin_elf_specs.h` - Rizin ELF

### `/samples/` - Test Binaries (4+ files)
- `minimal_elf.bin` - Minimal valid ELF
- `minimal_pe.exe` - Minimal valid PE
- `minimal_macho` - Minimal Mach-O
- `simple.wasm` - Simple WebAssembly

## Key Resources by Purpose

### For Binary Triage Implementation
1. Magic signatures in `/tools/magic_*.txt`
2. Header definitions in `/elf/`, `/pe-coff/`, `/macho/`
3. DIE signatures in `/security/die_*.sg`
4. Minimal samples in `/samples/`

### For Parser Implementation
1. Official specs (PDFs) in each format directory
2. Go standard library implementations
3. Multiple header versions for cross-validation
4. YARA module source for pattern ideas

### For Disassembly
1. LLVM TableGen files in `/architecture/`
2. Capstone tables
3. System register definitions

### For Security Analysis
1. Packer signatures and techniques in `/security/`
2. YARA modules
3. Unpacking documentation

## Cross-References with Project

### Related to `/reference/` repositories:
- **LIEF**: Comprehensive binary parser
- **Ghidra**: Java-based RE framework  
- **radare2/rizin**: Unix-philosophy RE tools
- **Capstone**: Disassembly engine
- **YARA**: Pattern matching
- **Detect-It-Easy**: Format identification
- **goblin**: Rust binary parser
- **angr/CLE**: Binary loader

### Supporting `/docs/triage/README.md`:
- All format specifications needed for Stage 2 (Header Peek)
- Magic signatures for Stage 1 (Container Probe)
- Packer signatures for Stage 4 (Entropy/Packers)
- Architecture definitions for Stage 3 (Heuristics)

## Usage Notes

1. **Multiple Implementations**: Headers from Linux, BSD, Windows, Android, QEMU, etc. for cross-validation
2. **Parser Examples**: Go standard library provides clean, modern implementations
3. **Real-World Tools**: Headers from Ghidra, radare2, YARA show production approaches
4. **Educational Materials**: Corkami samples, tutorials help understand edge cases

## Online References (Not Downloaded)

These require manual download or registration:

- **Intel Software Developer Manuals**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **ARM Architecture Reference Manual**: https://developer.arm.com/documentation/
- **AMD64 Architecture Programmer's Manual**: https://www.amd.com/en/resources/developer-guides-manuals.html
- **Full RISC-V ISA PDFs**: https://riscv.org/technical/specifications/

## Maintenance

This collection represents comprehensive documentation for binary format analysis. To add more:

```bash
# Example: Download more specifications
curl -sL "<url>" -o "/home/mjbommar/src/glaurung/reference/specifications/<category>/<filename>"

# Update counts
find /home/mjbommar/src/glaurung/reference/specifications -type f | wc -l
du -sh /home/mjbommar/src/glaurung/reference/specifications
```

## License Notice

These specifications are provided for reference purposes. Each document retains its original license and copyright. Most are publicly available standards or open-source documentation.

---

Last expanded: 2025-08-31 (110+ files, 31MB)