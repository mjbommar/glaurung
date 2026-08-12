//! Owned binary image and immutable indices shared by one analysis session.

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SectionKind, SymbolKind,
};

use crate::core::binary::{Arch, Endianness, Format};
use crate::target::TargetSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileMapping {
    va_start: u64,
    va_end: u64,
    file_start: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedSection {
    name: String,
    address: u64,
    file_range: Range<usize>,
}

/// Runtime mutability of one mapped image address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageMemoryKind {
    /// Code, constants, and other mapped storage without write permission.
    ReadOnly,
    /// Mapped static or thread-local storage with write permission.
    Writable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedMemoryRange {
    range: Range<u64>,
    kind: ImageMemoryKind,
}

/// A file-backed object section borrowed from an indexed [`ProgramImage`].
///
/// The section metadata and byte range are validated when the image is built,
/// so consumers can inspect section data without parsing the object again.
#[derive(Debug, Clone, Copy)]
pub struct ProgramSection<'a> {
    section: &'a IndexedSection,
    bytes: &'a [u8],
}

impl ProgramSection<'_> {
    /// Object-declared section name, or an empty string when unnamed.
    pub fn name(&self) -> &str {
        &self.section.name
    }

    /// Object-declared virtual address.
    pub fn address(&self) -> u64 {
        self.section.address
    }

    /// Exact file-backed section bytes.
    pub fn data(&self) -> &[u8] {
        &self.bytes[self.section.file_range.clone()]
    }
}

impl FileMapping {
    fn new(va_start: u64, size: u64, file_start: u64) -> Option<Self> {
        if size == 0 {
            return None;
        }
        Some(Self {
            va_start,
            va_end: va_start.checked_add(size)?,
            file_start,
        })
    }

    fn translate(self, va: u64, byte_len: usize) -> Option<usize> {
        if va < self.va_start || va >= self.va_end {
            return None;
        }
        let offset = self.file_start.checked_add(va - self.va_start)?;
        let offset = usize::try_from(offset).ok()?;
        (offset < byte_len).then_some(offset)
    }
}

/// Failure to load or parse a program image.
#[derive(Debug)]
pub enum ProgramImageError {
    /// The image could not be read from storage.
    Io(std::io::Error),
    /// The bytes are not an object format supported by the `object` crate.
    Parse(String),
}

impl std::fmt::Display for ProgramImageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "image read failed: {error}"),
            Self::Parse(error) => write!(formatter, "image parse failed: {error}"),
        }
    }
}

impl std::error::Error for ProgramImageError {}

impl From<std::io::Error> for ProgramImageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Immutable program bytes plus target and address indices derived by one parse.
///
/// `object::File` borrows its input and therefore cannot safely be stored beside
/// an owned `Vec<u8>` without a self-referential allocation. `ProgramImage`
/// extracts durable, owned indices during construction instead. Consumers query
/// these indices and never reopen the object merely to translate an address.
#[derive(Debug, Clone)]
pub struct ProgramImage {
    bytes: Arc<Vec<u8>>,
    target: TargetSpec,
    entry_va: u64,
    segment_mappings: Arc<[FileMapping]>,
    section_mappings: Arc<[FileMapping]>,
    code_mappings: Arc<[FileMapping]>,
    sections: Arc<[IndexedSection]>,
    memory_ranges: Arc<[IndexedMemoryRange]>,
    executable_ranges: Arc<[Range<u64>]>,
    eh_frame_functions: Arc<[crate::analysis::exception::EhFrameFunction]>,
    defined_text_symbols_by_name: Arc<HashMap<String, u64>>,
    defined_symbols_by_va: Arc<HashMap<u64, String>>,
}

impl ProgramImage {
    /// Read and index one image from disk.
    pub fn from_path(path: &Path) -> Result<Self, ProgramImageError> {
        Self::from_bytes(std::fs::read(path)?)
    }

    /// Own and index one object image without copying the supplied vector.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProgramImageError> {
        let object = crate::decompile::profile::parse_object(&bytes)
            .map_err(|error| ProgramImageError::Parse(error.to_string()))?;
        let format = map_format(object.format());
        let arch = map_arch(object.architecture());
        let endianness = if object.is_little_endian() {
            Endianness::Little
        } else {
            Endianness::Big
        };
        let entry_va = object.entry();
        let arm_hard_float = matches!(
            object.flags(),
            object::FileFlags::Elf { e_flags, .. }
                if arch == Arch::ARM && e_flags & object::elf::EF_ARM_ABI_FLOAT_HARD != 0
        );
        let target = TargetSpec::from_image_metadata(arch, endianness, format, arm_hard_float);

        let mut segment_mappings = Vec::new();
        let mut segment_ranges = Vec::new();
        for segment in object.segments() {
            let (file_start, file_size) = segment.file_range();
            let file_backed_size = segment.size().min(file_size);
            if let Some(mapping) = FileMapping::new(segment.address(), file_backed_size, file_start)
            {
                segment_mappings.push(mapping);
            }
            if segment.size() != 0 {
                if let Some(end) = segment.address().checked_add(segment.size()) {
                    segment_ranges.push(segment.address()..end);
                }
            }
        }

        let mut section_mappings = Vec::new();
        let mut code_mappings = Vec::new();
        let mut sections = Vec::new();
        let mut memory_ranges = Vec::new();
        let mut executable_ranges = Vec::new();
        for section in object.sections() {
            let address = section.address();
            let size = section.size();
            if let (Some(kind), Some(end)) = (
                image_memory_kind(section.kind(), section.flags()),
                address.checked_add(size),
            ) {
                if size != 0 && !(format == Format::COFF && address == 0) {
                    memory_ranges.push(IndexedMemoryRange {
                        range: address..end,
                        kind,
                    });
                }
            }
            let name_is_code = section.name().is_ok_and(|name| {
                let name = name.to_ascii_lowercase();
                name.contains(".text") || name.contains("code") || name == "text"
            });
            let is_code = section.kind() == SectionKind::Text || name_is_code;
            let Some((file_start, file_size)) = section.file_range() else {
                continue;
            };
            if let (Ok(file_start), Ok(file_size)) =
                (usize::try_from(file_start), usize::try_from(file_size))
            {
                if let Some(file_end) = file_start.checked_add(file_size) {
                    if file_end <= bytes.len() {
                        sections.push(IndexedSection {
                            name: section.name().unwrap_or("").to_string(),
                            address,
                            file_range: file_start..file_end,
                        });
                    }
                }
            }
            if is_code && size != 0 {
                if let Some(end) = address.checked_add(size) {
                    executable_ranges.push(address..end);
                }
            }
            let Some(mapping) = FileMapping::new(address, size.min(file_size), file_start) else {
                continue;
            };
            section_mappings.push(mapping);
            if is_code {
                code_mappings.push(mapping);
            }
        }
        if executable_ranges.is_empty() {
            executable_ranges = segment_ranges;
        }

        let mut defined_text_symbols_by_name = HashMap::new();
        let mut defined_symbols_by_va = HashMap::new();
        for symbol in object.symbols().chain(object.dynamic_symbols()) {
            if !symbol.is_definition() {
                continue;
            }
            let Ok(name) = symbol.name() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let address = normalize_function_entry(format, arch, symbol.address());
            defined_symbols_by_va
                .entry(address)
                .or_insert_with(|| name.to_string());
            if symbol.kind() == SymbolKind::Text {
                defined_text_symbols_by_name
                    .entry(name.to_string())
                    .or_insert(address);
            }
        }
        let eh_frame_functions = crate::analysis::exception::eh_frame_functions(&bytes);
        drop(object);

        Ok(Self {
            bytes: Arc::new(bytes),
            target,
            entry_va,
            segment_mappings: segment_mappings.into(),
            section_mappings: section_mappings.into(),
            code_mappings: code_mappings.into(),
            sections: sections.into(),
            memory_ranges: memory_ranges.into(),
            executable_ranges: executable_ranges.into(),
            eh_frame_functions: eh_frame_functions.into(),
            defined_text_symbols_by_name: Arc::new(defined_text_symbols_by_name),
            defined_symbols_by_va: Arc::new(defined_symbols_by_va),
        })
    }

    /// Original immutable file bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Parsed object format.
    pub fn format(&self) -> Format {
        self.target.format()
    }

    /// Exact function extents decoded once from ELF `.eh_frame` FDEs.
    pub fn eh_frame_functions(&self) -> &[crate::analysis::exception::EhFrameFunction] {
        &self.eh_frame_functions
    }

    /// Parsed instruction-set architecture.
    pub fn arch(&self) -> Arch {
        self.target.architecture()
    }

    /// Parsed byte order.
    pub fn endianness(&self) -> Endianness {
        self.target.endianness()
    }

    /// Canonical target facts derived during the image's single parse.
    pub fn target(&self) -> &TargetSpec {
        &self.target
    }

    /// Object-declared program entry virtual address.
    pub fn entry_va(&self) -> u64 {
        self.entry_va
    }

    /// Whether an ARM ELF advertises the AAPCS hard-float calling convention.
    pub fn arm_hard_float(&self) -> bool {
        self.target.calling_convention() == Some(crate::target::CallConv::ArmHardFloat)
    }

    /// Normalize an external function symbol value to its instruction address.
    pub fn normalize_function_entry(&self, va: u64) -> u64 {
        normalize_function_entry(self.format(), self.arch(), va)
    }

    /// Look up the first defined text symbol with `name`.
    pub fn defined_text_symbol_address(&self, name: &str) -> Option<u64> {
        self.defined_text_symbols_by_name.get(name).copied()
    }

    /// Look up the first defined symbol naming an exact code address.
    pub fn defined_symbol_name_at(&self, va: u64) -> Option<&str> {
        self.defined_symbols_by_va.get(&va).map(String::as_str)
    }

    /// Executable section ranges in object order.
    pub fn executable_ranges(&self) -> impl Iterator<Item = &Range<u64>> {
        self.executable_ranges.iter()
    }

    /// Iterate all valid file-backed sections in object order.
    pub fn sections(&self) -> impl Iterator<Item = ProgramSection<'_>> {
        self.sections.iter().map(|section| ProgramSection {
            section,
            bytes: self.bytes(),
        })
    }

    /// Classify a mapped image VA by runtime mutability.
    ///
    /// Conflicting overlapping section claims fail closed as `None`. This is
    /// important for relocatable objects whose sections may all report address
    /// zero before relocation.
    pub fn memory_kind_at(&self, va: u64) -> Option<ImageMemoryKind> {
        let mut matches = self
            .memory_ranges
            .iter()
            .filter(|memory| memory.range.contains(&va))
            .map(|memory| memory.kind);
        let first = matches.next()?;
        matches.all(|kind| kind == first).then_some(first)
    }

    /// Translate a code VA, preferring executable sections for relocatable files.
    pub fn va_to_code_file_offset(&self, va: u64) -> Option<usize> {
        self.code_mappings
            .iter()
            .find_map(|mapping| mapping.translate(va, self.bytes.len()))
            .or_else(|| self.va_to_file_offset(va))
    }

    /// Translate an arbitrary mapped, file-backed VA to its byte offset.
    pub fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        self.segment_mappings
            .iter()
            .chain(self.section_mappings.iter())
            .find_map(|mapping| mapping.translate(va, self.bytes.len()))
    }
}

fn image_memory_kind(kind: SectionKind, flags: SectionFlags) -> Option<ImageMemoryKind> {
    match flags {
        SectionFlags::Elf { sh_flags } if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0 => {
            return Some(if sh_flags & u64::from(object::elf::SHF_WRITE) != 0 {
                ImageMemoryKind::Writable
            } else {
                ImageMemoryKind::ReadOnly
            });
        }
        SectionFlags::Coff { characteristics }
            if characteristics
                & (object::pe::IMAGE_SCN_MEM_READ
                    | object::pe::IMAGE_SCN_MEM_WRITE
                    | object::pe::IMAGE_SCN_MEM_EXECUTE)
                != 0 =>
        {
            return Some(if characteristics & object::pe::IMAGE_SCN_MEM_WRITE != 0 {
                ImageMemoryKind::Writable
            } else {
                ImageMemoryKind::ReadOnly
            });
        }
        _ => {}
    }

    match kind {
        SectionKind::Text
        | SectionKind::ReadOnlyData
        | SectionKind::ReadOnlyDataWithRel
        | SectionKind::ReadOnlyString => Some(ImageMemoryKind::ReadOnly),
        SectionKind::Data
        | SectionKind::UninitializedData
        | SectionKind::Common
        | SectionKind::Tls
        | SectionKind::UninitializedTls
        | SectionKind::TlsVariables => Some(ImageMemoryKind::Writable),
        _ => None,
    }
}

fn normalize_function_entry(format: Format, arch: Arch, va: u64) -> u64 {
    if format == Format::ELF && arch == Arch::ARM {
        va & !1
    } else {
        va
    }
}

fn map_format(format: object::BinaryFormat) -> Format {
    match format {
        object::BinaryFormat::Elf => Format::ELF,
        object::BinaryFormat::Coff => Format::COFF,
        object::BinaryFormat::Pe => Format::PE,
        object::BinaryFormat::MachO => Format::MachO,
        _ => Format::Unknown,
    }
}

fn map_arch(arch: object::Architecture) -> Arch {
    match arch {
        object::Architecture::I386 => Arch::X86,
        object::Architecture::X86_64 => Arch::X86_64,
        object::Architecture::Arm => Arch::ARM,
        object::Architecture::Aarch64 => Arch::AArch64,
        object::Architecture::Mips => Arch::MIPS,
        object::Architecture::Mips64 => Arch::MIPS64,
        object::Architecture::PowerPc => Arch::PPC,
        object::Architecture::PowerPc64 => Arch::PPC64,
        object::Architecture::Riscv32 => Arch::RISCV,
        object::Architecture::Riscv64 => Arch::RISCV64,
        _ => Arch::Unknown,
    }
}
