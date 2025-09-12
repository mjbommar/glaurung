//! Core ELF types and constants

use std::fmt;

/// ELF parsing errors
#[derive(Debug, Clone)]
pub enum ElfError {
    InvalidMagic,
    UnsupportedClass(u8),
    UnsupportedData(u8),
    InvalidOffset { offset: usize },
    Truncated { offset: usize, needed: usize },
    InvalidSectionIndex(u16),
    MalformedHeader(String),
    InvalidString,
    InvalidAlignment,
    UnsupportedArchitecture(u16),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid ELF magic"),
            Self::UnsupportedClass(c) => write!(f, "Unsupported ELF class: {}", c),
            Self::UnsupportedData(d) => write!(f, "Unsupported ELF data encoding: {}", d),
            Self::InvalidOffset { offset } => write!(f, "Invalid offset: {:#x}", offset),
            Self::Truncated { offset, needed } => {
                write!(f, "Truncated at {:#x}, needed {} bytes", offset, needed)
            }
            Self::InvalidSectionIndex(idx) => write!(f, "Invalid section index: {}", idx),
            Self::MalformedHeader(msg) => write!(f, "Malformed header: {}", msg),
            Self::InvalidString => write!(f, "String not UTF-8"),
            Self::InvalidAlignment => write!(f, "Invalid alignment"),
            Self::UnsupportedArchitecture(arch) => {
                write!(f, "Unsupported architecture: {:#x}", arch)
            }
        }
    }
}

impl std::error::Error for ElfError {}

pub type Result<T> = std::result::Result<T, ElfError>;

/// ELF magic number
pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// ELF class (32-bit or 64-bit)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32 = 1,
    Elf64 = 2,
}

impl ElfClass {
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            1 => Ok(ElfClass::Elf32),
            2 => Ok(ElfClass::Elf64),
            _ => Err(ElfError::UnsupportedClass(val)),
        }
    }

    pub fn bits(&self) -> u8 {
        match self {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 64,
        }
    }
}

/// ELF data encoding (endianness)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfData {
    Little = 1,
    Big = 2,
}

impl ElfData {
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            1 => Ok(ElfData::Little),
            2 => Ok(ElfData::Big),
            _ => Err(ElfError::UnsupportedData(val)),
        }
    }

    pub fn is_little_endian(&self) -> bool {
        matches!(self, ElfData::Little)
    }
}

/// ELF file type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    None = 0,
    Relocatable = 1,
    Executable = 2,
    SharedObject = 3,
    Core = 4,
}

impl From<u16> for ElfType {
    fn from(val: u16) -> Self {
        match val {
            1 => ElfType::Relocatable,
            2 => ElfType::Executable,
            3 => ElfType::SharedObject,
            4 => ElfType::Core,
            _ => ElfType::None,
        }
    }
}

/// ELF machine architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfMachine {
    None,
    Sparc,
    X86,
    Mips,
    PowerPC,
    PowerPC64,
    S390,
    ARM,
    X86_64,
    AArch64,
    RiscV,
    Other(u16),
}

impl From<u16> for ElfMachine {
    fn from(val: u16) -> Self {
        match val {
            0 => ElfMachine::None,
            2 => ElfMachine::Sparc,
            3 => ElfMachine::X86,
            8 => ElfMachine::Mips,
            20 => ElfMachine::PowerPC,
            21 => ElfMachine::PowerPC64,
            22 => ElfMachine::S390,
            40 => ElfMachine::ARM,
            62 => ElfMachine::X86_64,
            183 => ElfMachine::AArch64,
            243 => ElfMachine::RiscV,
            other => ElfMachine::Other(other),
        }
    }
}

/// ELF identification (first 16 bytes)
#[derive(Debug, Clone, Copy)]
pub struct ElfIdent {
    pub class: ElfClass,
    pub data: ElfData,
    pub version: u8,
    pub osabi: u8,
    pub abiversion: u8,
}

/// ELF header
#[derive(Debug, Clone, Copy)]
pub struct ElfHeader {
    pub ident: ElfIdent,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl ElfHeader {
    pub fn file_type(&self) -> ElfType {
        ElfType::from(self.e_type)
    }

    pub fn machine(&self) -> ElfMachine {
        ElfMachine::from(self.e_machine)
    }

    pub fn entry_point(&self) -> u64 {
        self.e_entry
    }

    pub fn is_pie(&self) -> bool {
        self.e_type == 3 // ET_DYN
    }
}

/// Section header
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Section types
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
pub const SHT_GNU_VERSYM: u32 = 0x6fffffff;
pub const SHT_GNU_VERNEED: u32 = 0x6ffffffe;

/// Section flags
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;

/// Special section indices
pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

/// Program header
#[derive(Debug, Clone, Copy)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Program header types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;

/// Program header flags
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

/// Symbol entry
#[derive(Debug, Clone, Copy)]
pub struct Symbol {
    pub st_name: u32,
    pub st_value: u64,
    pub st_size: u64,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
}

impl Symbol {
    pub fn st_bind(&self) -> u8 {
        self.st_info >> 4
    }

    pub fn st_type(&self) -> u8 {
        self.st_info & 0xf
    }

    pub fn is_undefined(&self) -> bool {
        self.st_shndx == SHN_UNDEF
    }

    pub fn is_global(&self) -> bool {
        self.st_bind() == STB_GLOBAL
    }

    pub fn is_weak(&self) -> bool {
        self.st_bind() == STB_WEAK
    }

    pub fn is_function(&self) -> bool {
        self.st_type() == STT_FUNC
    }
}

/// Symbol binding
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

/// Symbol types
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_TLS: u8 = 6;

/// Dynamic entry
#[derive(Debug, Clone, Copy)]
pub struct DynamicEntry {
    pub d_tag: i64,
    pub d_val: u64,
}

/// Dynamic tags
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_GNU_HASH: i64 = 0x6ffffef5;
pub const DT_VERSYM: i64 = 0x6ffffff0;
pub const DT_VERNEED: i64 = 0x6ffffffe;
pub const DT_VERNEEDNUM: i64 = 0x6fffffff;

/// Dynamic flags
pub const DF_BIND_NOW: u64 = 0x8;

/// Relocation entry
#[derive(Debug, Clone, Copy)]
pub struct Relocation {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64, // Only for RELA
}

impl Relocation {
    pub fn symbol_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    pub fn reloc_type(&self) -> u32 {
        self.r_info as u32
    }
}

/// Note header
#[derive(Debug, Clone, Copy)]
pub struct NoteHeader {
    pub n_namesz: u32,
    pub n_descsz: u32,
    pub n_type: u32,
}

/// Note types
pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;

/// Security features
#[derive(Debug, Clone, Copy)]
pub struct SecurityFeatures {
    pub nx: bool,
    pub pie: bool,
    pub relro: RelroLevel,
    pub stack_canary: bool,
    pub fortify: bool,
    pub cfi: bool,
    pub safestack: bool,
    pub asan: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelroLevel {
    None,
    Partial,
    Full,
}

/// Section
pub struct Section<'a> {
    pub header: SectionHeader,
    pub name: &'a str,
    pub data: &'a [u8],
}

impl<'a> Section<'a> {
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn size(&self) -> u64 {
        self.header.sh_size
    }

    pub fn addr(&self) -> u64 {
        self.header.sh_addr
    }

    pub fn is_executable(&self) -> bool {
        (self.header.sh_flags & SHF_EXECINSTR) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.header.sh_flags & SHF_WRITE) != 0
    }

    pub fn is_allocated(&self) -> bool {
        (self.header.sh_flags & SHF_ALLOC) != 0
    }
}

/// Program segment
pub struct Segment<'a> {
    pub header: ProgramHeader,
    pub data: &'a [u8],
}

impl<'a> Segment<'a> {
    pub fn is_executable(&self) -> bool {
        (self.header.p_flags & PF_X) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.header.p_flags & PF_W) != 0
    }

    pub fn is_readable(&self) -> bool {
        (self.header.p_flags & PF_R) != 0
    }

    pub fn contains_vaddr(&self, addr: u64) -> bool {
        addr >= self.header.p_vaddr && addr < self.header.p_vaddr + self.header.p_memsz
    }
}
