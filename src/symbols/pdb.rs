//! Native PDB symbol and type ingestion.
//!
//! This module is intentionally small for the first ingestion slice: it opens a
//! PDB, reports coarse table counts, and locates complete struct/class type
//! records by name.

use std::fmt;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use ::pdb::{
    ClassKind, FallibleIterator, Indirection, PointerMode, PrimitiveKind, PrimitiveType, TypeData,
    TypeFinder, TypeIndex,
};

use crate::formats::pe::{directories::CodeViewRsds, PeError, PeParser};

/// PDB implementation used by the ingestor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbBackend {
    /// The pure-Rust `pdb` crate backend.
    Native,
}

/// Coarse metadata from a PDB file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSummary {
    /// Number of records in the TPI type stream.
    pub type_count: usize,
    /// Number of records in the global symbol stream.
    pub symbol_count: usize,
}

/// Summary for a named PDB struct/class type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbStructSummary {
    /// Struct/class name as stored in the PDB.
    pub name: String,
    /// Declared byte size of the type.
    pub byte_size: u64,
    /// Top-level field count from the class/structure record.
    pub field_count: usize,
}

/// Top-level struct/class layout resolved from a PDB field list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbStructLayout {
    /// Struct/class name as stored in the PDB.
    pub name: String,
    /// Declared byte size of the type.
    pub byte_size: u64,
    /// Field count declared by the class/structure record.
    pub field_count: usize,
    /// Top-level members in PDB field-list order.
    pub fields: Vec<PdbFieldSummary>,
}

/// A top-level PDB struct/class member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbFieldSummary {
    /// Zero-based ordinal in the collected FieldList walk.
    pub ordinal: usize,
    /// Field name as stored in the PDB.
    pub name: String,
    /// Byte offset of the member storage.
    pub byte_offset: u64,
    /// Best-effort C-like type spelling resolved from the raw TypeIndex.
    pub type_name: Option<String>,
    /// Coarse PDB type kind for the resolved field type.
    pub type_kind: Option<String>,
    /// Raw PDB TypeIndex of the field type.
    pub type_index: u32,
    /// Bitfield width, when this member's type is LF_BITFIELD.
    pub bit_size: Option<u8>,
    /// Bit offset within the storage type, when this member is a bitfield.
    pub bit_position: Option<u8>,
    /// Raw PDB TypeIndex of the bitfield storage type.
    pub bit_underlying_type_index: Option<u32>,
}

/// A PDB procedure or member-function type record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbFunctionPrototype {
    /// Raw TypeIndex of the LF_PROCEDURE or LF_MFUNCTION record.
    pub type_index: u32,
    /// Coarse record kind: "procedure" or "member_function".
    pub kind: String,
    /// Raw return TypeIndex, when present.
    pub return_type_index: Option<u32>,
    /// Best-effort C-like return type spelling.
    pub return_type_name: Option<String>,
    /// Number of parameters declared by the function type record.
    pub argument_count: u16,
    /// Raw TypeIndex values from the referenced LF_ARGLIST record.
    pub argument_type_indices: Vec<u32>,
    /// Best-effort C-like argument type spellings aligned with `argument_type_indices`.
    pub argument_type_names: Vec<Option<String>>,
    /// Raw CodeView calling convention byte.
    pub calling_convention: u8,
    /// For LF_MFUNCTION, raw TypeIndex of the parent class.
    pub class_type_index: Option<u32>,
    /// For LF_MFUNCTION, raw TypeIndex of the `this` pointer type.
    pub this_pointer_type_index: Option<u32>,
}

/// Errors while resolving a PE's CodeView record to a cached PDB.
#[derive(Debug)]
pub enum PdbPeError {
    /// Filesystem read/open failure.
    Io(std::io::Error),
    /// PE parser failure.
    Pe(PeError),
    /// PDB parser failure.
    Pdb(::pdb::Error),
}

impl fmt::Display for PdbPeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Pe(error) => write!(f, "PE parse error: {error}"),
            Self::Pdb(error) => write!(f, "PDB parse error: {error}"),
        }
    }
}

impl std::error::Error for PdbPeError {}

impl From<std::io::Error> for PdbPeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PeError> for PdbPeError {
    fn from(error: PeError) -> Self {
        Self::Pe(error)
    }
}

impl From<::pdb::Error> for PdbPeError {
    fn from(error: ::pdb::Error) -> Self {
        Self::Pdb(error)
    }
}

/// Result type for PE-to-PDB cache wiring.
pub type PdbPeResult<T> = std::result::Result<T, PdbPeError>;

/// A PE CodeView record resolved to a local PDB cache hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PePdbSource {
    /// PE binary path that supplied the CodeView RSDS record.
    pub pe_path: PathBuf,
    /// Local cached PDB path.
    pub pdb_path: PathBuf,
    /// Parsed CodeView RSDS metadata.
    pub codeview: CodeViewRsds,
    /// Native PDB ingestor for the cache hit.
    pub ingestor: PdbIngestor,
}

impl PePdbSource {
    /// Locate a complete struct/class and return its top-level fields.
    pub fn find_struct_layout(&self, name: &str) -> ::pdb::Result<Option<PdbStructLayout>> {
        self.ingestor.find_struct_layout(name)
    }

    /// Enumerate procedure and member-function type records.
    pub fn function_prototypes(&self) -> ::pdb::Result<Vec<PdbFunctionPrototype>> {
        self.ingestor.function_prototypes()
    }
}

/// PDB-backed data pulled from a PE's matching cached PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PePdbAnalysis {
    /// PE binary path that supplied the CodeView RSDS record.
    pub pe_path: PathBuf,
    /// Local cached PDB path.
    pub pdb_path: PathBuf,
    /// Parsed CodeView RSDS metadata.
    pub codeview: CodeViewRsds,
    /// Requested struct/class layouts found in the PDB.
    pub struct_layouts: Vec<PdbStructLayout>,
    /// Procedure and member-function prototype rows.
    pub function_prototypes: Vec<PdbFunctionPrototype>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PdbTypeDescriptor {
    name: String,
    kind: &'static str,
}

/// Entry point for reading PDB symbol and type information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIngestor {
    path: PathBuf,
    backend: PdbBackend,
}

impl PdbIngestor {
    /// Create an ingestor using the native Rust PDB backend.
    pub fn open<P: Into<PathBuf>>(path: P) -> Self {
        Self::with_backend(path, PdbBackend::Native)
    }

    /// Create an ingestor with an explicit backend.
    pub fn with_backend<P: Into<PathBuf>>(path: P, backend: PdbBackend) -> Self {
        Self {
            path: path.into(),
            backend,
        }
    }

    /// Return the selected backend.
    pub fn backend(&self) -> PdbBackend {
        self.backend
    }

    /// Return the PDB path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read coarse type and symbol counts from the PDB.
    pub fn summarize(&self) -> ::pdb::Result<PdbSummary> {
        match self.backend {
            PdbBackend::Native => self.summarize_native(),
        }
    }

    /// Locate a complete struct/class type record by exact PDB name.
    pub fn find_struct(&self, name: &str) -> ::pdb::Result<Option<PdbStructSummary>> {
        let layout = self.find_struct_layout(name)?;
        Ok(layout.map(|layout| PdbStructSummary {
            name: layout.name,
            byte_size: layout.byte_size,
            field_count: layout.field_count,
        }))
    }

    /// Locate a complete struct/class and return its top-level fields.
    pub fn find_struct_layout(&self, name: &str) -> ::pdb::Result<Option<PdbStructLayout>> {
        match self.backend {
            PdbBackend::Native => self.find_struct_layout_native(name),
        }
    }

    /// Enumerate procedure and member-function type records.
    pub fn function_prototypes(&self) -> ::pdb::Result<Vec<PdbFunctionPrototype>> {
        match self.backend {
            PdbBackend::Native => self.function_prototypes_native(),
        }
    }

    /// Resolve a PE's CodeView RSDS record against a local PDB cache.
    pub fn from_pe_cache<P: AsRef<Path>, C: AsRef<Path>>(
        pe_path: P,
        cache_dir: C,
    ) -> PdbPeResult<Option<PePdbSource>> {
        let pe_path = pe_path.as_ref();
        let data = fs::read(pe_path)?;
        let parser = PeParser::new(&data)?;
        let Some(codeview) = parser.codeview_rsds()?.cloned() else {
            return Ok(None);
        };
        let Some(pdb_path) = codeview.resolve_pdb_path(cache_dir.as_ref()) else {
            return Ok(None);
        };

        Ok(Some(PePdbSource {
            pe_path: pe_path.to_path_buf(),
            ingestor: Self::open(pdb_path.clone()),
            pdb_path,
            codeview,
        }))
    }

    /// Resolve a PE's matching PDB and return selected layouts plus all prototypes.
    pub fn analyze_pe_cache<P: AsRef<Path>, C: AsRef<Path>>(
        pe_path: P,
        cache_dir: C,
        struct_names: &[&str],
    ) -> PdbPeResult<Option<PePdbAnalysis>> {
        let Some(source) = Self::from_pe_cache(pe_path, cache_dir)? else {
            return Ok(None);
        };

        let mut struct_layouts = Vec::new();
        for name in struct_names {
            if let Some(layout) = source.find_struct_layout(name)? {
                struct_layouts.push(layout);
            }
        }
        let function_prototypes = source.function_prototypes()?;

        Ok(Some(PePdbAnalysis {
            pe_path: source.pe_path,
            pdb_path: source.pdb_path,
            codeview: source.codeview,
            struct_layouts,
            function_prototypes,
        }))
    }

    fn open_native(&self) -> ::pdb::Result<::pdb::PDB<'static, File>> {
        let file = File::open(&self.path)?;
        ::pdb::PDB::open(file)
    }

    fn summarize_native(&self) -> ::pdb::Result<PdbSummary> {
        let mut pdb = self.open_native()?;
        let type_count = pdb.type_information()?.len();
        let mut symbol_count = 0usize;

        match pdb.global_symbols() {
            Ok(symbol_table) => {
                let mut symbols = symbol_table.iter();
                while symbols.next()?.is_some() {
                    symbol_count += 1;
                }
            }
            Err(::pdb::Error::GlobalSymbolsNotFound) => {}
            Err(error) => return Err(error),
        }

        Ok(PdbSummary {
            type_count,
            symbol_count,
        })
    }

    fn find_struct_layout_native(&self, name: &str) -> ::pdb::Result<Option<PdbStructLayout>> {
        let mut pdb = self.open_native()?;
        let type_information = pdb.type_information()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next()? {
            type_finder.update(&iter);

            let parsed = match typ.parse() {
                Ok(parsed) => parsed,
                Err(::pdb::Error::UnimplementedTypeKind(_)) => continue,
                Err(error) => return Err(error),
            };

            if let TypeData::Class(class) = parsed {
                if class.name.as_bytes() == name.as_bytes() && !class.properties.forward_reference()
                {
                    let fields = match class.fields {
                        Some(fields_index) => {
                            collect_field_list_members(&type_finder, fields_index)?
                        }
                        None => Vec::new(),
                    };

                    return Ok(Some(PdbStructLayout {
                        name: class.name.to_string().into_owned(),
                        byte_size: class.size,
                        field_count: usize::from(class.count),
                        fields,
                    }));
                }
            }
        }

        Ok(None)
    }

    fn function_prototypes_native(&self) -> ::pdb::Result<Vec<PdbFunctionPrototype>> {
        let mut pdb = self.open_native()?;
        let type_information = pdb.type_information()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();
        let mut prototypes = Vec::new();

        while let Some(typ) = iter.next()? {
            type_finder.update(&iter);
            let type_index = typ.index();

            let parsed = match typ.parse() {
                Ok(parsed) => parsed,
                Err(::pdb::Error::UnimplementedTypeKind(_)) => continue,
                Err(error) => return Err(error),
            };

            match parsed {
                TypeData::Procedure(procedure) => {
                    prototypes.push(build_procedure_prototype(
                        &type_finder,
                        type_index,
                        procedure,
                    )?);
                }
                TypeData::MemberFunction(member_function) => {
                    prototypes.push(build_member_function_prototype(
                        &type_finder,
                        type_index,
                        member_function,
                    )?);
                }
                _ => {}
            }
        }

        Ok(prototypes)
    }
}

fn build_procedure_prototype(
    type_finder: &TypeFinder<'_>,
    type_index: TypeIndex,
    procedure: ::pdb::ProcedureType,
) -> ::pdb::Result<PdbFunctionPrototype> {
    let argument_types = collect_argument_types(type_finder, procedure.argument_list)?;
    let argument_type_names = describe_type_names(type_finder, &argument_types)?;
    let return_type_name = match procedure.return_type {
        Some(return_type) => describe_type_name(type_finder, return_type)?,
        None => None,
    };

    Ok(PdbFunctionPrototype {
        type_index: type_index.0,
        kind: "procedure".to_string(),
        return_type_index: procedure.return_type.map(|return_type| return_type.0),
        return_type_name,
        argument_count: procedure.parameter_count,
        argument_type_indices: argument_types
            .iter()
            .map(|argument_type| argument_type.0)
            .collect(),
        argument_type_names,
        calling_convention: procedure.attributes.calling_convention(),
        class_type_index: None,
        this_pointer_type_index: None,
    })
}

fn build_member_function_prototype(
    type_finder: &TypeFinder<'_>,
    type_index: TypeIndex,
    member_function: ::pdb::MemberFunctionType,
) -> ::pdb::Result<PdbFunctionPrototype> {
    let argument_types = collect_argument_types(type_finder, member_function.argument_list)?;
    let argument_type_names = describe_type_names(type_finder, &argument_types)?;

    Ok(PdbFunctionPrototype {
        type_index: type_index.0,
        kind: "member_function".to_string(),
        return_type_index: Some(member_function.return_type.0),
        return_type_name: describe_type_name(type_finder, member_function.return_type)?,
        argument_count: member_function.parameter_count,
        argument_type_indices: argument_types
            .iter()
            .map(|argument_type| argument_type.0)
            .collect(),
        argument_type_names,
        calling_convention: member_function.attributes.calling_convention(),
        class_type_index: Some(member_function.class_type.0),
        this_pointer_type_index: member_function
            .this_pointer_type
            .map(|this_pointer_type| this_pointer_type.0),
    })
}

fn collect_argument_types(
    type_finder: &TypeFinder<'_>,
    argument_list: TypeIndex,
) -> ::pdb::Result<Vec<TypeIndex>> {
    let typ = match type_finder.find(argument_list) {
        Ok(typ) => typ,
        Err(::pdb::Error::TypeNotFound(_)) | Err(::pdb::Error::TypeNotIndexed(_, _)) => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };

    match typ.parse() {
        Ok(TypeData::ArgumentList(argument_list)) => Ok(argument_list.arguments),
        Ok(_) | Err(::pdb::Error::UnimplementedTypeKind(_)) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn describe_type_name(
    type_finder: &TypeFinder<'_>,
    type_index: TypeIndex,
) -> ::pdb::Result<Option<String>> {
    Ok(describe_type(type_finder, type_index)?.map(|descriptor| descriptor.name))
}

fn describe_type_names(
    type_finder: &TypeFinder<'_>,
    type_indices: &[TypeIndex],
) -> ::pdb::Result<Vec<Option<String>>> {
    let mut names = Vec::with_capacity(type_indices.len());
    for type_index in type_indices {
        names.push(describe_type_name(type_finder, *type_index)?);
    }
    Ok(names)
}

fn collect_field_list_members(
    type_finder: &TypeFinder<'_>,
    fields_index: TypeIndex,
) -> ::pdb::Result<Vec<PdbFieldSummary>> {
    let mut fields = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    collect_field_list_members_inner(type_finder, fields_index, &mut seen, &mut fields)?;
    Ok(fields)
}

fn collect_field_list_members_inner(
    type_finder: &TypeFinder<'_>,
    fields_index: TypeIndex,
    seen: &mut std::collections::BTreeSet<u32>,
    fields: &mut Vec<PdbFieldSummary>,
) -> ::pdb::Result<()> {
    if !seen.insert(fields_index.0) {
        return Ok(());
    }

    let typ = type_finder.find(fields_index)?;
    let parsed = match typ.parse() {
        Ok(parsed) => parsed,
        Err(::pdb::Error::UnimplementedTypeKind(_)) => return Ok(()),
        Err(error) => return Err(error),
    };

    let TypeData::FieldList(field_list) = parsed else {
        return Ok(());
    };

    for field in field_list.fields {
        if let TypeData::Member(member) = field {
            let bitfield = resolve_bitfield(type_finder, member.field_type)?;
            let type_descriptor = describe_type(type_finder, member.field_type)?;
            fields.push(PdbFieldSummary {
                ordinal: fields.len(),
                name: member.name.to_string().into_owned(),
                byte_offset: member.offset,
                type_name: type_descriptor
                    .as_ref()
                    .map(|descriptor| descriptor.name.clone()),
                type_kind: type_descriptor
                    .as_ref()
                    .map(|descriptor| descriptor.kind.to_string()),
                type_index: member.field_type.0,
                bit_size: bitfield.as_ref().map(|bitfield| bitfield.length),
                bit_position: bitfield.as_ref().map(|bitfield| bitfield.position),
                bit_underlying_type_index: bitfield
                    .as_ref()
                    .map(|bitfield| bitfield.underlying_type.0),
            });
        }
    }

    if let Some(continuation) = field_list.continuation {
        collect_field_list_members_inner(type_finder, continuation, seen, fields)?;
    }

    Ok(())
}

fn describe_type(
    type_finder: &TypeFinder<'_>,
    type_index: TypeIndex,
) -> ::pdb::Result<Option<PdbTypeDescriptor>> {
    let mut seen = std::collections::BTreeSet::new();
    describe_type_inner(type_finder, type_index, &mut seen, 0)
}

fn describe_type_inner(
    type_finder: &TypeFinder<'_>,
    type_index: TypeIndex,
    seen: &mut std::collections::BTreeSet<u32>,
    depth: usize,
) -> ::pdb::Result<Option<PdbTypeDescriptor>> {
    if depth > 32 || !seen.insert(type_index.0) {
        return Ok(None);
    }

    let typ = match type_finder.find(type_index) {
        Ok(typ) => typ,
        Err(::pdb::Error::TypeNotFound(_)) | Err(::pdb::Error::TypeNotIndexed(_, _)) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    let parsed = match typ.parse() {
        Ok(parsed) => parsed,
        Err(::pdb::Error::UnimplementedTypeKind(_)) => return Ok(None),
        Err(error) => return Err(error),
    };

    let descriptor = match parsed {
        TypeData::Primitive(primitive) => describe_primitive(primitive),
        TypeData::Pointer(pointer) => {
            let underlying =
                describe_type_inner(type_finder, pointer.underlying_type, seen, depth + 1)?;
            let base = underlying
                .map(|descriptor| descriptor.name)
                .unwrap_or_else(|| "unknown".to_string());
            PdbTypeDescriptor {
                name: pointer_type_name(&base, pointer.attributes.pointer_mode()),
                kind: "pointer",
            }
        }
        TypeData::Modifier(modifier) => {
            let underlying =
                describe_type_inner(type_finder, modifier.underlying_type, seen, depth + 1)?;
            let Some(mut descriptor) = underlying else {
                return Ok(None);
            };
            let mut qualifiers = Vec::new();
            if modifier.constant {
                qualifiers.push("const");
            }
            if modifier.volatile {
                qualifiers.push("volatile");
            }
            if modifier.unaligned {
                qualifiers.push("unaligned");
            }
            if !qualifiers.is_empty() {
                descriptor.name = format!("{} {}", qualifiers.join(" "), descriptor.name);
            }
            descriptor
        }
        TypeData::Array(array) => {
            let element = describe_type_inner(type_finder, array.element_type, seen, depth + 1)?;
            let Some(element) = element else {
                return Ok(None);
            };
            let suffix = array_dimension_suffix(type_finder, array.element_type, &array.dimensions);
            PdbTypeDescriptor {
                name: format!("{}{}", element.name, suffix),
                kind: "array",
            }
        }
        TypeData::Class(class) => PdbTypeDescriptor {
            name: class.name.to_string().into_owned(),
            kind: match class.kind {
                ClassKind::Class => "class",
                ClassKind::Struct => "struct",
                ClassKind::Interface => "interface",
            },
        },
        TypeData::Union(union) => PdbTypeDescriptor {
            name: union.name.to_string().into_owned(),
            kind: "union",
        },
        TypeData::Enumeration(enumeration) => PdbTypeDescriptor {
            name: enumeration.name.to_string().into_owned(),
            kind: "enum",
        },
        TypeData::Bitfield(bitfield) => {
            let underlying =
                describe_type_inner(type_finder, bitfield.underlying_type, seen, depth + 1)?;
            let base = underlying
                .map(|descriptor| descriptor.name)
                .unwrap_or_else(|| "unknown".to_string());
            PdbTypeDescriptor {
                name: format!("{}:{}", base, bitfield.length),
                kind: "bitfield",
            }
        }
        TypeData::Procedure(_) => PdbTypeDescriptor {
            name: "procedure".to_string(),
            kind: "procedure",
        },
        TypeData::MemberFunction(_) => PdbTypeDescriptor {
            name: "member_function".to_string(),
            kind: "member_function",
        },
        _ => return Ok(None),
    };

    Ok(Some(descriptor))
}

fn describe_primitive(primitive: PrimitiveType) -> PdbTypeDescriptor {
    let base = primitive_kind_name(primitive.kind);
    match primitive.indirection {
        Some(indirection) => PdbTypeDescriptor {
            name: primitive_indirection_type_name(base, indirection),
            kind: "pointer",
        },
        None => PdbTypeDescriptor {
            name: base.to_string(),
            kind: "primitive",
        },
    }
}

fn primitive_kind_name(kind: PrimitiveKind) -> &'static str {
    match kind {
        PrimitiveKind::NoType => "no_type",
        PrimitiveKind::Void => "void",
        PrimitiveKind::Char | PrimitiveKind::RChar => "char",
        PrimitiveKind::UChar => "uchar",
        PrimitiveKind::WChar => "wchar",
        PrimitiveKind::RChar16 => "char16",
        PrimitiveKind::RChar32 => "char32",
        PrimitiveKind::I8 => "int8",
        PrimitiveKind::U8 => "uint8",
        PrimitiveKind::Short | PrimitiveKind::I16 => "short",
        PrimitiveKind::UShort | PrimitiveKind::U16 => "ushort",
        PrimitiveKind::Long | PrimitiveKind::I32 => "long",
        PrimitiveKind::ULong | PrimitiveKind::U32 => "ulong",
        PrimitiveKind::Quad | PrimitiveKind::I64 => "long64",
        PrimitiveKind::UQuad | PrimitiveKind::U64 => "ulong64",
        PrimitiveKind::Octa | PrimitiveKind::I128 => "int128",
        PrimitiveKind::UOcta | PrimitiveKind::U128 => "uint128",
        PrimitiveKind::F16 => "float16",
        PrimitiveKind::F32 | PrimitiveKind::F32PP => "float",
        PrimitiveKind::F48 => "float48",
        PrimitiveKind::F64 => "double",
        PrimitiveKind::F80 => "float80",
        PrimitiveKind::F128 => "float128",
        PrimitiveKind::Complex32 => "complex32",
        PrimitiveKind::Complex64 => "complex64",
        PrimitiveKind::Complex80 => "complex80",
        PrimitiveKind::Complex128 => "complex128",
        PrimitiveKind::Bool8 => "bool8",
        PrimitiveKind::Bool16 => "bool16",
        PrimitiveKind::Bool32 => "bool32",
        PrimitiveKind::Bool64 => "bool64",
        PrimitiveKind::HRESULT => "HRESULT",
        _ => "primitive",
    }
}

fn primitive_indirection_type_name(base: &str, indirection: Indirection) -> String {
    match indirection {
        Indirection::Near16
        | Indirection::Far16
        | Indirection::Huge16
        | Indirection::Near32
        | Indirection::Far32
        | Indirection::Near64
        | Indirection::Near128 => format!("{} *", base),
    }
}

fn pointer_type_name(base: &str, mode: PointerMode) -> String {
    match mode {
        PointerMode::Pointer | PointerMode::Member | PointerMode::MemberFunction => {
            format!("{} *", base)
        }
        PointerMode::LValueReference => format!("{} &", base),
        PointerMode::RValueReference => format!("{} &&", base),
    }
}

fn array_dimension_suffix(
    type_finder: &TypeFinder<'_>,
    element_type: TypeIndex,
    dimensions: &[u32],
) -> String {
    if dimensions.is_empty() {
        return "[]".to_string();
    }

    let mut divisor = type_size(type_finder, element_type).unwrap_or(0);
    let mut suffix = String::new();
    for dimension in dimensions {
        let count = if divisor > 0 && dimension % divisor == 0 {
            dimension / divisor
        } else {
            *dimension
        };
        suffix.push('[');
        suffix.push_str(&count.to_string());
        suffix.push(']');
        divisor = *dimension;
    }
    suffix
}

fn type_size(type_finder: &TypeFinder<'_>, type_index: TypeIndex) -> Option<u32> {
    let typ = type_finder.find(type_index).ok()?;
    let parsed = typ.parse().ok()?;
    match parsed {
        TypeData::Primitive(primitive) => primitive_type_size(primitive),
        TypeData::Pointer(pointer) => Some(u32::from(pointer.attributes.size())),
        TypeData::Modifier(modifier) => type_size(type_finder, modifier.underlying_type),
        TypeData::Array(array) => array.dimensions.last().copied(),
        TypeData::Class(class) => u32::try_from(class.size).ok(),
        TypeData::Union(union) => u32::try_from(union.size).ok(),
        TypeData::Enumeration(enumeration) => type_size(type_finder, enumeration.underlying_type),
        TypeData::Bitfield(bitfield) => type_size(type_finder, bitfield.underlying_type),
        _ => None,
    }
}

fn primitive_type_size(primitive: PrimitiveType) -> Option<u32> {
    if primitive.indirection.is_some() {
        return Some(8);
    }

    match primitive.kind {
        PrimitiveKind::NoType | PrimitiveKind::Void => Some(0),
        PrimitiveKind::Char
        | PrimitiveKind::UChar
        | PrimitiveKind::RChar
        | PrimitiveKind::I8
        | PrimitiveKind::U8
        | PrimitiveKind::Bool8 => Some(1),
        PrimitiveKind::WChar
        | PrimitiveKind::RChar16
        | PrimitiveKind::Short
        | PrimitiveKind::UShort
        | PrimitiveKind::I16
        | PrimitiveKind::U16
        | PrimitiveKind::F16
        | PrimitiveKind::Bool16 => Some(2),
        PrimitiveKind::RChar32
        | PrimitiveKind::Long
        | PrimitiveKind::ULong
        | PrimitiveKind::I32
        | PrimitiveKind::U32
        | PrimitiveKind::F32
        | PrimitiveKind::F32PP
        | PrimitiveKind::Bool32
        | PrimitiveKind::HRESULT => Some(4),
        PrimitiveKind::Quad
        | PrimitiveKind::UQuad
        | PrimitiveKind::I64
        | PrimitiveKind::U64
        | PrimitiveKind::F64
        | PrimitiveKind::Complex32
        | PrimitiveKind::Bool64 => Some(8),
        PrimitiveKind::Octa
        | PrimitiveKind::UOcta
        | PrimitiveKind::I128
        | PrimitiveKind::U128
        | PrimitiveKind::F128
        | PrimitiveKind::Complex64 => Some(16),
        PrimitiveKind::F48 => Some(6),
        PrimitiveKind::F80 | PrimitiveKind::Complex80 => Some(10),
        PrimitiveKind::Complex128 => Some(32),
        _ => None,
    }
}

fn resolve_bitfield(
    type_finder: &TypeFinder<'_>,
    type_index: TypeIndex,
) -> ::pdb::Result<Option<::pdb::BitfieldType>> {
    let typ = match type_finder.find(type_index) {
        Ok(typ) => typ,
        Err(::pdb::Error::TypeNotFound(_)) | Err(::pdb::Error::TypeNotIndexed(_, _)) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    match typ.parse() {
        Ok(TypeData::Bitfield(bitfield)) => Ok(Some(bitfield)),
        Ok(_) | Err(::pdb::Error::UnimplementedTypeKind(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<PathBuf> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
            .join(name);
        path.is_file().then_some(path)
    }

    fn fixture_pdb(name: &str) -> Option<PathBuf> {
        fixture(name)
    }

    fn fixture_cache_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
    }

    #[test]
    fn pdb_ingestor_loads_ntkrnlmp_and_finds_eprocess() {
        let Some(path) = fixture_pdb("ntkrnlmp.pdb") else {
            eprintln!("skipping PDB fixture test: ntkrnlmp.pdb is not present");
            return;
        };

        let ingestor = PdbIngestor::open(path);
        assert_eq!(ingestor.backend(), PdbBackend::Native);

        let summary = ingestor.summarize().expect("summarize ntkrnlmp.pdb");
        assert!(
            summary.type_count > 1_000,
            "unexpectedly small type stream: {}",
            summary.type_count
        );
        assert!(
            summary.symbol_count > 0,
            "expected at least one global symbol"
        );

        let eprocess = ingestor
            .find_struct("_EPROCESS")
            .expect("find _EPROCESS")
            .expect("_EPROCESS should exist in ntkrnlmp.pdb");

        assert_eq!(eprocess.name, "_EPROCESS");
        assert_eq!(eprocess.byte_size, 2_944);
        assert!(
            eprocess.field_count >= 140,
            "unexpected _EPROCESS field count: {}",
            eprocess.field_count
        );
    }

    #[test]
    fn pdb_ingestor_extracts_eprocess_field_list() {
        let Some(path) = fixture_pdb("ntkrnlmp.pdb") else {
            eprintln!("skipping PDB fixture test: ntkrnlmp.pdb is not present");
            return;
        };

        let ingestor = PdbIngestor::open(path);
        let eprocess = ingestor
            .find_struct_layout("_EPROCESS")
            .expect("find _EPROCESS layout")
            .expect("_EPROCESS should exist in ntkrnlmp.pdb");

        assert_eq!(eprocess.name, "_EPROCESS");
        assert_eq!(eprocess.byte_size, 2_944);
        assert!(
            eprocess.fields.len() >= 141,
            "expected at least the common Ghidra/pdb-struct fields, got {}",
            eprocess.fields.len()
        );

        let expected = [
            ("Pcb", 0),
            ("UniqueProcessId", 1088),
            ("ActiveProcessLinks", 1096),
            ("Token", 1208),
            ("ObjectTable", 1392),
            ("ImageFilePointer", 1440),
            ("ImageFileName", 1448),
            ("ThreadListHead", 1504),
            ("VadRoot", 2008),
            ("Protection", 2170),
        ];

        for (name, offset) in expected {
            let field = eprocess
                .fields
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("missing _EPROCESS field {name}"));
            assert_eq!(
                field.byte_offset, offset,
                "unexpected _EPROCESS offset for {name}"
            );
            assert_ne!(field.type_index, 0, "missing raw TypeIndex for {name}");
        }

        let expected_type_names = [
            ("UniqueProcessId", "void *", "pointer"),
            ("ActiveProcessLinks", "_LIST_ENTRY", "struct"),
            ("Token", "_EX_FAST_REF", "struct"),
            ("ImageFilePointer", "_FILE_OBJECT *", "pointer"),
            ("ImageFileName", "uchar[15]", "array"),
            ("VadRoot", "_RTL_AVL_TREE", "struct"),
            ("Protection", "_PS_PROTECTION", "struct"),
        ];

        for (name, type_name, type_kind) in expected_type_names {
            let field = eprocess
                .fields
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("missing _EPROCESS field {name}"));
            assert_eq!(
                field.type_name.as_deref(),
                Some(type_name),
                "unexpected _EPROCESS type name for {name}"
            );
            assert_eq!(
                field.type_kind.as_deref(),
                Some(type_kind),
                "unexpected _EPROCESS type kind for {name}"
            );
        }

        let last_app_state = eprocess
            .fields
            .iter()
            .find(|field| field.name == "LastAppState")
            .expect("LastAppState bitfield should be exposed");
        assert_eq!(last_app_state.byte_offset, 2336);
        assert_eq!(last_app_state.type_name.as_deref(), Some("ulong64:3"));
        assert_eq!(last_app_state.type_kind.as_deref(), Some("bitfield"));
        assert_eq!(last_app_state.bit_size, Some(3));
        assert_eq!(last_app_state.bit_position, Some(61));
        assert!(last_app_state.bit_underlying_type_index.is_some());
    }

    #[test]
    fn pdb_ingestor_extracts_function_prototypes() {
        let Some(path) = fixture_pdb("ntkrnlmp.pdb") else {
            eprintln!("skipping PDB fixture test: ntkrnlmp.pdb is not present");
            return;
        };

        let ingestor = PdbIngestor::open(path);
        let prototypes = ingestor
            .function_prototypes()
            .expect("extract function prototypes");
        assert!(
            prototypes.len() > 100,
            "expected many ntkrnlmp function prototypes, got {}",
            prototypes.len()
        );

        let prototype = prototypes
            .iter()
            .find(|prototype| {
                prototype.argument_count >= 2
                    && prototype.argument_type_indices.len()
                        == usize::from(prototype.argument_count)
                    && prototype.return_type_index.is_some()
                    && prototype.return_type_name.is_some()
                    && prototype.argument_type_names.iter().any(Option::is_some)
            })
            .expect("expected a non-trivial function prototype");

        assert!(
            matches!(prototype.kind.as_str(), "procedure" | "member_function"),
            "unexpected prototype kind: {}",
            prototype.kind
        );
        assert_eq!(
            prototype.argument_type_names.len(),
            prototype.argument_type_indices.len(),
            "argument type names should align with raw argument indexes"
        );
    }

    #[test]
    fn pdb_ingestor_resolves_fixture_pe_cache_hit() {
        let Some(pe_path) = fixture("ntoskrnl.exe") else {
            eprintln!("skipping PE/PDB cache test: ntoskrnl.exe is not present");
            return;
        };
        let Some(_pdb_path) = fixture_pdb("ntkrnlmp.pdb") else {
            eprintln!("skipping PE/PDB cache test: ntkrnlmp.pdb is not present");
            return;
        };

        let analysis = PdbIngestor::analyze_pe_cache(&pe_path, fixture_cache_dir(), &["_EPROCESS"])
            .expect("analyze PE through cached PDB")
            .expect("expected PE/PDB cache hit");

        assert_eq!(analysis.codeview.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(
            analysis.codeview.guid_age_key(),
            "CF32DE2E4A334C7C06FB63FCB6FAFB5C1"
        );
        assert_eq!(analysis.pdb_path.file_name().unwrap(), "ntkrnlmp.pdb");

        let eprocess = analysis
            .struct_layouts
            .iter()
            .find(|layout| layout.name == "_EPROCESS")
            .expect("expected _EPROCESS layout from PE cache hit");
        assert_eq!(eprocess.byte_size, 2_944);
        assert!(
            analysis.function_prototypes.len() > 100,
            "expected function prototypes from PE cache hit"
        );
    }

    #[test]
    fn pdb_ingestor_resolves_microsoft_symbol_cache_if_present() {
        let Some(pe_path) = fixture("ntoskrnl.exe") else {
            eprintln!("skipping Microsoft cache test: ntoskrnl.exe is not present");
            return;
        };
        let cache_dir = PathBuf::from("/nas4/data/symbol-cache/microsoft");
        if !cache_dir.is_dir() {
            eprintln!(
                "skipping Microsoft cache test: {} absent",
                cache_dir.display()
            );
            return;
        }

        let source = PdbIngestor::from_pe_cache(&pe_path, &cache_dir)
            .expect("resolve PE through Microsoft symbol cache")
            .expect("expected Microsoft symbol-cache hit");

        assert_eq!(source.codeview.pdb_name, "ntkrnlmp.pdb");
        assert!(source
            .pdb_path
            .ends_with("ntkrnlmp.pdb/CF32DE2E4A334C7C06FB63FCB6FAFB5C1/ntkrnlmp.pdb"));
        assert!(source.find_struct_layout("_EPROCESS").unwrap().is_some());
    }
}
