//! Exact symbol, import, export, and relocation import from one parsed object.
//!
//! Only facts a program table states verbatim are imported here. No name
//! heuristic, catalog resemblance, or library prototype is applied.

use std::collections::BTreeMap;

use object::read::elf::{ElfFile, FileHeader, Sym};
use object::read::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, ReadRef};
use object::{
    ObjectKind, RelocationFlags, RelocationKind, RelocationTarget, SymbolKind as ObjectSymbolKind,
    SymbolSection,
};

use crate::program::image::ProgramImage;

use super::{
    demangled_name, ReferenceKind, SymbolAuthority, SymbolBinding, SymbolDefinition,
    SymbolEvidence, SymbolFact, SymbolIncompleteness, SymbolKind, SymbolReference, SymbolSource,
    SymbolStore,
};

/// Module and version pairs declared for one dynamic name.
type VersionMap = BTreeMap<String, Vec<(Option<String>, Option<String>)>>;

impl SymbolStore {
    /// Import every exact symbol, import, export, and relocation fact one
    /// parsed object states.
    pub fn import_object(&mut self, object: &object::read::File<'_>, image: &ProgramImage) {
        if object.kind() == ObjectKind::Relocatable {
            self.note_incomplete(SymbolIncompleteness::SectionRelativeAddresses);
        }
        if object.symbol_table().is_none() {
            self.note_incomplete(SymbolIncompleteness::NoObjectSymbolTable);
        }
        if object.dynamic_symbol_table().is_none() {
            self.note_incomplete(SymbolIncompleteness::NoDynamicSymbolTable);
        }

        let versions = elf_symbol_versions(object);
        self.import_symbols(
            object.symbols(),
            SymbolSource::ObjectSymbolTable,
            image,
            &VersionMap::new(),
        );
        self.import_symbols(
            object.dynamic_symbols(),
            SymbolSource::DynamicSymbolTable,
            image,
            &versions,
        );
        self.import_imports(object);
        self.import_exports(object, image);
        self.import_static_relocations(object);
        self.import_dynamic_relocations(object);
    }

    fn import_symbols<'data, S: ObjectSymbol<'data>>(
        &mut self,
        symbols: impl Iterator<Item = S>,
        source: SymbolSource,
        image: &ProgramImage,
        versions: &VersionMap,
    ) {
        for symbol in symbols {
            let Ok(name) = symbol.name() else {
                self.note_incomplete(SymbolIncompleteness::UnreadableTable("symbol name"));
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let definition = definition_of(&symbol, image);
            let fact = SymbolFact::new(
                symbol_kind(symbol.kind()),
                binding_of(&symbol),
                definition,
                SymbolEvidence::new(SymbolAuthority::Binary, source),
            );
            let Ok(id) = self.declare(name, fact) else {
                continue;
            };
            for (module, version) in versions.get(name).into_iter().flatten() {
                let mut evidence = SymbolEvidence::new(SymbolAuthority::Binary, source);
                evidence.module.clone_from(module);
                evidence.version.clone_from(version);
                self.attest(name, evidence);
            }
            if let Some(alias) = demangled_name(name) {
                self.add_name(id, alias);
            }
        }
    }

    fn import_imports(&mut self, object: &object::read::File<'_>) {
        let Ok(imports) = object.imports() else {
            self.note_incomplete(SymbolIncompleteness::UnreadableTable("import table"));
            return;
        };
        for import in imports {
            let (Ok(name), Ok(library)) = (
                std::str::from_utf8(import.name()),
                std::str::from_utf8(import.library()),
            ) else {
                self.note_incomplete(SymbolIncompleteness::UnreadableTable("import table"));
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let mut evidence =
                SymbolEvidence::new(SymbolAuthority::Binary, SymbolSource::ImportTable);
            if !library.is_empty() {
                evidence = evidence.with_module(library);
            }
            if self.attest(name, evidence.clone()).is_some() {
                continue;
            }
            let fact = SymbolFact::new(
                SymbolKind::Unknown,
                SymbolBinding::Unknown,
                SymbolDefinition::Undefined,
                evidence,
            );
            if let Ok(id) = self.declare(name, fact) {
                if let Some(alias) = demangled_name(name) {
                    self.add_name(id, alias);
                }
            }
        }
    }

    fn import_exports(&mut self, object: &object::read::File<'_>, image: &ProgramImage) {
        let Ok(exports) = object.exports() else {
            self.note_incomplete(SymbolIncompleteness::UnreadableTable("export table"));
            return;
        };
        for export in exports {
            let Ok(name) = std::str::from_utf8(export.name()) else {
                self.note_incomplete(SymbolIncompleteness::UnreadableTable("export table"));
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let evidence = SymbolEvidence::new(SymbolAuthority::Binary, SymbolSource::ExportTable);
            if self.attest(name, evidence.clone()).is_some() {
                continue;
            }
            let fact = SymbolFact::new(
                SymbolKind::Unknown,
                SymbolBinding::Unknown,
                SymbolDefinition::Defined {
                    address: image.normalize_function_entry(export.address()),
                    size: None,
                },
                evidence,
            );
            if let Ok(id) = self.declare(name, fact) {
                if let Some(alias) = demangled_name(name) {
                    self.add_name(id, alias);
                }
            }
        }
    }

    fn import_static_relocations(&mut self, object: &object::read::File<'_>) {
        let mut sites = Vec::new();
        for section in object.sections() {
            for (offset, relocation) in section.relocations() {
                sites.push((section.address().wrapping_add(offset), relocation));
            }
        }
        for (site, relocation) in sites {
            let name = match relocation.target() {
                RelocationTarget::Symbol(index) => object
                    .symbol_table()
                    .and_then(|table| table.symbol_by_index(index).ok())
                    .and_then(|symbol| symbol.name().ok().map(str::to_string)),
                _ => None,
            };
            self.index_relocation(site, &relocation, name, SymbolSource::StaticRelocation);
        }
    }

    fn import_dynamic_relocations(&mut self, object: &object::read::File<'_>) {
        let Some(relocations) = object.dynamic_relocations() else {
            return;
        };
        let sites = relocations.collect::<Vec<_>>();
        for (site, relocation) in sites {
            let name = match relocation.target() {
                RelocationTarget::Symbol(index) => object
                    .dynamic_symbol_table()
                    .and_then(|table| table.symbol_by_index(index).ok())
                    .and_then(|symbol| symbol.name().ok().map(str::to_string)),
                _ => None,
            };
            self.index_relocation(site, &relocation, name, SymbolSource::DynamicRelocation);
        }
    }

    fn index_relocation(
        &mut self,
        site: u64,
        relocation: &object::Relocation,
        name: Option<String>,
        source: SymbolSource,
    ) {
        let Some(symbol) = name
            .as_deref()
            .filter(|name| !name.is_empty())
            .and_then(|name| self.symbol_by_linkage(name))
        else {
            self.note_incomplete(SymbolIncompleteness::UnresolvedRelocationTargets);
            return;
        };
        let reference = SymbolReference {
            site,
            symbol,
            addend: relocation.addend(),
            implicit_addend: relocation.has_implicit_addend(),
            width_bits: (relocation.size() != 0).then_some(relocation.size()),
            kind: reference_kind(relocation.kind()),
            format_type: format_relocation_type(relocation.flags()),
            evidence: SymbolEvidence::new(SymbolAuthority::Binary, source),
        };
        if self.add_reference(reference).is_err() {
            self.note_incomplete(SymbolIncompleteness::UnresolvedRelocationTargets);
        }
    }
}

fn symbol_kind(kind: ObjectSymbolKind) -> SymbolKind {
    match kind {
        ObjectSymbolKind::Text => SymbolKind::Function,
        ObjectSymbolKind::Data => SymbolKind::Data,
        ObjectSymbolKind::Section => SymbolKind::Section,
        ObjectSymbolKind::File => SymbolKind::File,
        ObjectSymbolKind::Label => SymbolKind::Label,
        ObjectSymbolKind::Tls => SymbolKind::Tls,
        _ => SymbolKind::Unknown,
    }
}

fn binding_of<'data, S: ObjectSymbol<'data>>(symbol: &S) -> SymbolBinding {
    if symbol.is_weak() {
        SymbolBinding::Weak
    } else if symbol.is_global() {
        SymbolBinding::Global
    } else if symbol.is_local() {
        SymbolBinding::Local
    } else {
        SymbolBinding::Unknown
    }
}

fn definition_of<'data, S: ObjectSymbol<'data>>(
    symbol: &S,
    image: &ProgramImage,
) -> SymbolDefinition {
    match symbol.section() {
        SymbolSection::Undefined => SymbolDefinition::Undefined,
        SymbolSection::Absolute => SymbolDefinition::Absolute {
            value: symbol.address(),
        },
        SymbolSection::Common => SymbolDefinition::Common {
            size: symbol.size(),
        },
        SymbolSection::Section(_) => SymbolDefinition::Defined {
            address: image.normalize_function_entry(symbol.address()),
            size: (symbol.size() != 0).then(|| symbol.size()),
        },
        _ => SymbolDefinition::Unknown,
    }
}

fn reference_kind(kind: RelocationKind) -> ReferenceKind {
    match kind {
        RelocationKind::Absolute => ReferenceKind::Absolute,
        RelocationKind::Relative
        | RelocationKind::GotRelative
        | RelocationKind::GotBaseRelative
        | RelocationKind::PltRelative => ReferenceKind::ProgramCounterRelative,
        RelocationKind::Got | RelocationKind::GotBaseOffset => ReferenceKind::GotOffset,
        RelocationKind::ImageOffset => ReferenceKind::ImageRelative,
        RelocationKind::SectionOffset => ReferenceKind::SectionRelative,
        _ => ReferenceKind::Unclassified,
    }
}

fn format_relocation_type(flags: RelocationFlags) -> Option<u32> {
    match flags {
        RelocationFlags::Elf { r_type } => Some(r_type),
        RelocationFlags::MachO { r_type, .. } => Some(u32::from(r_type)),
        RelocationFlags::Coff { typ } => Some(u32::from(typ)),
        RelocationFlags::Xcoff { r_rtype, .. } => Some(u32::from(r_rtype)),
        _ => None,
    }
}

/// Read the ELF symbol version table so module and version provenance survive.
fn elf_symbol_versions(object: &object::read::File<'_>) -> VersionMap {
    match object {
        object::read::File::Elf32(elf) => collect_elf_versions(elf),
        object::read::File::Elf64(elf) => collect_elf_versions(elf),
        _ => VersionMap::new(),
    }
}

fn collect_elf_versions<'data, Elf, R>(elf: &ElfFile<'data, Elf, R>) -> VersionMap
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    let endian = elf.endian();
    let Ok(Some(table)) = elf.elf_section_table().versions(endian, elf.data()) else {
        return VersionMap::new();
    };
    let symbols = elf.elf_dynamic_symbol_table();
    let strings = symbols.strings();
    let mut map = VersionMap::new();
    for (index, symbol) in symbols.enumerate() {
        let Ok(name) = symbol
            .name(endian, strings)
            .map(String::from_utf8_lossy)
            .map(std::borrow::Cow::into_owned)
        else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Ok(Some(version)) = table.version(table.version_index(endian, index)) else {
            continue;
        };
        let entry = (
            version
                .file()
                .map(|file| String::from_utf8_lossy(file).into_owned()),
            Some(String::from_utf8_lossy(version.name()).into_owned()),
        );
        let entries = map.entry(name).or_default();
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    map
}
