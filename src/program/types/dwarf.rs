//! DWARF adapter for the canonical, language-neutral type store.

use std::collections::{BTreeMap, HashMap};

use crate::core::{DataType, EnumMember, Field};
use crate::debug::dwarf::{DwarfType, DwarfTypeKind};

use super::{TypeAuthority, TypeEvidence, TypeImportReport, TypeStore};

fn nominal_id(kind: DwarfTypeKind, name: &str) -> String {
    let kind = match kind {
        DwarfTypeKind::Struct => "struct",
        DwarfTypeKind::Union => "union",
        DwarfTypeKind::Enum => "enum",
        DwarfTypeKind::Typedef => "typedef",
    };
    format!("dwarf:{kind}:{name}")
}

fn strip_qualifiers(mut spelling: &str) -> &str {
    loop {
        let mut changed = false;
        for qualifier in ["const", "volatile", "restrict"] {
            if let Some(rest) = spelling.strip_prefix(qualifier) {
                if rest.starts_with(char::is_whitespace) {
                    spelling = rest.trim_start();
                    changed = true;
                    break;
                }
            }
            if let Some(rest) = spelling.strip_suffix(qualifier) {
                if rest.ends_with(char::is_whitespace) {
                    spelling = rest.trim_end();
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            return spelling;
        }
    }
}

fn primitive_size(spelling: &str) -> Option<u64> {
    match spelling
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .as_str()
    {
        "_Bool" | "bool" | "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" => {
            Some(1)
        }
        "short" | "short int" | "signed short" | "signed short int" | "unsigned short"
        | "unsigned short int" | "int16_t" | "uint16_t" => Some(2),
        "int" | "signed" | "signed int" | "unsigned" | "unsigned int" | "float" | "int32_t"
        | "uint32_t" => Some(4),
        "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "double"
        | "int64_t"
        | "uint64_t" => Some(8),
        _ => None,
    }
}

struct DwarfDataTypeBuilder {
    address_size: u64,
    nominal: HashMap<(DwarfTypeKind, String), String>,
    /// Pointer and primitive types synthesized from field spellings. These are
    /// keyed by construction, so an identical spelling is built once.
    synthesized: BTreeMap<String, DataType>,
    /// Nominal records in extraction order. Two compilation units may define
    /// one tag differently; both are forwarded so the store retains the
    /// conflict rather than letting the last record win here.
    records: Vec<DataType>,
}

impl DwarfDataTypeBuilder {
    fn new(types: &[DwarfType], address_size: u64) -> Self {
        let nominal = types
            .iter()
            .map(|record| {
                (
                    (record.kind, record.name.clone()),
                    nominal_id(record.kind, &record.name),
                )
            })
            .collect();
        Self {
            address_size,
            nominal,
            synthesized: BTreeMap::new(),
            records: Vec::new(),
        }
    }

    fn resolve_spelling(&mut self, spelling: &str, observed_size: u64) -> String {
        let spelling = spelling.trim();
        let unqualified = strip_qualifiers(spelling);
        if let Some(pointee) = unqualified.strip_suffix('*').map(str::trim_end) {
            let pointee_id = self.resolve_spelling(pointee, 0);
            let id = format!("dwarf:pointer:{spelling}");
            let size = (observed_size != 0)
                .then_some(observed_size)
                .unwrap_or(self.address_size);
            self.synthesized.entry(id.clone()).or_insert_with(|| {
                DataType::new_pointer(
                    id.clone(),
                    spelling.to_string(),
                    size,
                    // The legacy DWARF record does not retain DW_AT_alignment.
                    // Natural alignment is a target rule, not debug evidence, so
                    // it is left absent rather than inferred from the width.
                    None,
                    pointee_id,
                    Vec::new(),
                    Some("DW_TAG_pointer_type".to_string()),
                )
            });
            return id;
        }
        for (prefix, kind) in [
            ("struct ", DwarfTypeKind::Struct),
            ("union ", DwarfTypeKind::Union),
            ("enum ", DwarfTypeKind::Enum),
        ] {
            if let Some(name) = unqualified.strip_prefix(prefix).map(str::trim) {
                if let Some(id) = self.nominal.get(&(kind, name.to_string())) {
                    return id.clone();
                }
            }
        }
        if let Some(id) = self
            .nominal
            .get(&(DwarfTypeKind::Typedef, unqualified.to_string()))
        {
            return id.clone();
        }
        let aggregate_matches = [DwarfTypeKind::Struct, DwarfTypeKind::Union]
            .into_iter()
            .filter_map(|kind| self.nominal.get(&(kind, unqualified.to_string())))
            .cloned()
            .collect::<Vec<_>>();
        if let [id] = aggregate_matches.as_slice() {
            return id.clone();
        }
        if let Some(size) = (observed_size != 0)
            .then_some(observed_size)
            .or_else(|| primitive_size(unqualified))
        {
            let id = format!("dwarf:primitive:{unqualified}:{size}");
            self.synthesized.entry(id.clone()).or_insert_with(|| {
                DataType::new_primitive(
                    id.clone(),
                    unqualified.to_string(),
                    size,
                    None,
                    Some("DW_TAG_base_type".to_string()),
                )
            });
            return id;
        }
        format!("dwarf:unresolved:{unqualified}")
    }

    fn add_record(&mut self, record: &DwarfType) {
        let id = nominal_id(record.kind, &record.name);
        let source = record.source_file.clone();
        let data_type = match record.kind {
            DwarfTypeKind::Struct | DwarfTypeKind::Union => {
                let fields = record
                    .fields
                    .iter()
                    .map(|field| Field {
                        name: field.name.clone(),
                        type_id: self.resolve_spelling(&field.c_type, field.size),
                        offset: field.offset,
                    })
                    .collect();
                if record.kind == DwarfTypeKind::Struct {
                    DataType::new_struct(
                        id.clone(),
                        record.name.clone(),
                        record.byte_size,
                        None,
                        fields,
                        source,
                    )
                } else {
                    DataType::new_union(
                        id.clone(),
                        record.name.clone(),
                        record.byte_size,
                        None,
                        fields,
                        source,
                    )
                }
            }
            DwarfTypeKind::Enum => {
                let width = record.byte_size;
                // The legacy DWARF record retains width and enumerators but not
                // DW_AT_encoding. Do not invent signed `int` evidence here.
                let underlying = self.resolve_spelling("enum-underlying", width);
                DataType::new_enum(
                    id.clone(),
                    record.name.clone(),
                    width,
                    None,
                    underlying,
                    record
                        .variants
                        .iter()
                        .map(|variant| EnumMember {
                            name: variant.name.clone(),
                            value: variant.value,
                        })
                        .collect(),
                    source,
                )
            }
            DwarfTypeKind::Typedef => {
                let target = record
                    .typedef_target
                    .as_deref()
                    .map(|target| self.resolve_spelling(target, record.byte_size))
                    .unwrap_or_else(|| format!("dwarf:unresolved:typedef:{}", record.name));
                DataType::new_typedef(
                    id.clone(),
                    record.name.clone(),
                    record.byte_size,
                    None,
                    target,
                    source,
                )
            }
        };
        self.records.push(data_type);
    }
}

impl TypeStore {
    /// Import one already-extracted DWARF type collection into this store.
    /// Nominal identities are reserved before field spellings are resolved, so
    /// self-referential aggregates remain recursive rather than being flattened.
    pub fn import_dwarf_types(
        &mut self,
        types: &[DwarfType],
        address_size: u64,
    ) -> TypeImportReport {
        let mut builder = DwarfDataTypeBuilder::new(types, address_size);
        for record in types {
            builder.add_record(record);
        }
        let data_types = builder
            .synthesized
            .into_values()
            .chain(builder.records)
            .collect::<Vec<_>>();
        self.import_data_types(
            &data_types,
            TypeEvidence::new(TypeAuthority::Debug, "dwarf"),
        )
    }
}
