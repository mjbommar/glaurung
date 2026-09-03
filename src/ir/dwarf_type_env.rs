//! Program-level DWARF type relationships used by decompiler passes.
//!
//! A function prototype commonly names a typedef (`List_t *`) while the
//! aggregate layout is keyed by its tag (`struct xLIST`).  Consumers used to
//! compare those spellings directly and silently discard authoritative type
//! evidence.  This environment resolves the relationship once and gives AST
//! rendering and field recovery one fail-closed source of truth.

use std::collections::{HashMap, HashSet};

use crate::debug::dwarf::{DwarfType, DwarfTypeKind};

/// One pointer spelling resolved to its source alias and aggregate tag.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AggregatePointer<'a> {
    /// Name used by the source prototype (`List_t`, or `xLIST` for
    /// `struct xLIST *`).
    pub(crate) source_name: &'a str,
    /// Concrete DWARF aggregate tag reached through any typedef chain.
    pub(crate) tag_name: &'a str,
    pub(crate) kind: DwarfTypeKind,
    /// Complete layout when the binary contains one; opaque declarations do
    /// not require it.
    pub(crate) layout: Option<&'a DwarfType>,
    pub(crate) source_is_tagged: bool,
}

/// Immutable index over the type records extracted from one program image.
pub(crate) struct DwarfTypeEnv<'a> {
    typedefs: HashMap<&'a str, Option<&'a str>>,
    layouts: HashMap<(DwarfTypeKind, &'a str), Option<&'a DwarfType>>,
    enums: HashMap<&'a str, Option<&'a DwarfType>>,
}

#[derive(Debug, Clone, Copy)]
enum TypedefTerminal<'a> {
    Scalar,
    Enum(&'a DwarfType),
}

impl<'a> DwarfTypeEnv<'a> {
    pub(crate) fn new(types: &'a [DwarfType]) -> Self {
        let mut typedefs: HashMap<&'a str, Option<&'a str>> = HashMap::new();
        let mut layouts: HashMap<(DwarfTypeKind, &'a str), Option<&'a DwarfType>> = HashMap::new();
        let mut enums: HashMap<&'a str, Option<&'a DwarfType>> = HashMap::new();
        for record in types {
            match record.kind {
                DwarfTypeKind::Typedef => {
                    let Some(target) = record.typedef_target.as_deref() else {
                        continue;
                    };
                    typedefs
                        .entry(record.name.as_str())
                        .and_modify(|selected| {
                            if selected.is_some_and(|prior| prior != target) {
                                *selected = None;
                            }
                        })
                        .or_insert(Some(target));
                }
                DwarfTypeKind::Struct | DwarfTypeKind::Union => {
                    let key = (record.kind, record.name.as_str());
                    layouts
                        .entry(key)
                        .and_modify(|selected| {
                            if selected.is_some_and(|prior| prior != record) {
                                *selected = None;
                            }
                        })
                        .or_insert(Some(record));
                }
                DwarfTypeKind::Enum => {
                    enums
                        .entry(record.name.as_str())
                        .and_modify(|selected| {
                            if selected.is_some_and(|prior| prior != record) {
                                *selected = None;
                            }
                        })
                        .or_insert(Some(record));
                }
            }
        }
        Self {
            typedefs,
            layouts,
            enums,
        }
    }

    /// Resolve an exactly one-level pointer to an aggregate.
    ///
    /// Multiple pointer levels, arrays, function pointers, malformed names,
    /// conflicting aliases/layouts, and typedef cycles all return `None`.
    pub(crate) fn aggregate_pointer<'b>(&'a self, c_type: &'b str) -> Option<AggregatePointer<'b>>
    where
        'a: 'b,
    {
        let (source_name, tagged_kind) = pointed_type_identity(c_type)?;
        let (kind, tag_name) = if let Some(kind) = tagged_kind {
            (kind, source_name)
        } else {
            self.resolve_bare_aggregate(source_name, &mut HashSet::new())?
        };
        let layout = self.layouts.get(&(kind, tag_name)).and_then(|entry| *entry);
        Some(AggregatePointer {
            source_name,
            tag_name,
            kind,
            layout,
            source_is_tagged: tagged_kind.is_some(),
        })
    }

    /// The complete recorded layout of a BARE aggregate spelling.
    ///
    /// This is the by-value counterpart of [`Self::aggregate_pointer`], which
    /// deliberately answers only about pointers because a pointer needs no
    /// layout. A by-value result does: its size and field types are what decide
    /// which registers the ABI returns it in. Pointer spellings, arrays,
    /// conflicting definitions, and typedef cycles all return `None`.
    pub(crate) fn aggregate_layout(&'a self, c_type: &str) -> Option<&'a DwarfType> {
        let spelling = strip_leading_qualifiers(strip_trailing_qualifiers(c_type.trim()));
        if spelling.contains('*') || spelling.contains('[') {
            return None;
        }
        let (kind, tag_name) = if let Some(tag) = spelling.strip_prefix("struct ").map(str::trim) {
            (DwarfTypeKind::Struct, tag)
        } else if let Some(tag) = spelling.strip_prefix("union ").map(str::trim) {
            (DwarfTypeKind::Union, tag)
        } else {
            self.resolve_bare_aggregate(spelling, &mut HashSet::new())?
        };
        valid_c_identifier(tag_name).then_some(())?;
        self.layouts.get(&(kind, tag_name)).and_then(|entry| *entry)
    }

    /// Follow typedef aliases to the spelling that carries the representation.
    ///
    /// Unlike [`Self::scalar_spelling`], this does not stop at width-equivalent
    /// scalar aliases: an ABI storage class depends only on the representation,
    /// never on the source typedef's identity, so `int32_t` resolving to `int`
    /// is exactly the answer wanted here.
    pub(crate) fn representation_spelling(&self, c_type: &str) -> String {
        let mut spelling = strip_leading_qualifiers(strip_trailing_qualifiers(c_type.trim()));
        let mut visiting = HashSet::new();
        while !builtin_scalar_type(spelling)
            && valid_c_identifier(spelling)
            && visiting.insert(spelling)
        {
            let Some(target) = self.typedefs.get(spelling).and_then(|entry| *entry) else {
                break;
            };
            spelling = strip_leading_qualifiers(strip_trailing_qualifiers(target.trim()));
        }
        spelling.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Standalone declaration preserving the producer's real typedef/tag
    /// relationship.
    pub(crate) fn forward_declaration(&self, pointer: AggregatePointer<'_>) -> String {
        let keyword = match pointer.kind {
            DwarfTypeKind::Struct => "struct",
            DwarfTypeKind::Union => "union",
            DwarfTypeKind::Enum | DwarfTypeKind::Typedef => {
                unreachable!("aggregate_pointer only returns struct/union identities")
            }
        };
        let alias = if pointer.source_is_tagged {
            pointer.tag_name
        } else {
            pointer.source_name
        };
        format!("typedef {keyword} {} {alias};", pointer.tag_name)
    }

    /// Render the declaration needed to preserve a named enum typedef in an
    /// authoritative prototype.
    ///
    /// Enumerators are intentionally not reproduced: a prototype only needs
    /// an ABI-equivalent alias. Signedness and width come from the enum's
    /// observed values and measured DWARF byte size. Ambiguity fails closed.
    pub(crate) fn typedef_declaration(&self, c_type: &str) -> Option<String> {
        let alias = typedef_reference_name(c_type)?;
        self.typedefs.get(alias).and_then(|entry| *entry)?;
        let TypedefTerminal::Enum(layout) =
            self.resolve_typedef_terminal(alias, &mut HashSet::new())?
        else {
            return None;
        };
        let target = enum_integer_spelling(layout)?;
        Some(format!("typedef {target} {alias};"))
    }

    /// Resolve a built-in or named enum typedef to an ABI-equivalent spelling.
    pub(crate) fn scalar_spelling(&self, c_type: &str) -> Option<String> {
        let spelling = strip_leading_qualifiers(c_type.trim());
        if builtin_scalar_type(spelling) {
            return Some(spelling.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        valid_c_identifier(spelling).then_some(())?;
        self.typedefs.get(spelling).and_then(|entry| *entry)?;
        match self.resolve_typedef_terminal(spelling, &mut HashSet::new())? {
            TypedefTerminal::Enum(layout) => Some(enum_integer_spelling(layout)?.to_string()),
            // Width-equivalent scalar aliases can still change expression
            // signedness. Keep them opaque until body values carry the same
            // source typedef identity as the function boundary.
            TypedefTerminal::Scalar => None,
        }
    }

    fn resolve_bare_aggregate<'b>(
        &'a self,
        name: &'b str,
        visiting: &mut HashSet<&'b str>,
    ) -> Option<(DwarfTypeKind, &'b str)>
    where
        'a: 'b,
    {
        if !visiting.insert(name) {
            return None;
        }
        let resolved = if let Some(target) = self.typedefs.get(name).and_then(|entry| *entry) {
            let target = strip_leading_qualifiers(target.trim());
            if let Some(tag_name) = target.strip_prefix("struct ").map(str::trim) {
                valid_c_identifier(tag_name).then_some((DwarfTypeKind::Struct, tag_name))
            } else if let Some(tag_name) = target.strip_prefix("union ").map(str::trim) {
                valid_c_identifier(tag_name).then_some((DwarfTypeKind::Union, tag_name))
            } else if valid_c_identifier(target) {
                self.resolve_bare_aggregate(target, visiting)
            } else {
                None
            }
        } else {
            let structure = self
                .layouts
                .get(&(DwarfTypeKind::Struct, name))
                .and_then(|entry| *entry)
                .is_some();
            let union = self
                .layouts
                .get(&(DwarfTypeKind::Union, name))
                .and_then(|entry| *entry)
                .is_some();
            match (structure, union) {
                (true, false) => Some((DwarfTypeKind::Struct, name)),
                (false, true) => Some((DwarfTypeKind::Union, name)),
                _ => None,
            }
        };
        visiting.remove(name);
        resolved
    }

    fn resolve_typedef_terminal<'b>(
        &'a self,
        name: &'b str,
        visiting: &mut HashSet<&'b str>,
    ) -> Option<TypedefTerminal<'b>>
    where
        'a: 'b,
    {
        if !visiting.insert(name) {
            return None;
        }
        let target = self.typedefs.get(name).and_then(|entry| *entry)?.trim();
        let target = strip_leading_qualifiers(target);
        let terminal = if builtin_scalar_type(target) {
            Some(TypedefTerminal::Scalar)
        } else if let Some(tag_name) = target.strip_prefix("enum ").map(str::trim) {
            let layout = valid_c_identifier(tag_name)
                .then(|| self.enums.get(tag_name).and_then(|entry| *entry))
                .flatten()?;
            Some(TypedefTerminal::Enum(layout))
        } else if valid_c_identifier(target) {
            self.resolve_typedef_terminal(target, visiting)
        } else {
            None
        };
        visiting.remove(name);
        terminal
    }
}

/// Return the source name named by an exactly one-level pointer spelling.
pub(crate) fn pointed_type_name(c_type: &str) -> Option<&str> {
    pointed_type_identity(c_type).map(|(name, _)| name)
}

/// Replace an aggregate pointee name while retaining its qualifiers.
pub(crate) fn render_pointer_name(c_type: &str, replacement: &str) -> Option<String> {
    valid_c_identifier(replacement).then_some(())?;
    pointed_type_identity(c_type)?;
    let star = c_type.rfind('*')?;
    if c_type[..star].contains('*') {
        return None;
    }
    let before = c_type[..star].trim();
    let after = c_type[star + 1..].trim();
    if !after
        .split_whitespace()
        .all(|word| matches!(word, "const" | "volatile" | "restrict"))
    {
        return None;
    }
    let mut words = before.split_whitespace().collect::<Vec<_>>();
    let source_name = words.pop()?;
    if !valid_c_identifier(source_name) {
        return None;
    }
    words.retain(|word| !matches!(*word, "struct" | "union"));
    if !words
        .iter()
        .all(|word| matches!(*word, "const" | "volatile" | "restrict"))
    {
        return None;
    }
    let mut rendered = String::new();
    if !words.is_empty() {
        rendered.push_str(&words.join(" "));
        rendered.push(' ');
    }
    rendered.push_str(replacement);
    rendered.push_str(" *");
    if !after.is_empty() {
        rendered.push(' ');
        rendered.push_str(after);
    }
    Some(rendered)
}

/// Attach an identifier to a plain C type using conventional pointer spacing.
///
/// Type recovery stores declarators independently from their names, with stars
/// separated as tokens (`const char * *`). Merely joining those strings with a
/// space produces the mechanically valid but source-hostile `char * * argv`.
/// Keep non-pointer and complex declarators on the conservative old path; the
/// plain pointer chain used by recovered parameters becomes `char **argv`.
pub(crate) fn render_named_declaration(c_type: &str, name: &str) -> String {
    let c_type = c_type.trim();
    let Some(first_star) = c_type.find('*') else {
        return format!("{c_type} {name}");
    };
    let base = c_type[..first_star].trim_end();
    let suffix = &c_type[first_star..];
    if base.is_empty()
        || suffix
            .chars()
            .any(|ch| !(ch == '*' || ch == '_' || ch.is_ascii_alphabetic() || ch.is_whitespace()))
    {
        return format!("{c_type} {name}");
    }

    let mut rendered = String::with_capacity(c_type.len() + name.len() + 1);
    rendered.push_str(base);
    rendered.push(' ');
    let mut previous_was_word = false;
    for token in suffix.split_whitespace() {
        if token.chars().all(|ch| ch == '*') {
            if previous_was_word {
                rendered.push(' ');
            }
            rendered.push_str(token);
            previous_was_word = false;
        } else {
            rendered.push_str(token);
            previous_was_word = true;
        }
    }
    if previous_was_word {
        rendered.push(' ');
    }
    rendered.push_str(name);
    rendered
}

fn typedef_reference_name(c_type: &str) -> Option<&str> {
    if c_type.contains('*') {
        return pointed_type_name(c_type);
    }
    let spelling = strip_leading_qualifiers(c_type.trim());
    valid_c_identifier(spelling).then_some(spelling)
}

fn enum_integer_spelling(layout: &DwarfType) -> Option<&'static str> {
    if layout.kind != DwarfTypeKind::Enum || layout.variants.is_empty() {
        return None;
    }
    let signed = layout.variants.iter().any(|variant| variant.value < 0);
    match (layout.byte_size, signed) {
        (1, true) => Some("signed char"),
        (1, false) => Some("unsigned char"),
        (2, true) => Some("short"),
        (2, false) => Some("unsigned short"),
        (4, true) => Some("int"),
        (4, false) => Some("unsigned int"),
        (8, true) => Some("long long"),
        (8, false) => Some("unsigned long long"),
        _ => None,
    }
}

pub(crate) fn builtin_scalar_type(spelling: &str) -> bool {
    matches!(
        spelling
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .as_str(),
        "_Bool"
            | "bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "short int"
            | "signed short"
            | "signed short int"
            | "unsigned short"
            | "unsigned short int"
            | "int"
            | "signed"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "long int"
            | "signed long"
            | "signed long int"
            | "unsigned long"
            | "unsigned long int"
            | "long unsigned"
            | "long unsigned int"
            | "long long"
            | "long long int"
            | "signed long long"
            | "signed long long int"
            | "unsigned long long"
            | "unsigned long long int"
            | "long long unsigned"
            | "long long unsigned int"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "float"
            | "double"
            // The double-word integer types. Present because they are exactly
            // the ABI storage of a two-register INTEGER result: the CALL
            // boundary has declared `unsigned __int128` since `c2fb19d`, and a
            // callee whose own result is such an aggregate now declares the
            // same spelling. Omitting them made that declaration unrenderable
            // and the signature silently fell back to one machine word.
            // `scalar_eightbyte_class` still refuses them (its `size <= 8`
            // guard), so a struct MEMBER of this type classifies no differently
            // than before.
            | "__int128"
            | "signed __int128"
            | "unsigned __int128"
    )
}

fn pointed_type_identity(c_type: &str) -> Option<(&str, Option<DwarfTypeKind>)> {
    let mut spelling = strip_trailing_qualifiers(c_type.trim());
    spelling = spelling.strip_suffix('*')?.trim_end();
    if spelling.contains('*') {
        return None;
    }
    spelling = strip_leading_qualifiers(spelling);
    if let Some(name) = spelling.strip_prefix("struct ").map(str::trim) {
        return valid_c_identifier(name).then_some((name, Some(DwarfTypeKind::Struct)));
    }
    if let Some(name) = spelling.strip_prefix("union ").map(str::trim) {
        return valid_c_identifier(name).then_some((name, Some(DwarfTypeKind::Union)));
    }
    valid_c_identifier(spelling).then_some((spelling, None))
}

fn strip_trailing_qualifiers(mut spelling: &str) -> &str {
    loop {
        let mut changed = false;
        for qualifier in ["const", "volatile", "restrict"] {
            let Some(prefix) = spelling.strip_suffix(qualifier) else {
                continue;
            };
            if prefix
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                continue;
            }
            spelling = prefix.trim_end();
            changed = true;
            break;
        }
        if !changed {
            return spelling;
        }
    }
}

fn strip_leading_qualifiers(mut spelling: &str) -> &str {
    loop {
        let mut changed = false;
        for qualifier in ["const ", "volatile ", "restrict "] {
            if let Some(rest) = spelling.strip_prefix(qualifier) {
                spelling = rest.trim_start();
                changed = true;
                break;
            }
        }
        if !changed {
            return spelling;
        }
    }
}

/// Whether `name` is spellable as a C identifier: a leading letter or
/// underscore, then letters, digits or underscores.
///
/// `pub(crate)` rather than private because `ast::dwarf_render_types` needs the
/// same question answered and had an identical copy. The two were byte-for-byte
/// the same 163 characters, under the same name, in two modules — a duplication
/// that a name-based search DOES find, unlike the three others measured beside
/// it, which had diverged in name while staying identical in body.
pub(crate) fn valid_c_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: DwarfTypeKind, name: &str, target: Option<&str>) -> DwarfType {
        DwarfType {
            kind,
            name: name.to_string(),
            byte_size: u64::from(kind == DwarfTypeKind::Struct) * 4,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: target.map(str::to_string),
            source_file: Some("types.h".to_string()),
        }
    }

    #[test]
    fn aggregate_pointer_follows_typedefs_and_pointer_qualifiers() {
        let types = [
            record(DwarfTypeKind::Typedef, "PublicList", Some("List_t")),
            record(DwarfTypeKind::Typedef, "List_t", Some("struct xLIST")),
            record(DwarfTypeKind::Struct, "xLIST", None),
        ];
        let env = DwarfTypeEnv::new(&types);

        let pointer = env.aggregate_pointer("const PublicList *const").unwrap();

        assert_eq!(pointer.source_name, "PublicList");
        assert_eq!(pointer.tag_name, "xLIST");
        assert_eq!(pointer.kind, DwarfTypeKind::Struct);
        assert!(pointer.layout.is_some());
        assert_eq!(
            env.forward_declaration(pointer),
            "typedef struct xLIST PublicList;"
        );
        assert_eq!(
            render_pointer_name("const struct xLIST *const", "PublicList").as_deref(),
            Some("const PublicList * const")
        );
    }

    #[test]
    fn aggregate_pointer_rejects_cycles_and_multiple_indirection() {
        let types = [
            record(DwarfTypeKind::Typedef, "Left", Some("Right")),
            record(DwarfTypeKind::Typedef, "Right", Some("Left")),
        ];
        let env = DwarfTypeEnv::new(&types);

        assert!(env.aggregate_pointer("Left *").is_none());
        assert!(env.aggregate_pointer("struct node **").is_none());
    }

    #[test]
    fn named_pointer_declarations_use_source_like_spacing() {
        assert_eq!(render_named_declaration("int", "argc"), "int argc");
        assert_eq!(
            render_named_declaration("const char * *", "argv"),
            "const char **argv"
        );
        assert_eq!(
            render_named_declaration("char * const *", "items"),
            "char *const *items"
        );
        assert_eq!(
            render_named_declaration("void (*)(int)", "callback"),
            "void (*)(int) callback"
        );
    }

    #[test]
    fn enum_typedef_uses_measured_width_and_signedness() {
        use crate::debug::dwarf::DwarfEnumVariant;

        let types = [
            record(DwarfTypeKind::Typedef, "Status", Some("enum Status_")),
            DwarfType {
                kind: DwarfTypeKind::Enum,
                name: "Status_".to_string(),
                byte_size: 4,
                fields: Vec::new(),
                variants: vec![
                    DwarfEnumVariant {
                        name: "ERROR".to_string(),
                        value: -1,
                    },
                    DwarfEnumVariant {
                        name: "OK".to_string(),
                        value: 0,
                    },
                ],
                typedef_target: None,
                source_file: Some("types.h".to_string()),
            },
        ];
        let env = DwarfTypeEnv::new(&types);

        assert_eq!(
            env.typedef_declaration("Status").as_deref(),
            Some("typedef int Status;")
        );
        assert_eq!(env.typedef_declaration("char"), None);
    }
}
