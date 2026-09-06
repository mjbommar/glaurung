//! Reading the declared type of every name.
//!
//! Split from [`super::events`] because the two answer different questions
//! about the same tree: that module decides which names are written and read,
//! this one decides what each name was declared as. They share the tree walk's
//! helpers and nothing else.
//!
//! # As written, not resolved
//!
//! This front end reads one translation unit and does not process `#include`
//! (`REQ-GEN`), so a typedef from a header is an opaque name and is recorded
//! as one. `uint32_t` is stored as `uint32_t`; nothing here claims to know it
//! is four bytes.
//!
//! Deliberately **not** built on [`crate::metrics::type_name::normalize_type`],
//! which reproduces four defects in DecBench's reference implementation on
//! purpose --- it emits the non-C spelling `long long long`, and turns `_Bool`
//! into `_bool` --- because parity with the benchmark is its contract. A
//! consumer who wants the type the programmer wrote needs a different reader,
//! so this is one.

use crate::csource::lex::kind::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::Tree;
use crate::syntax::ids::{NodeId, Span};

use super::events::name_of;
use super::model::CType;

/// The declared type of every name in this function, keyed by the name's span.
///
/// A declaration is `DeclSpecifiers` followed by one or more declarators, and
/// the specifiers apply to all of them: in `int a = 1, *b, c[4];` every name
/// has base `int`, and `b` additionally has a pointer and `c` an array rank.
/// So this reads the specifiers once per `Decl` and then walks the declarators
/// after it, counting the `*` between one name and the previous one.
///
/// Parameters are read from the parameter list's tokens for the same reason
/// [`parameter_names`] is: `tag.rs` keeps a parameter list as one opaque token
/// run, so there are no child nodes to walk.
pub(super) fn declared_types(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<(Span, CType)> {
    let arena = tree.arena();
    let mut out: Vec<(Span, CType)> = Vec::new();

    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::Decl.as_u16()) {
            continue;
        }
        let Some((decl_first, decl_end)) = arena.token_extent(node) else {
            continue;
        };

        // The specifier text, and where it stops.
        let mut specifiers = String::new();
        let mut specifier_end = decl_first;
        for inner in arena.preorder(node) {
            if arena.tag(inner) != Some(NodeTag::DeclSpecifiers.as_u16()) {
                continue;
            }
            if let Some(span) = arena.span(inner, token_spans) {
                if let Some(slice) = text.get(span.lo as usize..span.hi as usize) {
                    specifiers = slice.split_whitespace().collect::<Vec<_>>().join(" ");
                }
            }
            if let Some((_, end)) = arena.token_extent(inner) {
                specifier_end = specifier_end.max(end);
            }
            break;
        }

        let base = CType {
            is_const: has_word(&specifiers, "const"),
            is_volatile: has_word(&specifiers, "volatile"),
            is_static: has_word(&specifiers, "static"),
            is_extern: has_word(&specifiers, "extern"),
            specifiers,
            ..CType::default()
        };

        // Each declared name in this declaration, with the tokens between it
        // and the previous name deciding its pointer depth.
        let mut names: Vec<(Span, u32)> = Vec::new();
        for inner in arena.preorder(node) {
            if arena.tag(inner) != Some(NodeTag::DeclName.as_u16()) {
                continue;
            }
            if let Some((_, span)) = name_of(tree, text, token_spans, inner) {
                let index = token_index_of(token_spans, span).unwrap_or(specifier_end);
                names.push((span, index));
            }
        }
        names.sort_by_key(|(span, _)| span.lo);

        let mut previous_end = specifier_end;
        for (span, index) in &names {
            let mut ty = base.clone();
            // Stars between the last thing and this name.
            for token in previous_end..*index {
                let id = crate::syntax::ids::TokenId::new(token);
                if tree.tokens().text(id, text).trim() == "*" {
                    ty.pointer_depth += 1;
                }
            }
            // Array suffixes immediately after this name, before the next.
            let stop = names
                .iter()
                .find(|(other, _)| other.lo > span.lo)
                .map_or(decl_end, |(_, other_index)| *other_index);
            for token in (*index + 1)..stop {
                let id = crate::syntax::ids::TokenId::new(token);
                if tree.tokens().text(id, text).trim() == "[" {
                    ty.array_rank += 1;
                }
            }
            previous_end = *index + 1;
            out.push((*span, ty));
        }
    }

    // Parameters, from the outermost parameter list's tokens.
    for (span, ty) in parameter_types(tree, text, token_spans, root) {
        out.push((span, ty));
    }
    out
}

/// The declared type of every named parameter, read from the token run.
///
/// The rule matches [`parameter_names`]: an identifier followed by `,`, `)` or
/// `[` is a parameter name. Everything between the previous separator and that
/// name is its type, and the `*`s among those tokens are its pointer depth.
fn parameter_types(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<(Span, CType)> {
    let arena = tree.arena();
    let mut out = Vec::new();
    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::ParamList.as_u16()) {
            continue;
        }
        let Some((first, end)) = arena.token_extent(node) else {
            continue;
        };
        // Skip the opening paren.
        let mut group_start = first + 1;
        for index in first..end {
            let id = crate::syntax::ids::TokenId::new(index);
            let token = tree.tokens().text(id, text).trim();
            if token == "," {
                group_start = index + 1;
                continue;
            }
            if tree.tokens().kind(id) != TokenKind::Identifier.as_u16() {
                continue;
            }
            if index + 1 >= end {
                continue;
            }
            let next = crate::syntax::ids::TokenId::new(index + 1);
            let follows = tree.tokens().text(next, text).trim();
            if !matches!(follows, "," | ")" | "[") {
                continue;
            }
            let Some(span) = token_spans.get(index as usize).copied() else {
                continue;
            };

            let mut words: Vec<&str> = Vec::new();
            let mut pointer_depth = 0u32;
            for token_index in group_start..index {
                let id = crate::syntax::ids::TokenId::new(token_index);
                let word = tree.tokens().text(id, text).trim();
                if word == "*" {
                    pointer_depth += 1;
                } else if !word.is_empty() && word != "(" {
                    words.push(word);
                }
            }
            let mut array_rank = 0u32;
            let mut scan = index + 1;
            while scan < end {
                let id = crate::syntax::ids::TokenId::new(scan);
                if tree.tokens().text(id, text).trim() == "[" {
                    array_rank += 1;
                    scan += 1;
                } else {
                    break;
                }
            }
            let specifiers = words.join(" ");
            out.push((
                span,
                CType {
                    is_const: has_word(&specifiers, "const"),
                    is_volatile: has_word(&specifiers, "volatile"),
                    is_static: has_word(&specifiers, "static"),
                    is_extern: has_word(&specifiers, "extern"),
                    specifiers,
                    pointer_depth,
                    array_rank,
                },
            ));
            group_start = index + 1;
        }
        break; // the outermost list is the function's own
    }
    out
}

/// Whether `haystack` contains `word` as a whole word.
fn has_word(haystack: &str, word: &str) -> bool {
    haystack.split_whitespace().any(|candidate| candidate == word)
}

/// The token index whose span is exactly `span`.
fn token_index_of(token_spans: &[Span], span: Span) -> Option<u32> {
    token_spans
        .iter()
        .position(|candidate| *candidate == span)
        .map(|index| index as u32)
}

