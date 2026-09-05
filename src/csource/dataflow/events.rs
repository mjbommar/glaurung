//! Reading definitions and uses out of the syntax tree.
//!
//! Everything here answers one question: which names in this function are
//! written, which are read, and which variable is each one about. The
//! fixpoint that consumes the answer is [`super::solve`]; the vocabulary it
//! is expressed in is [`super::model`].
//!
//! # Why so much of this is about *not* recording an event
//!
//! Most of the work below is deciding that a name is not a read. C spells
//! several things with a bare identifier that are not values --- a type in
//! `sizeof(T)`, a callee in `f(x)`, the base of `a[i] = v` --- and this parser
//! deliberately has no typedef table (`parse/look.rs` says so and says why).
//! Each of those was a real over-report measured against the fixture corpus,
//! and each is fixed positionally rather than by adding the table.

use crate::csource::cfg::FunctionCfg;
use crate::csource::lex::kind::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::Tree;
use crate::syntax::cfg::Cfg;
use crate::syntax::ids::{NodeId, Span};

use super::model::{Binding, DefKind, Definition, Use};

/// The definitions and uses of one function, before the fixpoint.
pub(super) struct Events {
    pub(super) definitions: Vec<Definition>,
    pub(super) uses: Vec<Use>,
}

/// One lexical scope's bindings, as (name, binding) pairs.
type Scope = Vec<(String, Binding)>;

/// Walk the function's syntax tree and record every write and read.
///
/// One pass in source order over the definition's subtree. The scope stack
/// opens on a `CompoundStmt` and on the constructs that introduce a scope of
/// their own (`for`, which may declare its own induction variable), and the
/// binding of a use is the innermost visible one at that point.
pub(super) fn collect_events(tree: &Tree, text: &str, token_spans: &[Span], function: &FunctionCfg) -> Events {
    let arena = tree.arena();
    let mut definitions: Vec<Definition> = Vec::new();
    let mut uses: Vec<Use> = Vec::new();

    // Find the function definition node whose span matches this graph's.
    let Some(definition_node) = tree
        .functions(text)
        .into_iter()
        .find(|f| f.span == function.span)
    else {
        return Events { definitions, uses };
    };
    let root = definition_node.node;
    // The declarator names the function itself. That is not a variable, and
    // binding it would make a recursive call look like a read of a local.
    let own_name_span = definition_node.name_span;

    // Names that are not data reads, collected before the walk because both
    // tests need the *enclosing* node and the walk sees a node before it knows
    // what encloses it.
    //
    // A type name is the larger of the two: `int32_t x = 1;` puts `int32_t` in
    // the tree as a name, and counting it as a read of an undefined variable
    // was 516 of the 1,970 unresolved uses this analysis first reported over
    // the fixture corpus.
    let skip_spans = type_name_spans(tree, text, token_spans, root);
    let callee_spans = callee_name_spans(tree, text, token_spans, root);
    // Names in a position that is a type only when the name is not a variable.
    // `sizeof(int32_t)` is a type; `sizeof(pointer)` reads a pointer. The
    // binding is what separates them, so these are checked after resolution.
    let ambiguous_spans = ambiguous_type_spans(tree, text, token_spans, root);
    // `int x = 1;` writes. `int x;` does not: it binds a name and leaves it
    // holding whatever was on the stack. Counting the bare form as a store
    // made every uninitialized local a dead store --- 437 of the 897 this
    // analysis first reported --- and, worse, a read of one looked satisfied
    // rather than being the read-of-uninitialized it is.
    let initialized = initialized_declarator_spans(tree, text, token_spans, root);

    let mut scopes: Vec<Scope> = vec![Vec::new()];
    let mut next_binding = 0u32;

    // Parameters first, because every one of them is a definition live at the
    // entry and a body that reads one must see it.
    //
    // They are read from the parameter list's *tokens*, not from child nodes:
    // `tag.rs` keeps a parameter list as one opaque token run on purpose, so
    // there is no `DeclName` under it to walk.
    for (name, span) in parameter_names(tree, text, token_spans, root) {
        let binding = Binding(next_binding);
        next_binding += 1;
        if let Some(scope) = scopes.last_mut() {
            scope.push((name.clone(), binding));
        }
        definitions.push(Definition {
            binding,
            name,
            node: 0,
            span,
            // A parameter is written by the caller, so it is visible to every
            // read in the body including the first.
            effect_at: 0,
            kind: DefKind::Parameter,
        });
    }

    // An explicit stack, never native recursion (`REQ-SYN-3`). Each entry is
    // either a node to visit or a marker to close the scope it opened.
    enum Step {
        Visit(NodeId),
        CloseScope,
    }
    let mut stack = vec![Step::Visit(root)];

    while let Some(step) = stack.pop() {
        let node = match step {
            Step::CloseScope => {
                scopes.pop();
                continue;
            }
            Step::Visit(node) => node,
        };
        let tag = arena.tag(node).and_then(NodeTag::from_u16);

        // Opening a scope: push a frame, and schedule its close after the
        // children by pushing the marker first (the stack is LIFO).
        let opens_scope = matches!(tag, Some(NodeTag::CompoundStmt) | Some(NodeTag::ForStmt));
        if opens_scope {
            scopes.push(Vec::new());
            stack.push(Step::CloseScope);
        }

        match tag {
            // A declared name: bind it, and record the write.
            Some(NodeTag::DeclName) => {
                if let Some((name, span)) = name_of(tree, text, token_spans, node) {
                    if span == own_name_span {
                        // The function's own name; skip without binding it.
                        let children: Vec<NodeId> = arena.children_iter(node).collect();
                        for child in children.into_iter().rev() {
                            stack.push(Step::Visit(child));
                        }
                        continue;
                    }
                    let binding = Binding(next_binding);
                    next_binding += 1;
                    if let Some(scope) = scopes.last_mut() {
                        scope.push((name.clone(), binding));
                    }
                    if initialized.contains(&span) {
                        definitions.push(Definition {
                            binding,
                            name,
                            node: 0, // assigned below, once spans are joined
                            span,
                            // Raised to the end of the enclosing declaration
                            // once the walk is done, so an initializer is
                            // evaluated before the name it initializes is
                            // visible.
                            effect_at: span.hi,
                            kind: DefKind::Declaration,
                        });
                    }
                }
            }
            // A read of a name.
            Some(NodeTag::NameRef) => {
                if let Some((name, span)) = name_of(tree, text, token_spans, node) {
                    if skip_spans.contains(&span) {
                        let children: Vec<NodeId> = arena.children_iter(node).collect();
                        for child in children.into_iter().rev() {
                            stack.push(Step::Visit(child));
                        }
                        continue;
                    }
                    let binding = resolve(&scopes, &name);
                    // A name that resolves to nothing and is being *called* is
                    // a function, not a value: `memcpy(a, b, n)` reads a, b
                    // and n. A callee that does resolve is a function pointer,
                    // and reading it is a real dependence, so the test is on
                    // the binding rather than on the syntax alone.
                    if binding.is_free()
                        && (callee_spans.contains(&span) || ambiguous_spans.contains(&span))
                    {
                        // fall through to the children walk below
                    } else {
                        uses.push(Use {
                            binding,
                            name,
                            node: 0,
                            span,
                        });
                    }
                }
            }
            _ => {}
        }

        // Children in source order: push reversed so the first pops first.
        let children: Vec<NodeId> = arena.children_iter(node).collect();
        for child in children.into_iter().rev() {
            stack.push(Step::Visit(child));
        }
    }

    // An assignment's left operand is a *write* as well as, for a compound
    // operator, a read. The walk above recorded it as a read, because
    // syntactically it is a `NameRef`; promote it here where the shape of the
    // enclosing expression is available.
    promote_writes(tree, text, token_spans, root, &mut definitions, &mut uses);

    // A declaration's initializer runs before the name is visible, so raise
    // each declaration's effect point to the end of the `Decl` that holds it.
    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::Decl.as_u16()) {
            continue;
        }
        let Some(extent) = arena.span(node, token_spans) else {
            continue;
        };
        for definition in definitions.iter_mut() {
            if definition.kind == DefKind::Declaration
                && extent.lo <= definition.span.lo
                && definition.span.hi <= extent.hi
            {
                definition.effect_at = definition.effect_at.max(extent.hi);
            }
        }
    }

    // Join each event to the CFG node whose spans contain it.
    for definition in &mut definitions {
        definition.node = node_for_span(&function.cfg, definition.span);
    }
    for use_ in &mut uses {
        use_.node = node_for_span(&function.cfg, use_.span);
    }

    Events { definitions, uses }
}

/// Turn the left operand of an assignment, and the operand of `++`/`--`, into
/// a definition.
///
/// Kept separate from the main walk because it needs the *enclosing*
/// expression's tag, and the walk visits a node before it knows what encloses
/// it. A compound assignment (`x += 1`) and an increment both read and write,
/// so the use stays and a definition is added; a plain `=` is a write only, so
/// the use is removed.
fn promote_writes(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
    definitions: &mut Vec<Definition>,
    uses: &mut Vec<Use>,
) {
    let arena = tree.arena();
    let mut promoted: Vec<(Span, DefKind, u32)> = Vec::new();

    for node in arena.preorder(root) {
        let tag = arena.tag(node).and_then(NodeTag::from_u16);
        match tag {
            Some(NodeTag::AssignExpr) => {
                // The first child is the target. A plain `=` writes only; every
                // compound operator reads it too.
                let Some(target) = arena.children_iter(node).next() else {
                    continue;
                };
                let compound = assign_is_compound(tree, text, node);
                // Only a *direct* name is a definition. `a[i] = v`, `s.f = v`
                // and `*p = v` all store into memory the base merely points
                // at, so the base is read, not written. Calling them
                // definitions would kill the real reaching definition of the
                // base --- unsound in the dangerous direction, and the exact
                // opposite of what this module claims to do.
                if !is_direct_name(tree, target) {
                    continue;
                }
                let effect_at = arena
                    .span(node, token_spans)
                    .map_or(0, |whole| whole.hi);
                if let Some((_, span)) = leftmost_name(tree, text, token_spans, target) {
                    promoted.push((
                        span,
                        if compound {
                            DefKind::CompoundAssignment
                        } else {
                            DefKind::Assignment
                        },
                        effect_at,
                    ));
                }
            }
            // `i++` parses as a `PostfixExpr` holding a `NameRef` and an
            // `IncDecSuffix` side by side, so the operand is the suffix's
            // *sibling*. Reading the enclosing node is what finds it; reading
            // the suffix finds only the `++` token.
            // `&x` --- how C spells an out parameter. The callee may write
            // through the pointer, so after this point `x` holds something
            // this analysis cannot name. Recording a definition is the
            // conservative reading: it stops a later read looking like a read
            // of uninitialized storage, and it stops an earlier write to `x`
            // looking dead when the callee is what reads it.
            Some(NodeTag::UnaryExpr) if takes_address(tree, text, node) => {
                let effect_at = arena.span(node, token_spans).map_or(0, |whole| whole.hi);
                if let Some((_, span)) = leftmost_name(tree, text, token_spans, node) {
                    promoted.push((span, DefKind::AddressTaken, effect_at));
                }
            }
            Some(NodeTag::PostfixExpr) | Some(NodeTag::UnaryExpr) => {
                if !mentions_inc_dec(tree, text, node) {
                    continue;
                }
                // `++rank[ra]` increments an element, not the base, for the
                // same reason `rank[ra] = 1` does not define `rank`.
                if has_place_suffix(tree, node) {
                    continue;
                }
                let effect_at = arena
                    .span(node, token_spans)
                    .map_or(0, |whole| whole.hi);
                if let Some((_, span)) = leftmost_name(tree, text, token_spans, node) {
                    promoted.push((span, DefKind::IncDec, effect_at));
                }
            }
            _ => {}
        }
    }

    for (span, kind, effect_at) in promoted {
        // The use recorded for this name is the one whose span matches, and it
        // already carries the binding the scope walk resolved.
        let Some(index) = uses.iter().position(|u| u.span == span) else {
            continue;
        };
        let source = uses[index].clone();
        definitions.push(Definition {
            binding: source.binding,
            name: source.name.clone(),
            node: 0,
            span,
            effect_at,
            kind,
        });
        if kind == DefKind::Assignment {
            uses.remove(index);
        }
    }
}

/// The innermost binding of `name`, or [`Binding::FREE`].
fn resolve(scopes: &[Scope], name: &str) -> Binding {
    for scope in scopes.iter().rev() {
        for (bound, binding) in scope.iter().rev() {
            if bound == name {
                return *binding;
            }
        }
    }
    Binding::FREE
}

/// The identifier `node` carries, with its span.
fn name_of(tree: &Tree, text: &str, token_spans: &[Span], node: NodeId) -> Option<(String, Span)> {
    let arena = tree.arena();
    let (first, end) = arena.token_extent(node)?;
    for index in first..end {
        let id = crate::syntax::ids::TokenId::new(index);
        if tree.tokens().kind(id) == TokenKind::Identifier.as_u16() {
            // The span, not `Tokens::text`: that helper runs to the next
            // token's start and so carries trailing whitespace, which made
            // `x` and `x ` two different bindings.
            let span = *token_spans.get(index as usize)?;
            let name = text.get(span.lo as usize..span.hi as usize)?;
            return Some((name.to_string(), span));
        }
    }
    None
}

/// The first identifier at or under `node`, which is the assignment target's
/// base variable: `x`, `a[i]`'s `a`, `s.f`'s `s`, `*p`'s `p`.
fn leftmost_name(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    node: NodeId,
) -> Option<(String, Span)> {
    let arena = tree.arena();
    for candidate in arena.preorder(node) {
        if arena.tag(candidate) == Some(NodeTag::NameRef.as_u16()) {
            return name_of(tree, text, token_spans, candidate);
        }
    }
    None
}

/// Whether an `AssignExpr`'s operator is a compound one (`+=`, `<<=`, …).
fn assign_is_compound(tree: &Tree, text: &str, node: NodeId) -> bool {
    operator_text(tree, text, node, |t| t.ends_with('=') && t != "=").is_some()
}

/// Whether this node's own tokens contain `++` or `--`.
fn mentions_inc_dec(tree: &Tree, text: &str, node: NodeId) -> bool {
    operator_text(tree, text, node, |t| t == "++" || t == "--").is_some()
}

/// The first token under `node` whose text satisfies `matches`.
fn operator_text(
    tree: &Tree,
    text: &str,
    node: NodeId,
    matches: impl Fn(&str) -> bool,
) -> Option<String> {
    let (first, end) = tree.arena().token_extent(node)?;
    for index in first..end {
        let id = crate::syntax::ids::TokenId::new(index);
        // Trimmed: `Tokens::text` runs to the next token's start, so `+=`
        // arrives as `"+= "` and no suffix test on it can succeed.
        let token = tree.tokens().text(id, text).trim();
        if matches(token) {
            return Some(token.to_string());
        }
    }
    None
}

/// The name spans of declarators that carry an initializer.
///
/// `int a = 1, b;` initializes `a` and not `b`, so this pairs each declarator
/// with the initializer that follows it before the next one. A declarator with
/// no initializer binds a name and writes nothing, which is the difference
/// between "this local is dead" and "this local is uninitialized".
fn initialized_declarator_spans(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<Span> {
    let arena = tree.arena();
    let mut out = Vec::new();
    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::Decl.as_u16()) {
            continue;
        }
        // Every declared name and every initializer in this declaration, in
        // source order.
        let mut names: Vec<Span> = Vec::new();
        let mut inits: Vec<Span> = Vec::new();
        let mut arrays: Vec<Span> = Vec::new();
        for inner in arena.preorder(node) {
            match arena.tag(inner).and_then(NodeTag::from_u16) {
                Some(NodeTag::DeclName) => {
                    if let Some((_, span)) = name_of(tree, text, token_spans, inner) {
                        names.push(span);
                    }
                }
                Some(NodeTag::Initializer) | Some(NodeTag::InitList) => {
                    if let Some(span) = arena.span(inner, token_spans) {
                        inits.push(span);
                    }
                }
                Some(NodeTag::ArraySuffix) => {
                    if let Some(span) = arena.span(inner, token_spans) {
                        arrays.push(span);
                    }
                }
                _ => {}
            }
        }
        names.sort_by_key(|span| span.lo);
        for (index, name) in names.iter().enumerate() {
            let next = names.get(index + 1).map_or(u32::MAX, |span| span.lo);
            let has_initializer = inits
                .iter()
                .any(|init| init.lo >= name.hi && init.lo < next);
            // `int a[8];` has no initializer but still defines `a`: the array
            // decays to a well-defined address, and reading `a` to subscript
            // it is not a read of uninitialized storage. Only the *elements*
            // are uninitialized, and this analysis does not model elements.
            let is_array = arrays
                .iter()
                .any(|suffix| suffix.lo >= name.hi && suffix.lo < next);
            if has_initializer || is_array {
                out.push(*name);
            }
        }
    }
    out
}

/// Whether this unary expression is `&` applied to a bare name.
///
/// `&x` only. `&a[i]` and `&s.f` name interior storage, and treating them as
/// a definition of the base would claim the callee can replace the whole
/// object, which over-approximates further than the rest of this module does.
fn takes_address(tree: &Tree, text: &str, node: NodeId) -> bool {
    let arena = tree.arena();
    let Some((first, end)) = arena.token_extent(node) else {
        return false;
    };
    if first >= end {
        return false;
    }
    let id = crate::syntax::ids::TokenId::new(first);
    if tree.tokens().text(id, text).trim() != "&" {
        return false;
    }
    // Exactly one name under it, and nothing that subscripts or selects.
    let names = arena
        .preorder(node)
        .filter(|inner| arena.tag(*inner) == Some(NodeTag::NameRef.as_u16()))
        .count();
    let interior = arena
        .preorder(node)
        .filter(|inner| {
            matches!(
                arena.tag(*inner).and_then(NodeTag::from_u16),
                Some(NodeTag::IndexSuffix) | Some(NodeTag::MemberSuffix) | Some(NodeTag::CallArgs)
            )
        })
        .count();
    names == 1 && interior == 0
}

/// Whether an assignment target is a bare name rather than a place expression.
///
/// `x = v` writes `x`. `a[i] = v`, `s.f = v` and `*p = v` write memory the
/// base points at, and the base itself is unchanged; treating those as
/// definitions of the base kills the base's real reaching definition, which is
/// unsound in the direction that loses edges rather than adds them.
///
/// A parenthesised name is still a name: `(x) = v` writes `x`.
fn is_direct_name(tree: &Tree, target: NodeId) -> bool {
    let arena = tree.arena();
    let mut node = target;
    loop {
        match arena.tag(node).and_then(NodeTag::from_u16) {
            Some(NodeTag::NameRef) => return true,
            Some(NodeTag::ParenExpr) => {
                // Descend through the parentheses to whatever they wrap.
                match arena.children_iter(node).next() {
                    Some(child) => node = child,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
}

/// The spans of names that are types rather than values.
///
/// A declaration's specifiers and a cast's type name both hold identifiers ---
/// `int32_t`, a struct tag, a typedef --- and none of them is a read of a
/// variable. Collected as spans because the walk that needs the answer sees a
/// name before it knows what encloses it.
fn type_name_spans(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<Span> {
    let arena = tree.arena();
    let mut out = Vec::new();
    for node in arena.preorder(root) {
        let tag = arena.tag(node).and_then(NodeTag::from_u16);

        // The declared positions, where a name is a type by construction.
        if matches!(
            tag,
            Some(NodeTag::DeclSpecifiers) | Some(NodeTag::TypeName) | Some(NodeTag::ParamList)
        ) {
            for inner in arena.preorder(node) {
                if arena.tag(inner) == Some(NodeTag::NameRef.as_u16()) {
                    if let Some((_, span)) = name_of(tree, text, token_spans, inner) {
                        out.push(span);
                    }
                }
            }
            continue;
        }

        // `sizeof(T)` and `_Alignof(T)`. Without a typedef table the parser
        // cannot tell `sizeof(x)` from `sizeof(T)` --- `look.rs` says so and
        // says why --- so the operand arrives as a parenthesised name either
        // way. It is a type position all the same, and counting it as a read
        // of an undefined variable was 517 of the 1,970 unresolved uses this
        // analysis first reported over the fixture corpus.
        // `sizeof(T)` moved to `ambiguous_type_spans`: without a typedef
        // table `sizeof(x)` and `sizeof(T)` are the same shape, and only the
        // binding tells them apart.
        let _ = tag;
    }
    out
}

/// Names sitting where a type *or* a value is legal, so only the binding
/// decides which.
///
/// `sizeof(int32_t)` is a type; `sizeof(pointer)` reads a pointer. `look.rs`
/// records that this parser resolves neither, deliberately, because the CFG
/// cannot see the difference. The data-dependence graph can, and the binding
/// is the evidence: a name that resolves to a local is a value.
fn ambiguous_type_spans(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<Span> {
    let arena = tree.arena();
    let mut out = Vec::new();
    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::UnaryExpr.as_u16()) {
            continue;
        }
        if !starts_with_sizeof(tree, text, node) {
            continue;
        }
        if let Some(span) = lone_parenthesised_name(tree, text, token_spans, node) {
            out.push(span);
        }
    }
    out
}

/// Whether `node` subscripts, selects a member of, or calls something.
fn has_place_suffix(tree: &Tree, node: NodeId) -> bool {
    let arena = tree.arena();
    arena.preorder(node).any(|inner| {
        matches!(
            arena.tag(inner).and_then(NodeTag::from_u16),
            Some(NodeTag::IndexSuffix) | Some(NodeTag::MemberSuffix) | Some(NodeTag::CallArgs)
        )
    })
}

/// Whether this unary expression's operator is `sizeof` or `_Alignof`.
fn starts_with_sizeof(tree: &Tree, text: &str, node: NodeId) -> bool {
    let Some((first, end)) = tree.arena().token_extent(node) else {
        return false;
    };
    if first >= end {
        return false;
    }
    let id = crate::syntax::ids::TokenId::new(first);
    matches!(
        tree.tokens().text(id, text).trim(),
        "sizeof" | "_Alignof" | "alignof" | "__alignof__"
    )
}

/// The span of the single name inside `node`'s parenthesised operand, when
/// that is all the parentheses contain.
///
/// `(T)` yields the name; `(a + b)` and `(a.b)` yield nothing, because those
/// are unambiguously expressions.
fn lone_parenthesised_name(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    node: NodeId,
) -> Option<Span> {
    let arena = tree.arena();
    let paren = arena
        .children_iter(node)
        .find(|child| arena.tag(*child) == Some(NodeTag::ParenExpr.as_u16()))?;
    let names: Vec<NodeId> = arena
        .preorder(paren)
        .filter(|inner| arena.tag(*inner) == Some(NodeTag::NameRef.as_u16()))
        .collect();
    if names.len() != 1 {
        return None;
    }
    // Nothing but the name and its parentheses: no operator, no suffix.
    let interior: usize = arena
        .preorder(paren)
        .filter(|inner| {
            !matches!(
                arena.tag(*inner).and_then(NodeTag::from_u16),
                Some(NodeTag::ParenExpr) | Some(NodeTag::NameRef)
            )
        })
        .count();
    if interior != 0 {
        return None;
    }
    name_of(tree, text, token_spans, names[0]).map(|(_, span)| span)
}

/// The spans of names in callee position.
///
/// `f(x)` parses as a postfix expression whose first child is the callee and
/// whose `CallArgs` child holds the arguments. The callee's *name* is only a
/// data read when it resolves to a local binding --- a function pointer. A
/// plain `memcpy` resolves to nothing, and counting it as a read of an
/// undefined variable is noise, not a finding.
fn callee_name_spans(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<Span> {
    let arena = tree.arena();
    let mut out = Vec::new();
    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::PostfixExpr.as_u16()) {
            continue;
        }
        let children: Vec<NodeId> = arena.children_iter(node).collect();
        let calls = children
            .iter()
            .any(|child| arena.tag(*child) == Some(NodeTag::CallArgs.as_u16()));
        if !calls {
            continue;
        }
        let Some(first) = children.first() else {
            continue;
        };
        match arena.tag(*first).and_then(NodeTag::from_u16) {
            Some(NodeTag::NameRef) => {
                if let Some((_, span)) = name_of(tree, text, token_spans, *first) {
                    out.push(span);
                }
            }
            // `(T)(x)` and `(f)(x)` are the same shape, and `look.rs` records
            // that the parser resolves the ambiguity toward the call reading
            // on purpose. Either way the parenthesised name is in callee
            // position, so the binding test decides: a resolved name is a
            // function pointer being read, a free one is a type or a function.
            Some(NodeTag::ParenExpr) => {
                let names: Vec<NodeId> = arena
                    .preorder(*first)
                    .filter(|inner| arena.tag(*inner) == Some(NodeTag::NameRef.as_u16()))
                    .collect();
                if names.len() == 1 {
                    if let Some((_, span)) = name_of(tree, text, token_spans, names[0]) {
                        out.push(span);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Every named parameter of the function rooted at `root`, in order.
///
/// A parameter list is one opaque token run (`tag.rs`: "a construct with no
/// control flow and no lowering consequence --- an attribute, an `asm` operand
/// list, a parameter list --- is kept as a token run inside one opaque node"),
/// so this reads tokens rather than walking children.
///
/// The rule is the declarator-name position: an identifier immediately
/// followed by `,`, `)` or `[` is a parameter's name. That takes the `a` of
/// `int a`, the `name` of `const char *name` and the `v` of `int v[8]`, and
/// takes nothing from `(void)` or from an unnamed `int`. A function-pointer
/// parameter names its own parameters too; those bind to nothing in the body
/// and cost a definition that reaches no use, which the dead-store census
/// reports rather than hides.
fn parameter_names(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    root: NodeId,
) -> Vec<(String, Span)> {
    let arena = tree.arena();
    let mut out = Vec::new();
    for node in arena.preorder(root) {
        if arena.tag(node) != Some(NodeTag::ParamList.as_u16()) {
            continue;
        }
        let Some((first, end)) = arena.token_extent(node) else {
            continue;
        };
        for index in first..end {
            let id = crate::syntax::ids::TokenId::new(index);
            if tree.tokens().kind(id) != TokenKind::Identifier.as_u16() {
                continue;
            }
            let next = crate::syntax::ids::TokenId::new(index + 1);
            if index + 1 >= end {
                continue;
            }
            let follows = tree.tokens().text(next, text).trim();
            if !matches!(follows, "," | ")" | "[") {
                continue;
            }
            let Some(span) = token_spans.get(index as usize).copied() else {
                continue;
            };
            if let Some(name) = text.get(span.lo as usize..span.hi as usize) {
                out.push((name.to_string(), span));
            }
        }
        // The outermost list is the function's own; a nested one belongs to a
        // function-pointer parameter and is already covered by the scan above.
        break;
    }
    out
}

/// The CFG node whose spans contain `span`, or the entry when none does.
///
/// Falling back to the entry rather than dropping the event is deliberate: a
/// parameter is declared in the header, which no statement node covers, and
/// dropping it would leave every read of that parameter unresolved.
fn node_for_span(cfg: &Cfg, span: Span) -> u32 {
    for (index, node) in cfg.nodes().iter().enumerate() {
        for covered in node.spans() {
            if covered.lo <= span.lo && span.hi <= covered.hi {
                return index as u32;
            }
        }
    }
    cfg.entry().index() as u32
}

