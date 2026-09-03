//! `F-5`..`F-7` --- the C AST node tags: the `u16` the substrate stores and
//! never interprets.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md` `REQ-GEN-5` (the AST
//! must be lowerable) and section 8 (the non-requirements that keep this list
//! short).
//!
//! # Why this list is this short
//!
//! Section 8 forbids a C semantic model: no type resolution, no CPG, no
//! statement fidelity beyond what a control-flow graph reads. So the tag space
//! is sized by its two consumers and nothing else. The **CFG builder** needs
//! every construct that forks, joins, jumps or repeats, which is why `IfStmt`,
//! `SwitchStmt`, `CaseLabel` and `CondExpr` each get their own tag while
//! `struct`, `union` and `enum` bodies share one opaque [`NodeTag::StructBody`].
//! The **lowering** of `roadmap.md` stage S4 needs declarations, initializers,
//! types as written and the declaration-versus-expression distinction, which is
//! why `Decl`, `Initializer`, `TypeName` and `ExprStmt` exist even though the
//! first consumer never reads them.
//!
//! Nothing else earns a tag. A construct with no control flow and no lowering
//! consequence --- an attribute, an `asm` operand list, a parameter list, a
//! `_Generic` selection --- is kept as a *token run* inside one opaque node.
//! The tokens are still there, so a later consumer can re-read them
//! (`REQ-GEN-2`: spans survive); what is absent is a grammar for them, which is
//! the part that would have to be maintained.
//!
//! # Why operator nodes are flat rather than nested
//!
//! [`crate::syntax::event::Events`] deliberately has no `precede` operation
//! (`docs/design/source-front-ends/substrate.md` section 2.2), so a node cannot
//! be wrapped around a subtree that has already been emitted. A left-
//! associative binary chain therefore cannot be built as `((a+b)+c)` without
//! knowing the chain's length before its first operand is parsed. It is built
//! **flat** instead: one [`NodeTag::BinaryExpr`] per precedence level, holding
//! every operand of that level in source order with the operator tokens between
//! them. Left association is then a reading convention rather than a shape, and
//! no information is lost --- the operators are in the node.
//! [`NodeTag::PostfixExpr`] is flat for the same reason, with one suffix node
//! per link of the chain.

/// Declares the [`NodeTag`] enum together with a dense discriminant, a place in
/// [`NodeTag::ALL`] and a name for every entry --- one table rather than three
/// that have to agree, exactly as `csource::lex::kind` does for token kinds.
macro_rules! node_tags {
    ($( $variant:ident => $name:literal , )*) => {
        /// One C AST node's kind: the `u16` tag an `Open` event carries.
        ///
        /// Numbered densely from zero in the order written below, so
        /// [`NodeTag::from_u16`] is an array index rather than a match and a
        /// tag census can be a flat table.
        #[repr(u16)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum NodeTag {
            $(
                #[doc = concat!("The `", $name, "` node.")]
                $variant,
            )*
        }

        impl NodeTag {
            /// Every tag, in discriminant order.
            pub const ALL: &'static [NodeTag] = &[ $( NodeTag::$variant, )* ];

            /// This tag's name, for diagnostics and for a census dump.
            pub const fn name(self) -> &'static str {
                match self {
                    $( NodeTag::$variant => $name, )*
                }
            }
        }
    };
}

node_tags! {
    // --- machinery ----------------------------------------------------------
    Pending => "pending",
    Error => "error",
    PpDirective => "pp_directive",

    // --- declarations -------------------------------------------------------
    Decl => "decl",
    FuncDef => "func_def",
    DeclSpecifiers => "decl_specifiers",
    StructBody => "struct_body",
    Attribute => "attribute",
    Asm => "asm",
    StaticAssert => "static_assert",
    LocalLabel => "local_label",
    Declarator => "declarator",
    DeclName => "decl_name",
    ParamList => "param_list",
    ArraySuffix => "array_suffix",
    Initializer => "initializer",
    InitList => "init_list",
    Designator => "designator",
    TypeName => "type_name",

    // --- statements ---------------------------------------------------------
    CompoundStmt => "compound_stmt",
    ExprStmt => "expr_stmt",
    NullStmt => "null_stmt",
    IfStmt => "if_stmt",
    WhileStmt => "while_stmt",
    DoWhileStmt => "do_while_stmt",
    ForStmt => "for_stmt",
    ForInit => "for_init",
    ForCond => "for_cond",
    ForStep => "for_step",
    SwitchStmt => "switch_stmt",
    CaseLabel => "case_label",
    DefaultLabel => "default_label",
    LabelStmt => "label_stmt",
    GotoStmt => "goto_stmt",
    BreakStmt => "break_stmt",
    ContinueStmt => "continue_stmt",
    ReturnStmt => "return_stmt",

    // --- expressions --------------------------------------------------------
    CommaExpr => "comma_expr",
    AssignExpr => "assign_expr",
    CondExpr => "cond_expr",
    BinaryExpr => "binary_expr",
    CastExpr => "cast_expr",
    CompoundLiteral => "compound_literal",
    UnaryExpr => "unary_expr",
    SizeofType => "sizeof_type",
    AlignofType => "alignof_type",
    PostfixExpr => "postfix_expr",
    CallArgs => "call_args",
    IndexSuffix => "index_suffix",
    MemberSuffix => "member_suffix",
    IncDecSuffix => "inc_dec_suffix",
    ParenExpr => "paren_expr",
    StmtExpr => "stmt_expr",
    NameRef => "name_ref",
    Literal => "literal",
    BuiltinExpr => "builtin_expr",
    LabelAddr => "label_addr",
}

impl NodeTag {
    /// This tag as the `u16` an `Open` event carries.
    ///
    /// A plain cast, which is the reason the enum is `#[repr(u16)]`: the
    /// discriminant *is* the wire format, not something derived from it.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// The tag a `u16` denotes, or `None` when it names no tag.
    ///
    /// `None` is the honest answer for
    /// [`crate::syntax::event::Events::TOMBSTONE_TAG`] and for any value a
    /// different front end wrote, so a consumer reading a foreign arena
    /// degrades rather than mis-labelling.
    pub fn from_u16(tag: u16) -> Option<NodeTag> {
        Self::ALL.get(tag as usize).copied()
    }

    /// Whether this tag names a statement, which is the question the CFG
    /// builder asks most often.
    pub const fn is_statement(self) -> bool {
        let tag = self.as_u16();
        NodeTag::CompoundStmt.as_u16() <= tag && tag <= NodeTag::ReturnStmt.as_u16()
    }

    /// Whether this tag names an expression.
    pub const fn is_expression(self) -> bool {
        let tag = self.as_u16();
        NodeTag::CommaExpr.as_u16() <= tag && tag <= NodeTag::LabelAddr.as_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::event::Events;

    #[test]
    fn discriminants_are_dense_and_round_trip() {
        for (index, tag) in NodeTag::ALL.iter().enumerate() {
            assert_eq!(tag.as_u16(), index as u16, "{tag:?} is not at its index");
            assert_eq!(NodeTag::from_u16(index as u16), Some(*tag));
        }
        assert_eq!(NodeTag::from_u16(NodeTag::ALL.len() as u16), None);
    }

    #[test]
    fn no_tag_collides_with_the_substrates_tombstone() {
        // A tag equal to TOMBSTONE_TAG would make every node of that kind
        // silently vanish from the tree rather than fail loudly.
        for tag in NodeTag::ALL {
            assert_ne!(
                tag.as_u16(),
                Events::TOMBSTONE_TAG,
                "{tag:?} is a tombstone"
            );
        }
        println!("NodeTag::ALL.len() = {}", NodeTag::ALL.len());
    }

    #[test]
    fn the_group_predicates_match_the_table_layout() {
        assert!(NodeTag::IfStmt.is_statement());
        assert!(NodeTag::ReturnStmt.is_statement());
        assert!(!NodeTag::Decl.is_statement());
        assert!(!NodeTag::CommaExpr.is_statement());
        assert!(NodeTag::CommaExpr.is_expression());
        assert!(NodeTag::LabelAddr.is_expression());
        assert!(!NodeTag::ReturnStmt.is_expression());
        for tag in NodeTag::ALL {
            assert!(
                !(tag.is_statement() && tag.is_expression()),
                "{tag:?} is in two groups"
            );
        }
    }

    #[test]
    fn every_name_is_distinct() {
        let mut names: Vec<&str> = NodeTag::ALL.iter().map(|tag| tag.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "two tags share a name");
    }
}
