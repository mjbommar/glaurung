"""Tests for the annotated-lift store-grounding pass.

The 2026-05-26 hunt cycle's AfdRestartBufferSend disproof
(findings/.../AFD_RESTARTBUFFERSEND_UAF/) caught the LLM emitting
`*(u64*)node = *(u64*)(conn+0x8)` as a memory store when the actual
disassembly was `mov rax, [r8+38h]; mov r8, [rsi+8]` -- both
register-only argument-builds.

These tests pin the grounding pass that flags this pattern.
"""

from __future__ import annotations

import pytest

from glaurung.llm.tools.rewrite_function_idiomatic import (
    AnnotatedBranch,
    AnnotatedCallSite,
    AnnotatedFunction,
    AnnotatedMemAccess,
    CodeBlock,
    _STORE_PATTERN_RE,
    _ground_annotated_lift,
)


class TestStorePatternRegex:
    """Regex must catch store-shaped lines without false-positives."""

    @pytest.mark.parametrize("line", [
        "*(u64*)node = *(u64*)(conn+0x8);",
        "*node = value;",
        "obj->field = 1;",
        "  obj->state = 4;  ",
        "ptr[i] = x;",
        "*(uint32_t *)dst = 0x1000;",
    ])
    def test_matches_store_shapes(self, line):
        assert _STORE_PATTERN_RE.match(line) is not None, line

    @pytest.mark.parametrize("line", [
        "if (*ptr == 0) return;",
        "x = *ptr;",
        "if (obj->field == 1) {",
        "while (ptr[i] != 0) i++;",
        "return *ptr;",
        "u32 v = obj->count;",
        "// *ptr = ...  this is a comment",  # leading // breaks the start anchor
    ])
    def test_does_not_match_non_stores(self, line):
        assert _STORE_PATTERN_RE.match(line) is None, line


class TestGroundingPass:
    """End-to-end grounding pass on AnnotatedFunction objects."""

    def test_no_change_when_block_has_matching_write(self):
        """If a block claims a write in mem_accesses, trust its lifted_c."""
        block = CodeBlock(
            start_va="0x1000",
            end_va="0x1010",
            lifted_c="*ptr = 42;",
            calls=[],
            mem_accesses=[
                AnnotatedMemAccess(va="0x1004", kind="write", width=4, addr_expr="*ptr"),
            ],
            branches=[],
            block_confidence=0.8,
        )
        ann = AnnotatedFunction(
            prototype="void f(void)",
            blocks=[block],
            overall_confidence=0.8,
        )
        out = _ground_annotated_lift(ann)
        assert out.blocks[0].lifted_c == "*ptr = 42;"
        # No GROUNDING note added.
        assert not any("SYNTHESIZED" in a for a in out.assumptions)

    def test_flags_store_with_no_matching_mem_access(self):
        """The AfdRestartBufferSend hallucination shape gets flagged."""
        block = CodeBlock(
            start_va="0x1c002030c",
            end_va="0x1c0020320",
            lifted_c=(
                "u64 *conn = *(u64 **)(node + 0x30);\n"
                "*(u64*)node = *(u64*)(conn + 0x8);\n"
                "sub_helper(conn);"
            ),
            calls=[
                AnnotatedCallSite(
                    call_va="0x1c002031a",
                    callee="sub_helper",
                    kind="direct",
                ),
            ],
            mem_accesses=[
                # Only the initial read; NO write entry.
                AnnotatedMemAccess(
                    va="0x1c002030c", kind="read", width=8,
                    addr_expr="*(node + 0x30)",
                ),
                AnnotatedMemAccess(
                    va="0x1c0020312", kind="read", width=8,
                    addr_expr="*(conn + 0x8)",
                ),
            ],
            branches=[
                AnnotatedBranch(va="0x1c002031f", kind="return"),
            ],
            block_confidence=0.5,
        )
        ann = AnnotatedFunction(
            prototype="void AfdRestartBufferSend(void *node, ...);",
            blocks=[block],
            overall_confidence=0.5,
        )
        out = _ground_annotated_lift(ann)
        # The hallucinated store line should now be prefixed with the
        # SYNTHESIZED marker.
        flagged = out.blocks[0].lifted_c
        assert "SYNTHESIZED -- unverified store" in flagged
        assert "*(u64*)node = *(u64*)(conn + 0x8);" in flagged
        # And the top-level assumptions should include the GROUNDING note.
        assert any("GROUNDING" in a for a in out.assumptions)

    def test_legit_store_in_block_with_writes_not_flagged(self):
        """A block with writes claimed is trusted at the block level."""
        block = CodeBlock(
            start_va="0x2000",
            end_va="0x2020",
            lifted_c=(
                "obj->field1 = 1;\n"
                "obj->field2 = 2;"
            ),
            calls=[],
            mem_accesses=[
                AnnotatedMemAccess(
                    va="0x2004", kind="write", width=4,
                    addr_expr="obj->field1",
                ),
                # No mem_access for field2; but block-level grounding
                # accepts both because the block claims at least one
                # write.
            ],
            branches=[],
            block_confidence=0.9,
        )
        ann = AnnotatedFunction(
            prototype="void f(struct s *obj)",
            blocks=[block],
            overall_confidence=0.9,
        )
        out = _ground_annotated_lift(ann)
        # Block was not modified.
        assert out.blocks[0].lifted_c == block.lifted_c
        assert not any("SYNTHESIZED" in a for a in out.assumptions)

    def test_handles_empty_annotated_function(self):
        """Empty input returns unchanged."""
        ann = AnnotatedFunction(
            prototype="void f(void)",
            blocks=[],
            overall_confidence=0.0,
        )
        out = _ground_annotated_lift(ann)
        assert out is ann or out.blocks == []
