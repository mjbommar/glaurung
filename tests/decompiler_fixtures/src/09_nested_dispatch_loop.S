/*
 * A real x86-64 PIC dispatch nested inside a multi-exit parser loop.
 *
 * The outer natural-loop header does not directly feed the table dispatch: a
 * separate bounds-check block sits between them. Three distinct exits leave
 * the outer loop, and the common case path contains a nested back-edge. This is
 * the minimized ownership shape from gnutls certtool's yyparse: CFG discovery
 * resolves every table slot, but a whole-function structuring fallback used to
 * discard the dispatch and render an unrecovered indirect jump.
 */

    .text
    .globl nested_dispatch_parser
    .type nested_dispatch_parser, @function
nested_dispatch_parser:
    xorl %eax, %eax
    jmp .Louter_header

.Louter_header:
    testl %edi, %edi
    jle .Lexit_empty

.Lbounds:
    movl %esi, %edx
    andl $7, %edx
    cmpl $7, %edx
    ja .Lexit_bad_token
    leaq .Ldispatch_table(%rip), %rcx
    movslq (%rcx,%rdx,4), %rdx
    addq %rcx, %rdx
    notrack jmp *%rdx

.Lcase0:
    addl $1, %eax
    jmp .Linner_header
.Lcase1:
    addl $3, %eax
    jmp .Linner_header
.Lcase2:
    addl $5, %eax
    jmp .Linner_header
.Lcase3:
    cmpl $42, %eax
    je .Lexit_accept
    addl $7, %eax
    jmp .Linner_header
.Lcase4:
    xorl $0x11, %eax
    jmp .Linner_header
.Lcase5:
    subl $2, %eax
    jmp .Linner_header
.Lcase6:
    orl $0x20, %eax
    jmp .Linner_header
.Lcase7:
    addl %esi, %eax

.Linner_header:
    cmpl $16, %eax
    jle .Louter_latch
    subl $3, %eax
    testl $1, %eax
    jne .Linner_header

.Louter_latch:
    subl $1, %edi
    addl $1, %esi
    jmp .Louter_header

.Lexit_empty:
    ret
.Lexit_bad_token:
    movl $-1, %eax
    ret
.Lexit_accept:
    movl $1, %eax
    ret
    .size nested_dispatch_parser, .-nested_dispatch_parser

    .section .rodata
    .p2align 2
.Ldispatch_table:
    .long .Lcase0-.Ldispatch_table
    .long .Lcase1-.Ldispatch_table
    .long .Lcase2-.Ldispatch_table
    .long .Lcase3-.Ldispatch_table
    .long .Lcase4-.Ldispatch_table
    .long .Lcase5-.Ldispatch_table
    .long .Lcase6-.Ldispatch_table
    .long .Lcase7-.Ldispatch_table

    .section .note.GNU-stack,"",@progbits
