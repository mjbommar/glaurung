# A non-CET sibling-call thunk, the shape every rustc cdylib emits:
#
#   __rust_dealloc: jmp __rdl_dealloc
#
# No ENDBR marks the target, so only the symbol table says it is a function.
# `hot` jumps into `hot.cold`, GCC's name for the split-off cold part of the
# SAME function: that jump is local and must stay a branch.
    .text

    .globl real_dealloc
    .type real_dealloc, @function
real_dealloc:
    mov %rdi, %rax
    add %rsi, %rax
    add %rdx, %rax
    ret
    .size real_dealloc, .-real_dealloc

    .globl dealloc_thunk
    .type dealloc_thunk, @function
dealloc_thunk:
    jmp real_dealloc
    .size dealloc_thunk, .-dealloc_thunk

    .globl hot
    .type hot, @function
hot:
    test %edi, %edi
    je 1f
    mov $1, %eax
    ret
1:
    jmp hot.cold
    .size hot, .-hot

    .type hot.cold, @function
hot.cold:
    mov $2, %eax
    ret
    .size hot.cold, .-hot.cold

    .globl tail_caller
    .type tail_caller, @function
tail_caller:
    mov $1, %edi
    mov $2, %esi
    mov $3, %edx
    call dealloc_thunk
    ret
    .size tail_caller, .-tail_caller
