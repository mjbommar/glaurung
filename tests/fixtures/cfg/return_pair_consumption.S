.text
.globl scalar_error
.type scalar_error,@function
scalar_error:
    mov %edi, %eax
    xor %edx, %edx
    ret
.size scalar_error,.-scalar_error
.globl unrelated_pair
.type unrelated_pair,@function
unrelated_pair:
    mov %edi, %eax
    add $1, %eax
    mov $2, %edx
    ret
.size unrelated_pair,.-unrelated_pair
.globl later_call_caller
.type later_call_caller,@function
later_call_caller:
    sub $8, %rsp
    mov $42, %edi
    call scalar_error
    xor %edi, %edi
    call unrelated_pair
    add %rdx, %rax
    add $8, %rsp
    ret
.size later_call_caller,.-later_call_caller
.globl padding_caller
.type padding_caller,@function
padding_caller:
    sub $8, %rsp
    mov $42, %edi
    call scalar_error
    push %rdx
    mov $17, %edx
    push %rax
    xor %eax, %eax
    call capture_scalar
    add $16, %rsp
    add $8, %rsp
    ret
.size padding_caller,.-padding_caller
.type capture_scalar,@function
capture_scalar:
    mov 8(%rsp), %rax
    ret
.size capture_scalar,.-capture_scalar
.globl pair_caller
.type pair_caller,@function
pair_caller:
    sub $8, %rsp
    xor %edi, %edi
    call unrelated_pair
    add %rdx, %rax
    add $8, %rsp
    ret
.size pair_caller,.-pair_caller
.section .note.GNU-stack,"",@progbits
.text
.globl spill_pair_caller
.type spill_pair_caller,@function
spill_pair_caller:
    sub $24, %rsp
    xor %edi, %edi
    call unrelated_pair
    mov %rax, 8(%rsp)
    mov %rdx, 16(%rsp)
    xor %eax, %eax
    xor %edx, %edx
    mov 8(%rsp), %rcx
    mov 16(%rsp), %rsi
    lea (%rcx,%rsi), %rax
    add $24, %rsp
    ret
.size spill_pair_caller,.-spill_pair_caller

.text
.globl stack_pair_caller
.type stack_pair_caller,@function
stack_pair_caller:
    sub $8, %rsp
    xor %edi, %edi
    call unrelated_pair
    push %rdx
    push %rax
    call consume_stack_pair
    add $16, %rsp
    add $8, %rsp
    ret
.size stack_pair_caller,.-stack_pair_caller
.globl consume_stack_pair
.type consume_stack_pair,@function
consume_stack_pair:
    mov 8(%rsp), %rax
    mov 16(%rsp), %rdx
    add %rdx, %rax
    ret
.size consume_stack_pair,.-consume_stack_pair
.text
.globl frame_pair_caller
.type frame_pair_caller,@function
frame_pair_caller:
    push %rbp
    sub $32, %rsp
    mov %rsp, %rbp
    xor %edi, %edi
    call unrelated_pair
    mov %rax, 8(%rsp)
    mov %rdx, 16(%rbp)
    xor %eax, %eax
    xor %edx, %edx
    mov 8(%rbp), %rcx
    mov 16(%rsp), %rsi
    lea (%rcx,%rsi), %rax
    add $32, %rsp
    pop %rbp
    ret
.size frame_pair_caller,.-frame_pair_caller
.globl alias_overwrite_caller
.type alias_overwrite_caller,@function
alias_overwrite_caller:
    push %rbp
    sub $32, %rsp
    mov %rsp, %rbp
    mov $42, %edi
    call scalar_error
    mov %rax, 8(%rsp)
    mov %rdx, 16(%rsp)
    xor %eax, %eax
    xor %edx, %edx
    movq $123, 16(%rbp)
    mov 8(%rsp), %rcx
    mov 16(%rsp), %rsi
    lea (%rcx,%rsi), %rax
    add $32, %rsp
    pop %rbp
    ret
.size alias_overwrite_caller,.-alias_overwrite_caller
.text
.globl clear_only_caller
.type clear_only_caller,@function
clear_only_caller:
    sub $8, %rsp
    mov $42, %edi
    call scalar_error
    xor %eax, %eax
    xor %edx, %edx
    mov $7, %eax
    add $8, %rsp
    ret
.size clear_only_caller,.-clear_only_caller
.globl partial_overwrite_caller
.type partial_overwrite_caller,@function
partial_overwrite_caller:
    sub $24, %rsp
    mov $42, %edi
    call scalar_error
    mov %rax, 8(%rsp)
    mov %rdx, 16(%rsp)
    xor %eax, %eax
    xor %edx, %edx
    movb $123, 16(%rsp)
    mov 8(%rsp), %rcx
    mov 16(%rsp), %rsi
    lea (%rcx,%rsi), %rax
    add $24, %rsp
    ret
.size partial_overwrite_caller,.-partial_overwrite_caller
