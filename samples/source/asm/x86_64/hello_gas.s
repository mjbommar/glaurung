.section .rodata
.LC0:
    .string "Hello from x86_64 GAS"

.section .text
.globl main
.type main, @function
main:
    push %rbp
    mov %rsp, %rbp
    lea .LC0(%rip), %rdi
    call puts@PLT
    mov $0, %eax
    pop %rbp
    ret

