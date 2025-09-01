default rel

global main
extern puts

section .rodata
msg: db "Hello from x86_64 NASM", 0

section .text
main:
    lea rdi, [rel msg]
    xor eax, eax
    call puts
    xor eax, eax
    ret

