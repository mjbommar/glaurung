default rel

global main
extern puts

section .rdata
msg db "Hello from Win64 NASM", 0

section .text
main:
    lea rcx, [rel msg]
    xor eax, eax
    call puts
    xor eax, eax
    ret

