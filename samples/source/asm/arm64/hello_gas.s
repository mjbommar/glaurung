.section .rodata
msg:
    .asciz "Hello from AArch64 GAS"

.section .text
.global main
.type main, %function
main:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    adr x0, msg
    bl puts
    mov w0, 0
    ldp x29, x30, [sp], 16
    ret

