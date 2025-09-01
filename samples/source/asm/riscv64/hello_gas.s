.section .rodata
.LC0:
    .string "Hello from RISC-V GAS"

.section .text
.globl main
.type main, @function
main:
    addi sp, sp, -16
    sd ra, 8(sp)
    sd s0, 0(sp)
    addi s0, sp, 16

    la a0, .LC0
    call puts

    li a0, 0
    ld ra, 8(sp)
    ld s0, 0(sp)
    addi sp, sp, 16
    ret

