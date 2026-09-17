.syntax unified
.arm
.section .text,"ax",%progbits
.global hang
.type hang,%function
hang:
    b hang
.size hang, .-hang
.global divzero
.type divzero,%function
divzero:
    push {r4, lr}
    bl hang
.size divzero, .-divzero
.section .rodata,"a",%progbits
.balign 4
.global readonly_words
readonly_words:
    .word 0xe2800001, 0xe2800001, 0xe2800001, 0xe12fff1e
