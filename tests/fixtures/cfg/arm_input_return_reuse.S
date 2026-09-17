.syntax unified
.arm
.text
.globl entry
.type entry,%function
entry:
    cmp r0, #0
    beq .Lnull
    push {r4, lr}
    mov r4, r0
    ldrb r0, [r4]
    bl helper
    pop {r4, pc}
.Lnull:
    bx lr
.size entry,.-entry
.type helper,%function
helper:
    add r0, r0, #1
    bx lr
.size helper,.-helper
