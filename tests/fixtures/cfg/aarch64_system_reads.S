.text
.globl read_nzcv
.type read_nzcv,%function
read_nzcv:
    mrs x0, nzcv
    ret
.size read_nzcv,.-read_nzcv
.globl read_fpcr
.type read_fpcr,%function
read_fpcr:
    mrs x0, fpcr
    ret
.size read_fpcr,.-read_fpcr
.globl read_sp_el0
.type read_sp_el0,%function
read_sp_el0:
    mrs x0, sp_el0
    ret
.size read_sp_el0,.-read_sp_el0
.section .note.GNU-stack,"",%progbits
