.globl _start
.section .text
_start:



    li t1, 0x20000800
    csrw pmpaddr0, t1
    li t1, 0x200017FF
    csrw pmpaddr1, t1
    li t1, 0x000000000000180F
    csrw pmpcfg0, t1

    csrr t4, pmpcfg0
    csrr t5, pmpaddr1
init:


    csrr t1, mstatus
    li t2, -4097
    and t1, t1, t2
    li t2, 0x800
    or t1, t1, t2
    csrw mstatus, t1
    la t1, s_probe
    csrw mepc, t1
    mret
s_probe:

    li t2, 0x80004000
    li t3, 0x12345678
    sw t3, 0(t2)
1:  j 1b
