.globl _start
.section .text
_start:
    la t0, rdv_probe_handler
    csrw mtvec, t0
    csrw medeleg, zero
    csrw mideleg, zero
    li s0, 0          # probe index
    li s1, 0          # missing mask
    csrr t2, 0x747
    addi s0, s0, 1
    csrr t2, 0x3a0
    addi s0, s0, 1
    csrr t2, 0x3a2
    addi s0, s0, 1
    csrr t2, 0x3a4
    addi s0, s0, 1
    csrr t2, 0x3a6
    addi s0, s0, 1
    csrr t2, 0x3a8
    addi s0, s0, 1
    csrr t2, 0x3aa
    addi s0, s0, 1
    csrr t2, 0x3ac
    addi s0, s0, 1
    csrr t2, 0x3ae
    addi s0, s0, 1
    csrr t2, 0x3b0
    addi s0, s0, 1
    csrr t2, 0x3b1
    addi s0, s0, 1
    csrr t2, 0x3b2
    addi s0, s0, 1
    csrr t2, 0x3b3
    addi s0, s0, 1
    csrr t2, 0x3b4
    addi s0, s0, 1
    csrr t2, 0x3b5
    addi s0, s0, 1
    csrr t2, 0x3b6
    addi s0, s0, 1
    csrr t2, 0x3b7
    addi s0, s0, 1
    csrr t2, 0x3b8
    addi s0, s0, 1
    csrr t2, 0x3b9
    addi s0, s0, 1
    csrr t2, 0x3ba
    addi s0, s0, 1
    csrr t2, 0x3bb
    addi s0, s0, 1
    csrr t2, 0x3bc
    addi s0, s0, 1
    csrr t2, 0x3bd
    addi s0, s0, 1
    csrr t2, 0x3be
    addi s0, s0, 1
    csrr t2, 0x3bf
    addi s0, s0, 1
    mv a0, s1
    li t2, 0x5EED0000
    or a0, a0, t2
    slli a0, a0, 1
    ori a0, a0, 1
    la t0, tohost
    sd a0, 0(t0)
1:  j 1b

    .align 2
rdv_probe_handler:
    csrr t2, mcause
    li t3, 2
    bne t2, t3, rdv_probe_other
    li t3, 1
    sll t3, t3, s0
    or s1, s1, t3
    csrr t4, mepc
    addi t4, t4, 4
    csrw mepc, t4
    mret
    .align 2
rdv_probe_other:
    la t0, tohost
    csrr t2, mcause
    li a0, 0xDEAD0000
    slli t3, t2, 8
    or a0, a0, t3
    slli a0, a0, 1
    ori a0, a0, 1
    sd a0, 0(t0)
1:  j 1b

.section .data
    .align 6
    .global tohost
tohost:
    .dword 0
    .global fromhost
fromhost:
    .dword 0
