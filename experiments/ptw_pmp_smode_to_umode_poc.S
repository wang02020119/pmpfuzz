    .option norvc
    .option norelax
    .section .text
    .globl _start

_start:
    la sp, stack_top
    la t0, trap_handler
    csrw mtvec, t0
    csrw medeleg, zero
    csrw mideleg, zero
    csrw satp, zero
    sfence.vma


    li t0, 0x20004dff
    csrw pmpaddr0, t0
    li t0, 0x20003fff
    csrw pmpaddr1, t0
    li t0, 0x1f18
    csrw pmpcfg0, t0

    csrr t0, mstatus
    li t1, ~((3 << 11) | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20))
    and t0, t0, t1
    li t1, (1 << 11)
    or t0, t0, t1
    csrw mstatus, t0
    la t0, s_entry
    csrw mepc, t0
    mret

trap_handler:
    csrr t2, mcause
    csrr t3, mtval
    la t0, result
    sd t2, 0(t0)
    sd t3, 8(t0)
    li t1, 5
    beq t2, t1, pass
    li a0, 0x100
    li t4, 0xff
    and t4, t2, t4
    or a0, a0, t4
    j finish

pass:
    li a0, 1

finish:
    la t0, result
    sd a0, 16(t0)
    la t0, tohost
    sd a0, 0(t0)
1:  j 1b

    .org 0x2000
    .align 3
    .globl result
result:
    .dword 0
    .dword 0
    .dword 0
    .align 6
    .globl tohost
tohost:
    .dword 0
    .globl fromhost
fromhost:
    .dword 0
stack:
    .skip 2048
stack_top:

    .org 0x4000
s_entry:

    la t0, sv39_root_user
    li t1, 0x20004401
    sd t1, 0(t0)
    la t0, sv39_root_target
    li t1, 0x20004c01
    sd t1, 0(t0)
    la t0, sv39_l1_user
    li t1, 0x20004801
    sd t1, 0(t0)
    la t0, sv39_l0_user
    li t1, 0x200014db
    sd t1, 0(t0)

    li t0, 0x8000000000080010
    csrw satp, t0
    sfence.vma
    csrr t0, sstatus
    li t1, ~(1 << 8)
    and t0, t0, t1
    csrw sstatus, t0
    li t0, 0x0
    csrw sepc, t0
    sret

    .org 0x5000
u_entry:
    li t0, 0x40000000
    lw t1, 0(t0)
    li a0, 0x51
    ecall

    .org 0x10000
sv39_root_table:
sv39_root_user:
    .dword 0
sv39_root_target:
    .dword 0
sv39_root_identity:
    .dword 0x200000cf

    .org 0x11000
sv39_l1_user:
    .dword 0

    .org 0x12000
sv39_l0_user:
    .dword 0

    .org 0x13000
denied_l1_table:
    .dword 0
