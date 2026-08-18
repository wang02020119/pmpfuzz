.globl _start
.section .text
_start:
    # hand-known PMP config (correct encodings)
    # entry0: TOR @0x80002000, RWX=1 (0x0F)  -> allows [0, 0x80002000)
    # entry1: NAPOT base=0x80004000 size=0x4000, RWX=0 (0x18) -> denies window
    li t1, 0x20000800
    csrw pmpaddr0, t1
    li t1, 0x200017FF
    csrw pmpaddr1, t1
    li t1, 0x000000000000180F
    csrw pmpcfg0, t1
    # readback check (M-mode)
    csrr t4, pmpcfg0
    csrr t5, pmpaddr1
init:
    # (splicer prologue injected here: mtvec -> rdv_trap_handler)
    # switch to S-mode and probe the denied window
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
    # S-mode store to 0x80004000 -> entry1 denies -> trap to M-mode handler
    li t2, 0x80004000
    li t3, 0x12345678
    sw t3, 0(t2)
1:  j 1b
