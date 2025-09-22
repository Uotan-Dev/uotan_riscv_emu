# Copyright 2025 Nuo Shen, Nanjing University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#define concat_temp(x, y) x ## y
#define concat(x, y) concat_temp(x, y)
#define MAP(c, f) c(f)

#if __riscv_xlen == 32
#define LOAD  lw
#define STORE sw
#define XLEN  4
#else
#define LOAD  ld
#define STORE sd
#define XLEN  8
#endif

#define REGS_LO16(f) \
      f( 1)       f( 3) f( 4) f( 5) f( 6) f( 7) f( 8) f( 9) \
f(10) f(11) f(12) f(13) f(14) f(15)
#ifndef __riscv_e
#define REGS_HI16(f) \
                                    f(16) f(17) f(18) f(19) \
f(20) f(21) f(22) f(23) f(24) f(25) f(26) f(27) f(28) f(29) \
f(30) f(31)
#define NR_REGS 32
#else
#define REGS_HI16(f)
#define NR_REGS 16
#endif

#define REGS(f) REGS_LO16(f) REGS_HI16(f)

#define PUSH(n) STORE concat(x, n), (n * XLEN)(sp);
#define POP(n)  LOAD  concat(x, n), (n * XLEN)(sp);

#define CONTEXT_SIZE  ((NR_REGS + 3) * XLEN)
#define OFFSET_SP     ( 2 * XLEN)
#define OFFSET_CAUSE  ((NR_REGS + 0) * XLEN)
#define OFFSET_STATUS ((NR_REGS + 1) * XLEN)
#define OFFSET_EPC    ((NR_REGS + 2) * XLEN)

    .section .text
    .align  3
    .global _start
    .global trap
    .extern main

_start:
    mv s0, zero
    la sp, __stack_top
    call main
    li a0, -2
    ebreak

    .align 3
trap:
    // turn of intr
    csrci mstatus, (1 << 3)

    addi sp, sp, -CONTEXT_SIZE
    MAP(REGS, PUSH)

    csrr t0, mcause

    // is it an interrupt?
    srli t1, t0, 63
    beqz t1, .no_timer

    // get exception code
    li t2, 7
    andi t0, t0, 0xff
    bne t0, t2, .no_timer

    csrr t0, mepc
    addi t0, t0, 4
    csrw mepc, t0

    # andi t0, sp, -16
    # mv sp, t0
    call __cust_trap_handler

    li t2, (1 << 7)
    csrc mie, t2

.no_timer:
    MAP(REGS, POP)
    addi sp, sp, CONTEXT_SIZE
    mret
