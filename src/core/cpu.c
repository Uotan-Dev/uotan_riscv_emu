/*
 * Copyright 2025 Nuo Shen, Nanjing University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core/cpu.h"
#include "core/decode.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "device/clint.h"
#include "device/goldfish_rtc.h"
#include "device/uart16550.h"
#include "ui/ui.h"
#include "utils/alarm.h"
#include "utils/logger.h"
#include "utils/slowtimer.h"

void cpu_raise_exception(exception_t cause, uint64_t tval) {
    assert(((uint64_t)cause & INTERRUPT_FLAG) == 0);

    privilege_level_t priv = rv.privilege;
    if (((rv.MEDELEG >> cause) & 1) && (priv == PRIV_U || priv == PRIV_S)) {
        // Shift to S mode
        rv.privilege = PRIV_S;

        rv.decode.npc = cpu_read_csr(CSR_STVEC) & ~3ULL;
        cpu_write_csr(CSR_SEPC, rv.decode.pc);
        cpu_write_csr(CSR_SCAUSE, cause);
        cpu_write_csr(CSR_STVAL, tval);

        uint64_t sstatus = cpu_read_csr(CSR_SSTATUS);
        // Save current SIE to SPIE
        if (sstatus & SSTATUS_SIE)
            sstatus |= SSTATUS_SPIE;
        else
            sstatus &= ~SSTATUS_SPIE;
        // Save PRIV level to SPP
        sstatus &= ~SSTATUS_SPP;
        sstatus |= ((uint64_t)priv << SSTATUS_SPP_SHIFT);
        // Disable S mode interrupt
        sstatus &= ~SSTATUS_SIE;
        // Update
        cpu_write_csr(CSR_SSTATUS, sstatus);
    } else {
        // Shift to M Mode
        rv.privilege = PRIV_M;

        rv.decode.npc = cpu_read_csr(CSR_MTVEC) & ~3ULL;
        cpu_write_csr(CSR_MEPC, rv.decode.pc);
        cpu_write_csr(CSR_MCAUSE, cause);
        cpu_write_csr(CSR_MTVAL, tval);

        uint64_t mstatus = cpu_read_csr(CSR_MSTATUS);
        // Save current MIE to MPIE
        if (mstatus & MSTATUS_MIE)
            mstatus |= MSTATUS_MPIE;
        else
            mstatus &= ~MSTATUS_MPIE;
        // Save PRIV level to MPP
        mstatus &= ~MSTATUS_MPP;
        mstatus |= ((uint64_t)priv << MSTATUS_MPP_SHIFT);
        // Disable M mode interrupt
        mstatus &= ~MSTATUS_MIE;
        // Update
        cpu_write_csr(CSR_MSTATUS, mstatus);
    }

    rv.last_exception = cause;
}

void cpu_raise_intr(uint64_t ip, privilege_level_t priv) {
    pthread_mutex_lock(&rv.csr_lock);
    if (priv == PRIV_M)
        rv.MIP |= ip;
    else if (PRIV_S)
        rv.MIP |= ip & rv.MIDELEG;
    else
        __UNREACHABLE;
    pthread_mutex_unlock(&rv.csr_lock);
}

void cpu_clear_intr(uint64_t ip, privilege_level_t priv) {
    pthread_mutex_lock(&rv.csr_lock);
    if (priv == PRIV_M)
        rv.MIP &= ~ip;
    else if (priv == PRIV_S)
        rv.MIP &= ~(rv.MIDELEG & ip);
    else
        __UNREACHABLE;
    pthread_mutex_unlock(&rv.csr_lock);
}

/**
 * @brief Processes an interruption.
 *
 * This function should only be used during instruction execution.
 *
 * @param intr  The interruption number.
 */
FORCE_INLINE void cpu_process_intr(interrupt_t intr) {
    assert((uint64_t)intr & INTERRUPT_FLAG);

    privilege_level_t priv = rv.privilege;
    uint64_t cause = (uint64_t)intr & ~INTERRUPT_FLAG;
    bool mideleg_flag = (cpu_read_csr(CSR_MIDELEG) >> cause) & 1;

    if (cause == CAUSE_MACHINE_TIMER)
        mideleg_flag = false;

    if (mideleg_flag && (priv == PRIV_U || priv == PRIV_S)) {
        rv.privilege = PRIV_S;
        uint64_t vt_offset = 0;
        uint64_t stvec = cpu_read_csr(CSR_STVEC);
        if (stvec & 1)
            vt_offset = cause << 2;
        cpu_write_csr(CSR_SEPC, rv.PC);
        rv.PC = (stvec & ~3ULL) + vt_offset;
        cpu_write_csr(CSR_SCAUSE, intr);

        uint64_t sstatus = cpu_read_csr(CSR_SSTATUS);
        if (sstatus & SSTATUS_SIE)
            sstatus |= SSTATUS_SPIE;
        else
            sstatus &= ~SSTATUS_SPIE;
        sstatus &= ~SSTATUS_SIE;
        sstatus &= ~SSTATUS_SPP;
        sstatus |= ((uint64_t)priv << SSTATUS_SPP_SHIFT);
        cpu_write_csr(CSR_SSTATUS, sstatus);
    } else {
        rv.privilege = PRIV_M;
        uint64_t vt_offset = 0;
        uint64_t mtvec = cpu_read_csr(CSR_MTVEC);
        if (mtvec & 1)
            vt_offset = cause << 2;
        cpu_write_csr(CSR_MEPC, rv.PC);
        rv.PC = (mtvec & ~3ULL) + vt_offset;
        cpu_write_csr(CSR_MCAUSE, intr);

        uint64_t mstatus = cpu_read_csr(CSR_MSTATUS);
        if (mstatus & MSTATUS_MIE)
            mstatus |= MSTATUS_MPIE;
        else
            mstatus &= ~MSTATUS_MPIE;
        mstatus &= ~MSTATUS_MIE;
        mstatus &= ~MSTATUS_MPP;
        mstatus |= ((uint64_t)priv << MSTATUS_MPP_SHIFT);
        cpu_write_csr(CSR_MSTATUS, mstatus);
    }
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/**
 * The decoding algorithm is taken from NJU emulator
 * Keeping the original license here
 */

/***************************************************************************************
 * Copyright (c) 2014-2024 Zihao Yu, Nanjing University
 *
 * NEMU is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 *PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 * See the Mulan PSL v2 for more details.
 ***************************************************************************************/

#define R(i) rv.X[i]

// clang-format off
typedef enum {
    TYPE_I, TYPE_U, TYPE_S,
    TYPE_J, TYPE_R, TYPE_B,
    TYPE_N, // none
} inst_type_t;

#define src1R() do { *src1 = R(rs1); } while (0)
#define src2R() do { *src2 = R(rs2); } while (0)
// clang-format on

#define immI()                                                                 \
    do {                                                                       \
        *imm = SEXT(BITS(i, 31, 20), 12);                                      \
    } while (0)
#define immU()                                                                 \
    do {                                                                       \
        *imm = SEXT(BITS(i, 31, 12), 20) << 12;                                \
    } while (0)
#define immS()                                                                 \
    do {                                                                       \
        *imm = (SEXT(BITS(i, 31, 25), 7) << 5) | BITS(i, 11, 7);               \
    } while (0)
#define immJ()                                                                 \
    do {                                                                       \
        *imm = SEXT(BITS(i, 31, 31) << 20 | BITS(i, 19, 12) << 12 |            \
                        BITS(i, 20, 20) << 11 | BITS(i, 30, 21) << 1,          \
                    21);                                                       \
    } while (0)
#define immB()                                                                 \
    do {                                                                       \
        *imm = SEXT(BITS(i, 31, 31) << 12 | BITS(i, 7, 7) << 11 |              \
                        BITS(i, 30, 25) << 5 | BITS(i, 11, 8) << 1,            \
                    13);                                                       \
    } while (0)

FORCE_INLINE void decode_operand(Decode *s, int *rd, uint64_t *src1,
                                 uint64_t *src2, uint64_t *imm,
                                 inst_type_t type) {
    // clang-format off
    uint32_t i = s->inst;
    int rs1 = BITS(i, 19, 15);
    int rs2 = BITS(i, 24, 20);
    *rd     = BITS(i, 11, 7);
    switch (type) {
        case TYPE_I: src1R();          immI(); break;
        case TYPE_U:                   immU(); break;
        case TYPE_S: src1R(); src2R(); immS(); break;
        case TYPE_N:                           break;
        case TYPE_J:                   immJ(); break;
        case TYPE_R: src1R(); src2R();         break;
        case TYPE_B: src1R(); src2R(); immB(); break;
        default: __UNREACHABLE;
    }
    // clang-format on
}

FORCE_INLINE void _ecall(Decode *s) {
    switch (rv.privilege) {
        case PRIV_M: cpu_raise_exception(CAUSE_MACHINE_ECALL, s->pc); break;
        case PRIV_S: cpu_raise_exception(CAUSE_SUPERVISOR_ECALL, s->pc); break;
        case PRIV_U: cpu_raise_exception(CAUSE_USER_ECALL, s->pc); break;
        default: __UNREACHABLE;
    }
}

FORCE_INLINE void _mret(Decode *s) {
    if (rv.privilege != PRIV_M) {
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
        return;
    }
    s->npc = cpu_read_csr(CSR_MEPC);
    uint64_t mstatus = cpu_read_csr(CSR_MSTATUS);

    // Restore PRIV level
    rv.privilege =
        (privilege_level_t)((mstatus & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT);

    if (rv.privilege != PRIV_M)
        mstatus &= ~MSTATUS_MPRV;

    // Restore MIE
    if (mstatus & MSTATUS_MPIE)
        mstatus |= MSTATUS_MIE;
    else
        mstatus &= ~MSTATUS_MIE;

    mstatus |= MSTATUS_MPIE;

    mstatus &= ~MSTATUS_MPP;

    cpu_write_csr(CSR_MSTATUS, mstatus);
}

FORCE_INLINE void _sret(Decode *s) {
    // When TSR=1, this operation is not permitted in S-mode
    if ((rv.privilege == PRIV_S && (rv.MSTATUS & MSTATUS_TSR)) ||
        rv.privilege == PRIV_U) {
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
        return;
    }
    s->npc = cpu_read_csr(CSR_SEPC);
    uint64_t sstatus = cpu_read_csr(CSR_SSTATUS);
    rv.privilege =
        (privilege_level_t)((sstatus & SSTATUS_SPP) >> SSTATUS_SPP_SHIFT);

    // Looks weird, but this is what the riscv spec requires
    if (rv.privilege != PRIV_M)
        cpu_write_csr(CSR_MSTATUS, cpu_read_csr(CSR_MSTATUS) & ~MSTATUS_MPRV);

    if (sstatus & SSTATUS_SPIE)
        sstatus |= SSTATUS_SIE;
    else
        sstatus &= ~SSTATUS_SIE;

    sstatus |= SSTATUS_SPIE;

    sstatus &= ~SSTATUS_SPP;

    cpu_write_csr(CSR_SSTATUS, sstatus);
}

FORCE_INLINE void _sfence_vma(Decode *s) {
    // TODO: TLB
    ;
}

#define LOAD(rd, addr, type, sz_type, sz)                                      \
    do {                                                                       \
        type __v = vaddr_read_##sz_type(addr);                                 \
        if (rv.last_exception == CAUSE_EXCEPTION_NONE) {                       \
            R(rd) = (uint64_t)__v;                                             \
        }                                                                      \
    } while (0)

#define LOAD_SEXT(rd, addr, type, sz_type, sz)                                 \
    do {                                                                       \
        type __v = vaddr_read_##sz_type(addr);                                 \
        if (rv.last_exception == CAUSE_EXCEPTION_NONE) {                       \
            R(rd) = SEXT(__v, sz);                                             \
        }                                                                      \
    } while (0)

#define CSR_CHECK_PERM(csr)                                                    \
    do {                                                                       \
        if (((((csr) >> 8) & 0x3) == 3 && rv.privilege < PRIV_M) ||            \
            ((((csr) >> 8) & 0x3) == 1 && rv.privilege < PRIV_S))              \
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);      \
    } while (0)

static inline void decode_exec(Decode *s) {
    // FIXME: function ‘decode_exec’ can never be inlined because it contains a
    // computed goto

#define INSTPAT_INST(s) ((s)->inst)

#define INSTPAT_MATCH(s, name, type, ... /* execute body */)                   \
    {                                                                          \
        int rd = 0;                                                            \
        uint64_t src1 = 0, src2 = 0, imm = 0;                                  \
        decode_operand(s, &rd, &src1, &src2, &imm, concat(TYPE_, type));       \
        __VA_ARGS__;                                                           \
    }

    // clang-format off
    INSTPAT_START();

    // RV64I instructions
    INSTPAT("0000000 ????? ????? 000 ????? 01100 11", add    , R, R(rd) = src1 + src2);
    INSTPAT("??????? ????? ????? 000 ????? 00100 11", addi   , I, R(rd) = src1 + imm);
    INSTPAT("??????? ????? ????? 000 ????? 00110 11", addiw  , I, R(rd) = SEXT(BITS(src1 + imm, 31, 0), 32));
    INSTPAT("0000000 ????? ????? 000 ????? 01110 11", addw   , R, R(rd) = SEXT(BITS(src1 + src2, 31, 0), 32));
    INSTPAT("0000000 ????? ????? 111 ????? 01100 11", and    , R, R(rd) = src1 & src2);
    INSTPAT("??????? ????? ????? 111 ????? 00100 11", andi   , I, R(rd) = src1 & imm);
    INSTPAT("??????? ????? ????? ??? ????? 00101 11", auipc  , U, R(rd) = s->pc + imm);
    INSTPAT("??????? ????? ????? 000 ????? 11000 11", beq    , B, if (src1 == src2) s->npc = s->pc + imm;);
    INSTPAT("??????? ????? ????? 101 ????? 11000 11", bge    , B, if ((int64_t)src1 >= (int64_t)src2) s->npc = s->pc + imm;);
    INSTPAT("??????? ????? ????? 111 ????? 11000 11", bgeu   , B, if (src1 >= src2) s->npc = s->pc + imm;);
    INSTPAT("??????? ????? ????? 100 ????? 11000 11", blt    , B, if ((int64_t)src1 < (int64_t)src2) s->npc = s->pc + imm;);
    INSTPAT("??????? ????? ????? 110 ????? 11000 11", bltu   , B, if (src1 < src2) s->npc = s->pc + imm;);
    INSTPAT("??????? ????? ????? 001 ????? 11000 11", bne    , B, if (src1 != src2) s->npc = s->pc + imm;);
    INSTPAT("0000??? ????? 00000 000 00000 00011 11", fence  , I, /* nop */);
    INSTPAT("0000000 00000 00000 001 00000 00011 11", fence.i, I, /* nop */);
    INSTPAT("??????? ????? ????? ??? ????? 11011 11", jal    , J, R(rd) = s->pc + 4; s->npc = s->pc + imm;);
    INSTPAT("??????? ????? ????? 000 ????? 11001 11", jalr   , I, uint64_t t = s->pc + 4; s->npc = (src1 + imm) & ~1ULL; R(rd) = t;);
    INSTPAT("??????? ????? ????? 000 ????? 00000 11", lb     , I, LOAD_SEXT(rd, src1 + imm, uint8_t, b, 8));
    INSTPAT("??????? ????? ????? 100 ????? 00000 11", lbu    , I, LOAD(rd, src1 + imm, uint8_t, b, 8));
    INSTPAT("??????? ????? ????? 011 ????? 00000 11", ld     , I, LOAD(rd, src1 + imm, uint64_t, d, 64));
    INSTPAT("??????? ????? ????? 001 ????? 00000 11", lh     , I, LOAD_SEXT(rd, src1 + imm, uint16_t, s, 16));
    INSTPAT("??????? ????? ????? 101 ????? 00000 11", lhu    , I, LOAD(rd, src1 + imm, uint16_t, s, 16));
    INSTPAT("??????? ????? ????? ??? ????? 01101 11", lui    , U, R(rd) = SEXT(BITS(imm, 31, 12) << 12, 32));
    INSTPAT("??????? ????? ????? 010 ????? 00000 11", lw     , I, LOAD_SEXT(rd, src1 + imm, uint32_t, w, 32));
    INSTPAT("??????? ????? ????? 110 ????? 00000 11", lwu    , I, LOAD(rd, src1 + imm, uint32_t, w, 32));
    INSTPAT("0000000 ????? ????? 110 ????? 01100 11", or     , R, R(rd) = src1 | src2);
    INSTPAT("??????? ????? ????? 110 ????? 00100 11", ori    , I, R(rd) = src1 | imm);
    INSTPAT("??????? ????? ????? 000 ????? 01000 11", sb     , S, vaddr_write_b(src1 + imm, src2));
    INSTPAT("??????? ????? ????? 011 ????? 01000 11", sd     , S, vaddr_write_d(src1 + imm, src2));
    INSTPAT("??????? ????? ????? 001 ????? 01000 11", sh     , S, vaddr_write_s(src1 + imm, src2));
    INSTPAT("0000000 ????? ????? 001 ????? 01100 11", sll    , R, R(rd) = src1 << BITS(src2, 5, 0));
    INSTPAT("000000? ????? ????? 001 ????? 00100 11", slli   , I, R(rd) = src1 << BITS(imm, 5, 0));
    INSTPAT("0000000 ????? ????? 001 ????? 00110 11", slliw  , I, R(rd) = SEXT(BITS(src1, 31, 0) << BITS(imm, 4, 0), 32));
    INSTPAT("0000000 ????? ????? 001 ????? 01110 11", sllw   , R, R(rd) = SEXT((uint32_t)BITS(src1, 31, 0) << (BITS(src2, 4, 0)), 32));
    INSTPAT("0000000 ????? ????? 010 ????? 01100 11", slt    , R, R(rd) = (int64_t)src1 < (int64_t)src2);
    INSTPAT("??????? ????? ????? 010 ????? 00100 11", slti   , I, R(rd) = (int64_t)src1 < (int64_t)imm);
    INSTPAT("??????? ????? ????? 011 ????? 00100 11", sltiu  , I, R(rd) = src1 < imm);
    INSTPAT("0000000 ????? ????? 011 ????? 01100 11", sltu   , R, R(rd) = src1 < src2);
    INSTPAT("0100000 ????? ????? 101 ????? 01100 11", sra    , R, R(rd) = (int64_t)src1 >> BITS(src2, 5, 0));
    INSTPAT("010000? ????? ????? 101 ????? 00100 11", srai   , I, R(rd) = (int64_t)src1 >> BITS(imm, 5, 0));
    INSTPAT("0100000 ????? ????? 101 ????? 00110 11", sraiw  , I, R(rd) = SEXT((int32_t)(BITS(src1, 31, 0)) >> BITS(imm, 4, 0), 32));
    INSTPAT("0100000 ????? ????? 101 ????? 01110 11", sraw   , R, R(rd) = SEXT((int32_t)(BITS(src1, 31, 0)) >> BITS(src2, 4, 0), 32));
    INSTPAT("0000000 ????? ????? 101 ????? 01100 11", srl    , R, R(rd) = src1 >> BITS(src2, 5, 0));
    INSTPAT("000000? ????? ????? 101 ????? 00100 11", srli   , I, R(rd) = src1 >> BITS(imm, 5, 0));
    INSTPAT("0000000 ????? ????? 101 ????? 00110 11", srliw  , I, R(rd) = SEXT(BITS(src1, 31, 0) >> BITS(imm, 4, 0), 32));
    INSTPAT("0000000 ????? ????? 101 ????? 01110 11", srlw   , R, R(rd) = SEXT(BITS(src1, 31, 0) >> BITS(src2, 4, 0), 32));
    INSTPAT("0100000 ????? ????? 000 ????? 01100 11", sub    , R, R(rd) = src1 - src2);
    INSTPAT("0100000 ????? ????? 000 ????? 01110 11", subw   , R, R(rd) = SEXT(BITS(src1 - src2, 31, 0), 32));
    INSTPAT("??????? ????? ????? 010 ????? 01000 11", sw     , S, vaddr_write_w(src1 + imm, BITS(src2, 31, 0)));
    INSTPAT("0000000 ????? ????? 100 ????? 01100 11", xor    , R, R(rd) = src1 ^ src2);
    INSTPAT("??????? ????? ????? 100 ????? 00100 11", xori   , I, R(rd) = src1 ^ imm);
    INSTPAT("??????? ????? ????? 011 ????? 11100 11", csrrc   ,I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                cpu_write_csr(imm, t & ~src1);
                if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                    R(rd) = t;
            }
        }
    );
    INSTPAT("??????? ????? ????? 111 ????? 11100 11", csrrci  ,I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t zimm = BITS(s->inst, 19, 15);
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                cpu_write_csr(imm, t & ~zimm);
                if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                    R(rd) = t;
            }
        }
    );
    INSTPAT("??????? ????? ????? 010 ????? 11100 11", csrrs  , I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                cpu_write_csr(imm, t | src1);
                if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                    R(rd) = t;
            }
        }
    );
    INSTPAT("??????? ????? ????? 110 ????? 11100 11", csrrsi , I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t zimm = BITS(s->inst, 19, 15);
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                cpu_write_csr(imm, t | zimm);
                if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                    R(rd) = t;
            }
        }
    );
    INSTPAT("??????? ????? ????? 001 ????? 11100 11", csrrw  , I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                cpu_write_csr(imm, src1);
                if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                    R(rd) = t;
            }
        }
    );
    INSTPAT("??????? ????? ????? 101 ????? 11100 11", csrrwi , I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t zimm = BITS(s->inst, 19, 15);
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                R(rd) = t;
                cpu_write_csr(imm, zimm);
            }
        }
    );
    INSTPAT("0000000 00001 00000 000 00000 11100 11", ebreak     , N, cpu_raise_exception(CAUSE_BREAKPOINT, s->pc));
    INSTPAT("0000000 00000 00000 000 00000 11100 11", ecall      , N, _ecall(s));
    INSTPAT("0011000 00010 00000 000 00000 11100 11", mret       , N, _mret(s));
    INSTPAT("0001001 ????? ????? 000 00000 11100 11", sfence.vma , R, _sfence_vma(s));
    INSTPAT("0001000 00010 00000 000 00000 11100 11", sret       , N, _sret(s));
    INSTPAT("0001000 00101 00000 000 00000 11100 11", wfi        , N, /* nop */);

    // RV64M instructions
    INSTPAT("0000001 ????? ????? 100 ????? 01100 11", div    , R,
        if (unlikely((int64_t)src2 == 0))
            R(rd) = ~0ULL;
        else if (unlikely((int64_t)src1 == INT64_MIN && (int64_t)src2 == -1))
            R(rd) = (int64_t)src1;
        else
            R(rd) = (int64_t)src1 / (int64_t)src2;
    );
    INSTPAT("0000001 ????? ????? 101 ????? 01100 11", divu   , R,
        if (unlikely(src2 == 0))
            R(rd) = ~0ULL;
        else
            R(rd) = src1 / src2;
    );
    INSTPAT("0000001 ????? ????? 101 ????? 01110 11", divuw  , R,
        uint32_t v1 = BITS(src1, 31, 0);
        uint32_t v2 = BITS(src2, 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = ~0ULL;
        else
            R(rd) = SEXT(v1 / v2, 32);
    );
    INSTPAT("0000001 ????? ????? 100 ????? 01110 11", divw   , R,
        int32_t v1 = (int32_t)BITS(src1, 31, 0);
        int32_t v2 = (int32_t)BITS(src2, 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = ~0ULL;
        else if (unlikely(v1 == INT32_MIN && v2 == -1))
            R(rd) = SEXT(v1, 32);
        else
            R(rd) = SEXT(v1 / v2, 32);
    );
    INSTPAT("0000001 ????? ????? 000 ????? 01100 11", mul    , R, R(rd) = src1 * src2);
    INSTPAT("0000001 ????? ????? 001 ????? 01100 11", mulh   , R, 
        R(rd) = (int64_t)(((__int128_t)(int64_t)src1 * (__int128_t)(int64_t)src2) >> 64)
    );
    INSTPAT("0000001 ????? ????? 010 ????? 01100 11", mulhsu , R, 
        R(rd) = (int64_t)(((__int128_t)(int64_t)src1 * (__uint128_t)src2) >> 64)
    );
    INSTPAT("0000001 ????? ????? 011 ????? 01100 11", mulhu  , R,
        R(rd) = (uint64_t)((__uint128_t)src1 * (__uint128_t)src2 >> 64)
    );
    INSTPAT("0000001 ????? ????? 000 ????? 01110 11", mulw   , R, R(rd) = SEXT(BITS(src1 * src2, 31, 0), 32));
    INSTPAT("0000001 ????? ????? 110 ????? 01100 11", rem    , R,
        if (unlikely((int64_t)src2 == 0))
            R(rd) = (int64_t)src1;
        else if (unlikely((int64_t)src1 == INT64_MIN && (int64_t)src2 == -1))
            R(rd) = 0;  // overflow case: remainder is 0
        else
            R(rd) = (int64_t)src1 % (int64_t)src2;
    );
    INSTPAT("0000001 ????? ????? 111 ????? 01100 11", remu   , R,
        if (unlikely(src2 == 0))
            R(rd) = src1;
        else
            R(rd) = src1 % src2;
    );
    INSTPAT("0000001 ????? ????? 111 ????? 01110 11", remuw  , R, 
        uint32_t v1 = BITS(src1, 31, 0);
        uint32_t v2 = BITS(src2, 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = SEXT(v1, 32);
        else
            R(rd) = SEXT(v1 % v2, 32);
    );
    INSTPAT("0000001 ????? ????? 110 ????? 01110 11", remw   , R, 
        int32_t v1 = (int32_t)BITS(src1, 31, 0);
        int32_t v2 = (int32_t)BITS(src2, 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = SEXT(v1, 32);
        else if (unlikely(v1 == INT32_MIN && v2 == -1))
            R(rd) = 0;
        else
            R(rd) = SEXT(v1 % v2, 32);
    );

    // RV64A instructions
    INSTPAT("00010?? 00000 ????? 011 ????? 01011 11", lr.d   , R,
        uint64_t v = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = v;
            rv.reservation_address = src1;
            rv.reservation_valid = true;
        }
    );
    INSTPAT("00010?? 00000 ????? 010 ????? 01011 11", lr.w   , R,
        uint32_t v = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = SEXT(v, 32);
            rv.reservation_address = src1;
            rv.reservation_valid = true;
        }
    );
    INSTPAT("00011?? ????? ????? 011 ????? 01011 11", sc.d   , R,
        if (rv.reservation_valid && rv.reservation_address == src1) {
            vaddr_write_d(src1, src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = 0;
            else
                R(rd) = 1;
        } else {
            R(rd) = 1;
        }
        rv.reservation_valid = false;
    );
    INSTPAT("00011?? ????? ????? 010 ????? 01011 11", sc.w   , R,
        if (rv.reservation_valid && rv.reservation_address == src1) {
            vaddr_write_w(src1, src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = 0;
            else
                R(rd) = 1;
        } else {
            R(rd) = 1;
        }
        rv.reservation_valid = false;
    );
    INSTPAT("00000?? ????? ????? 011 ????? 01011 11", amoadd.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, (int64_t)t + (int64_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("00000?? ????? ????? 010 ????? 01011 11", amoadd.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, (int32_t)t + (int32_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("01100?? ????? ????? 011 ????? 01011 11", amoand.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, (int64_t)t & (int64_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("01100?? ????? ????? 010 ????? 01011 11", amoand.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, (int32_t)t & (int32_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("01000?? ????? ????? 011 ????? 01011 11", amoor.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, (int64_t)t | (int64_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("01000?? ????? ????? 010 ????? 01011 11", amoor.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, (int32_t)t | (int32_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("00100?? ????? ????? 011 ????? 01011 11", amoxor.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, (int64_t)t ^ (int64_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("00100?? ????? ????? 010 ????? 01011 11", amoxor.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, (int32_t)t ^ (int32_t)src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("10100?? ????? ????? 011 ????? 01011 11", amomax.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, MAX((int64_t)t, (int64_t)src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("10100?? ????? ????? 010 ????? 01011 11", amomax.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, MAX((int32_t)t, (int32_t)src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("11100?? ????? ????? 011 ????? 01011 11", amomaxu.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, MAX(t, src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("11100?? ????? ????? 010 ????? 01011 11", amomaxu.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, MAX((uint32_t)t, (uint32_t)src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("10000?? ????? ????? 011 ????? 01011 11", amomin.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, MIN((int64_t)t, (int64_t)src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("10000?? ????? ????? 010 ????? 01011 11", amomin.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, MIN((int32_t)t, (int32_t)src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("11000?? ????? ????? 011 ????? 01011 11", amominu.d , R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, MIN(t, src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("11000?? ????? ????? 010 ????? 01011 11", amominu.w , R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, MIN((uint32_t)t, (uint32_t)src2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("00001?? ????? ????? 011 ????? 01011 11", amoswap.d, R,
        uint64_t t = vaddr_read_d(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(src1, src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("00001?? ????? ????? 010 ????? 01011 11", amoswap.w, R,
        uint32_t t = vaddr_read_w(src1);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(src1, src2);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );

    // Invalid insturctions
    INSTPAT("??????? ????? ????? ??? ????? ????? ??", inv    , N, cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst));
    INSTPAT_END();
    // clang-format on

    R(0) = 0; // reset $zero to 0
}

FORCE_INLINE void cpu_exec_once(Decode *s, uint64_t pc) {
    s->pc = pc;
    s->npc = pc + 4;
    s->inst = vaddr_ifetch(pc);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        decode_exec(s);
    rv.PC = s->npc;
    rv.MCYCLE++;
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE &&
               !rv.suppress_minstret_increase))
        rv.MINSTRET++;
    rv.suppress_minstret_increase = false;
}

static pthread_t cpu_thread;
static pthread_mutex_t cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cpu_cond = PTHREAD_COND_INITIALIZER;
static bool cpu_thread_running = false;

/* Child CPU thread */
static void *cpu_thread_func(void *arg) {
    // Notify the main thread that the child thread has started
    pthread_mutex_lock(&cpu_mutex);
    cpu_thread_running = true;
    pthread_cond_broadcast(&cpu_cond);
    pthread_mutex_unlock(&cpu_mutex);

    uint64_t start = slowtimer_get_microseconds();
    uint64_t inst_cnt = 0;

    for (uint64_t i = 0; i < UINT64_MAX; i++) {
        if (unlikely(rv.shutdown))
            break;
        rv.last_exception = CAUSE_EXCEPTION_NONE;
        if ((i & 255) == 0) {
            interrupt_t intr = rv_get_pending_interrupt();
            if (unlikely(intr != CAUSE_INTERRUPT_NONE))
                cpu_process_intr(intr);
        }
        cpu_exec_once(&rv.decode, rv.PC);
        inst_cnt++;
    }

    uint64_t end = slowtimer_get_microseconds();
    double delta = (double)(end - start) / 1000000.0;
    log_info("Simulation time: %f seconds (%" PRIu64 " microseconds)", delta,
             end - start);
    log_info("Simulation speed: %f insts per second", inst_cnt / delta);

    sleep(1);

    // Notify the main thread again
    pthread_mutex_lock(&cpu_mutex);
    cpu_thread_running = false;
    pthread_cond_broadcast(&cpu_cond);
    pthread_mutex_unlock(&cpu_mutex);

    return NULL;
}

static inline void cpu_thread_start() {
    pthread_mutex_lock(&cpu_mutex);
    if (cpu_thread_running) {
        log_warn("CPU thread already running");
        pthread_mutex_unlock(&cpu_mutex);
        return;
    }

    if (pthread_create(&cpu_thread, NULL, cpu_thread_func, NULL) != 0) {
        pthread_mutex_unlock(&cpu_mutex);
        log_error("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    while (!cpu_thread_running)
        pthread_cond_wait(&cpu_cond, &cpu_mutex);
    pthread_mutex_unlock(&cpu_mutex);
}

void cpu_start() {
    alarm_turn(true);
    cpu_thread_start();

    while (true) {
        pthread_mutex_lock(&cpu_mutex);
        bool running = cpu_thread_running;
        pthread_mutex_unlock(&cpu_mutex);

        if (!running)
            break;

        // Update UI and framebuffer
        ui_update();
        // Update clint
        clint_tick();
        // Update UART
        uart_tick();
        // Update RTC
        rtc_tick();
    }

    alarm_turn(false);
    pthread_join(cpu_thread, NULL);
}

#define CPU_EXEC_COMMON()                                                      \
    do {                                                                       \
        rv.last_exception = CAUSE_EXCEPTION_NONE;                              \
        interrupt_t intr = rv_get_pending_interrupt();                         \
        if (unlikely(intr != CAUSE_INTERRUPT_NONE))                            \
            cpu_process_intr(intr);                                            \
        cpu_exec_once(&rv.decode, rv.PC);                                      \
    } while (0)

void cpu_step() {
    alarm_turn(true);
    if (!unlikely(rv.shutdown)) {
        clint_tick();
        uart_tick();
        CPU_EXEC_COMMON();
    }
    alarm_turn(false);
}

void cpu_start_archtest() {
    // FIXME: Use a better way to end the test
    uint64_t start = slowtimer_get_microseconds();
    alarm_turn(true);
    for (size_t i = 0; i < SIZE_MAX; i++) {
        if (i % 1000 == 1 && slowtimer_get_microseconds() - start > 4000000)
            break;
        if (rv.shutdown)
            continue;
        clint_tick();
        uart_tick();
        CPU_EXEC_COMMON();
    }
    alarm_turn(false);
}

// clang-format off
static const char *regs[] = {
    "$0", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
    "s0", "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
    "a6", "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};
// clang-format on

static const char *csrs[] = {
    [CSR_MVENDORID] = "mvendorid",
    [CSR_MARCHID] = "marchid",
    [CSR_MIMPID] = "mimpid",
    [CSR_MHARTID] = "mhartid",
    [CSR_MSTATUS] = "mstatus",
    [CSR_MISA] = "misa",
    [CSR_MEDELEG] = "medeleg",
    [CSR_MIDELEG] = "mideleg",
    [CSR_MIE] = "mie",
    [CSR_MTVEC] = "mtvec",
    [CSR_MSCRATCH] = "mscratch",
    [CSR_MEPC] = "mepc",
    [CSR_MCAUSE] = "mcause",
    [CSR_MTVAL] = "mtval",
    [CSR_MIP] = "mip",
    [CSR_SSTATUS] = "sstatus",
    [CSR_SIE] = "sie",
    [CSR_STVEC] = "stvec",
    [CSR_SSCRATCH] = "sscratch",
    [CSR_SEPC] = "sepc",
    [CSR_SCAUSE] = "scause",
    [CSR_STVAL] = "stval",
    [CSR_SIP] = "sip",
    [CSR_SATP] = "satp",
};

void cpu_print_registers() {
    for (size_t i = 0; i < NR_GPR; i++)
        printf("%s\t0x%08" PRIx64 "\n", regs[i], R(i));
    printf("%s\t0x%08" PRIx64 "\n", "pc", rv.PC);

    const int implemented_csrs[] = {
        CSR_MVENDORID, CSR_MARCHID, CSR_MIMPID,  CSR_MHARTID,  CSR_MSTATUS,
        CSR_MISA,      CSR_MEDELEG, CSR_MIDELEG, CSR_MIE,      CSR_MTVEC,
        CSR_MSCRATCH,  CSR_MEPC,    CSR_MCAUSE,  CSR_MTVAL,    CSR_MIP,
        CSR_SSTATUS,   CSR_SIE,     CSR_STVEC,   CSR_SSCRATCH, CSR_SEPC,
        CSR_SCAUSE,    CSR_STVAL,   CSR_SIP,     CSR_SATP};
    for (size_t i = 0; i < ARRAY_SIZE(implemented_csrs); i++)
        printf("%s\t0x%08" PRIx64 "\n", csrs[implemented_csrs[i]],
               cpu_read_csr(implemented_csrs[i]));
}
