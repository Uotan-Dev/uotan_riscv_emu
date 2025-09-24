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

#include "core/cpu.h"
#include "core/decode.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "ui/ui.h"

// Raise an exception
// This should only be called in the decode / exec proccess
void cpu_raise_exception(exception_t cause, uint64_t tval) {
    // We only support M mode for now
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

// Process intr
// This is not a part of decode/exec process,
// so not using Decode struct to change PC here
FORCE_INLINE void cpu_process_intr(interrupt_t intr) {
    assert((uint64_t)intr & INTERRUPT_FLAG);
    // printf("intr: %llu\n", (unsigned long long)intr & ~INTERRUPT_FLAG);

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

/*
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

    // We don't have U-mode implemented
    mstatus |= MSTATUS_MPP;
    // mstatus &= ~MSTATUS_MPP; // Use this for U-mode impl

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

    // We don't have U-mode implemented
    sstatus |= SSTATUS_SPP;

    cpu_write_csr(CSR_SSTATUS, sstatus);
}

FORCE_INLINE void _wfi(Decode *s) {
    // Implement as NOP
    ;
}

FORCE_INLINE void _sfence_vma(Decode *s) {
    // TODO: TLB
    ;
}

#define LOAD(rd, addr, type, sz_type, sz)                                      \
    do {                                                                       \
        type __v = vaddr_read_##sz_type(addr);                                 \
        if (rv.last_exception != CAUSE_LOAD_ACCESS &&                          \
            rv.last_exception != CAUSE_LOAD_PAGEFAULT) {                       \
            R(rd) = (uint64_t)__v;                                             \
        }                                                                      \
    } while (0)

#define LOAD_SEXT(rd, addr, type, sz_type, sz)                                 \
    do {                                                                       \
        type __v = vaddr_read_##sz_type(addr);                                 \
        if (rv.last_exception != CAUSE_LOAD_ACCESS &&                          \
            rv.last_exception != CAUSE_LOAD_PAGEFAULT) {                       \
            R(rd) = SEXT(__v, sz);                                             \
        }                                                                      \
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
    INSTPAT("??????? ????? ????? 000 ????? 11000 11", beq    , B,
        if (src1 == src2) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 101 ????? 11000 11", bge    , B,
        if ((int64_t)src1 >= (int64_t)src2) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 111 ????? 11000 11", bgeu   , B,
        if (src1 >= src2) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 100 ????? 11000 11", blt    , B,
        if ((int64_t)src1 < (int64_t)src2) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 110 ????? 11000 11", bltu   , B,
        if (src1 < src2) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 001 ????? 11000 11", bne    , B,
        if (src1 != src2) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("0000??? ????? 00000 000 00000 00011 11", fence  , I, /* nop */);
    INSTPAT("0000000 00000 00000 001 00000 00011 11", fence.i, I, /* nop */);
    INSTPAT("??????? ????? ????? ??? ????? 11011 11", jal    , J,
        uint64_t target = s->pc + imm;
        if (unlikely((target & 3) != 0)) {
            cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
        } else {
            R(rd) = s->pc + 4;
            s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 000 ????? 11001 11", jalr   , I,
        uint64_t t = s->pc + 4;
        uint64_t target = (src1 + imm) & ~1ULL;
        if (unlikely(target & 3) != 0) {
            cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
        } else {
            s->npc = (src1 + imm) & ~1ULL;
            R(rd) = t;
        }    
    );
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
    INSTPAT("0000000 ????? ????? 001 ????? 01110 11", sllw   , R, R(rd) = SEXT(BITS(src1, 31, 0) << BITS(src2, 5, 0), 32));
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
        uint64_t t = cpu_read_csr(imm);
        cpu_write_csr(imm, t & ~src1);
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 111 ????? 11100 11", csrrci  ,I,
        uint64_t zimm = BITS(s->inst, 19, 15);
        uint64_t t = cpu_read_csr(imm);
        cpu_write_csr(imm, t & ~zimm);
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 010 ????? 11100 11", csrrs  , I,
        uint64_t t = cpu_read_csr(imm);
        cpu_write_csr(imm, t | src1);
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 110 ????? 11100 11", csrrsi , I,
        uint64_t zimm = BITS(s->inst, 19, 15);
        uint64_t t = cpu_read_csr(imm);
        cpu_write_csr(imm, t | zimm);
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 001 ????? 11100 11", csrrw  , I,
        uint64_t t = cpu_read_csr(imm);
        cpu_write_csr(imm, src1);
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 101 ????? 11100 11", csrrwi , I,
        uint64_t zimm = BITS(s->inst, 19, 15);
        uint64_t t = cpu_read_csr(imm);
        R(rd) = t;
        cpu_write_csr(imm, zimm);
    );
    INSTPAT("0000000 00001 00000 000 00000 11100 11", ebreak     , N, cpu_raise_exception(CAUSE_BREAKPOINT, 0));
    INSTPAT("0000000 00000 00000 000 00000 11100 11", ecall      , N, _ecall(s));
    INSTPAT("0011000 00010 00000 000 00000 11100 11", mret       , N, _mret(s));
    INSTPAT("0001001 ????? ????? 000 00000 11100 11", sfence.vma , R, _sfence_vma(s));
    INSTPAT("0001000 00010 00000 000 00000 11100 11", sret       , N, _sret(s));
    INSTPAT("0001000 00101 00000 000 00000 11100 11", wfi        , N, _wfi(s));

    // RV64M instructions
    INSTPAT("0000001 ????? ????? 100 ????? 01100 11", div    , R, R(rd) = (int64_t)src1 / (int64_t)src2);
    INSTPAT("0000001 ????? ????? 101 ????? 01100 11", divu   , R, R(rd) = src1 / src2);
    INSTPAT("0000001 ????? ????? 101 ????? 01110 11", divuw  , R, R(rd) = SEXT(BITS(src1, 31, 0) / BITS(src2, 31, 0), 32));
    INSTPAT("0000001 ????? ????? 100 ????? 01110 11", divw   , R, R(rd) = SEXT((int32_t)BITS(src1, 31, 0) / (int32_t)BITS(src2, 31, 0), 32));
    INSTPAT("0000001 ????? ????? 000 ????? 01100 11", mul    , R, R(rd) = src1 * src2);
    INSTPAT("0000001 ????? ????? 001 ????? 01100 11", mulh   , R, R(rd) = (int64_t)((__int128_t)src1 * (__int128_t)src2 >> 64));
    INSTPAT("0000001 ????? ????? 010 ????? 01100 11", mulhsu , R, R(rd) = (uint64_t)((__int128_t)((__int128_t)src1 * (__uint128_t)src2) >> 64));
    INSTPAT("0000001 ????? ????? 011 ????? 01100 11", mulhu  , R, R(rd) = (uint64_t)((__uint128_t)src1 * (__uint128_t)src2 >> 64));
    INSTPAT("0000001 ????? ????? 000 ????? 01110 11", mulw   , R, R(rd) = SEXT(BITS(src1 * src2, 31, 0), 32));
    INSTPAT("0000001 ????? ????? 110 ????? 01100 11", rem    , R, R(rd) = (int64_t)src1 % (int64_t)src2);
    INSTPAT("0000001 ????? ????? 111 ????? 01100 11", remu   , R, R(rd) = src1 % src2);
    INSTPAT("0000001 ????? ????? 111 ????? 01110 11", remuw  , R, R(rd) = SEXT(BITS(src1, 31, 0) % BITS(src2, 31, 0), 32));
    INSTPAT("0000001 ????? ????? 110 ????? 01110 11", remw   , R, R(rd) = SEXT((int32_t)BITS(src1, 31, 0) % (int32_t)BITS(src2, 31, 0), 32));

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
    // printf("%" PRIx64 " %" PRIx32 "\n", s->pc, s->inst);
    decode_exec(s);
    rv.PC = s->npc;
}

void __cpu_exec_once() {
    if (!unlikely(rv.shutdown)) {
        rv.last_exception = CAUSE_EXCEPTION_NONE;
        clint_tick();
        interrupt_t intr = rv_get_pending_interrupt();
        if (unlikely(intr != CAUSE_INTERRUPT_NONE))
            cpu_process_intr(intr);
        cpu_exec_once(&rv.decode, rv.PC);
    }
}

// This can also be called directly from test
void __cpu_start() {
    while (!unlikely(rv.shutdown)) {
        rv.last_exception = CAUSE_EXCEPTION_NONE;
        clint_tick();
        interrupt_t intr = rv_get_pending_interrupt();
        if (unlikely(intr != CAUSE_INTERRUPT_NONE))
            cpu_process_intr(intr);
        cpu_exec_once(&rv.decode, rv.PC);
    }
}

void cpu_start() {
    __cpu_start();
    Info("Machine has shutdown, Starting the UI");
    ui_start();
}

/* Some tools */

// clang-format off
static const char *regs[] = {
    "$0", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
    "s0", "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
    "a6", "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};
// clang-format on

void cpu_print_registers() {
    for (size_t i = 0; i < NR_GPR; i++)
        printf("%s\t0x%08" PRIx64 "\n", regs[i], R(i));
    printf("%s\t0x%08" PRIx64 "\n", "pc", rv.PC);
}
