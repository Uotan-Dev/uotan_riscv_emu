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

void cpu_raise_exception(exception_t cause, uint64_t tval) {
    // We only support M mode for now
    assert(rv.privilege == PRIV_M);

    if (rv.has_debugger) {
        if (unlikely(cause == CAUSE_BREAKPOINT)) {
            rv_halt(rv.X[10], rv.decode.pc, rv.decode.inst);
            return;
        } else if (unlikely(cause == CAUSE_ILLEGAL_INSTRUCTION)) {
            Warn("An illegal instruction exception has happened!");
            // rv_halt(-1, rv.decode.pc, rv.decode.inst);
        }
    }

    rv.MEPC = rv.decode.pc & ~1ULL;
    rv.MCAUSE = cause;
    rv.MTVAL = tval;

    uint64_t mstatus = rv.MSTATUS;

    // Save current MIE to MPIE
    if (mstatus & MSTATUS_MIE)
        mstatus |= MSTATUS_MPIE;
    else
        mstatus &= ~MSTATUS_MPIE;
    // Save PRIV level to MPP
    mstatus &= ~MSTATUS_MPP;
    mstatus |= ((uint64_t)rv.privilege << MSTATUS_MPP_SHIFT);
    // Disable M mode interrupt
    mstatus &= ~MSTATUS_MIE;

    rv.MSTATUS = mstatus;

    // Shift to M Mode
    rv.privilege = PRIV_M;

    rv.decode.npc = rv.MTVEC & ~3ULL;
    uint64_t mtvec = rv.MTVEC;
    if ((mtvec & 3ULL) == 0) {
        // Direct Mode
        rv.decode.npc = mtvec & ~3ULL;
    } else {
        if (cause & INTERRUPT_FLAG)
            // Vectored Mode, Asynchronous interrupts set pc to BASE+4×cause
            rv.decode.npc = (mtvec & ~3ULL) + 4ULL * (cause & 0x3F);
        else
            rv.decode.npc = mtvec & ~3ULL;
    }
}

FORCE_INLINE void cpu_process_intr(interrupt_t intr) {
    assert(intr & INTERRUPT_FLAG);

    privilege_level_t priv = rv.privilege;

    assert(priv == PRIV_M); // M mode only for now
    rv.privilege = PRIV_M;

    uint64_t mtvec = rv.MTVEC;
    uint64_t vt_offset = 0;
    if (mtvec & 1) {
        uint64_t cause = (uint64_t)intr & ~INTERRUPT_FLAG;
        vt_offset = cause << 2;
    }

    rv.decode.npc = (mtvec & ~3ULL) + vt_offset;
    rv.MEPC = rv.decode.pc & ~1ULL;
    rv.MCAUSE = intr;

    uint64_t mstatus = rv.MSTATUS;
    if (mstatus & MSTATUS_MIE)
        mstatus |= MSTATUS_MPIE;
    else
        mstatus &= ~MSTATUS_MPIE;
    mstatus &= ~MSTATUS_MIE;

    mstatus &= ~MSTATUS_MPP;
    mstatus |= ((uint64_t)priv << MSTATUS_MPP_SHIFT);

    rv.MSTATUS = mstatus;
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
    s->npc = rv.MEPC;
    uint64_t mstatus = rv.MSTATUS;

    // Restore MIE
    if (mstatus & MSTATUS_MPIE)
        mstatus |= MSTATUS_MIE;
    else
        mstatus &= ~MSTATUS_MIE;

    mstatus |= MSTATUS_MPIE;

    // Restore PRIV level
    rv.privilege =
        (privilege_level_t)((mstatus & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT);
    mstatus &= ~MSTATUS_MPP;

    rv.MSTATUS = mstatus;
}

FORCE_INLINE void _wfi(Decode *s) {
    ;
    // Implement as NOP
}

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
    INSTPAT("??????? ????? ????? 000 ????? 11000 11", beq    , B, if (src1 == src2) s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? 101 ????? 11000 11", bge    , B, if ((int64_t)src1 >= (int64_t)src2) s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? 111 ????? 11000 11", bgeu   , B, if (src1 >= src2) s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? 100 ????? 11000 11", blt    , B, if ((int64_t)src1 < (int64_t)src2) s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? 110 ????? 11000 11", bltu   , B, if (src1 < src2) s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? 001 ????? 11000 11", bne    , B, if (src1 != src2) s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? ??? ????? 11011 11", jal    , J, R(rd) = s->pc + 4, s->npc = s->pc + imm);
    INSTPAT("??????? ????? ????? 000 ????? 11001 11", jalr   , I, uint64_t t = s->pc + 4; s->npc = (src1 + imm) & ~1ULL; R(rd) = t);
    INSTPAT("??????? ????? ????? 000 ????? 00000 11", lb     , I, R(rd) = SEXT(vaddr_read_b(src1 + imm), 8));
    INSTPAT("??????? ????? ????? 100 ????? 00000 11", lbu    , I, R(rd) = vaddr_read_b(src1 + imm));
    INSTPAT("??????? ????? ????? 011 ????? 00000 11", ld     , I, R(rd) = vaddr_read_d(src1 + imm));
    INSTPAT("??????? ????? ????? 001 ????? 00000 11", lh     , I, R(rd) = SEXT(vaddr_read_s(src1 + imm), 16));
    INSTPAT("??????? ????? ????? 101 ????? 00000 11", lhu    , I, R(rd) = vaddr_read_s(src1 + imm));
    INSTPAT("??????? ????? ????? ??? ????? 01101 11", lui    , U, R(rd) = SEXT(BITS(imm, 31, 12) << 12, 32));
    INSTPAT("??????? ????? ????? 010 ????? 00000 11", lw     , I, R(rd) = SEXT(vaddr_read_w(src1 + imm), 32));
    INSTPAT("??????? ????? ????? 110 ????? 00000 11", lwu    , I, R(rd) = vaddr_read_w(src1 + imm));
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

#define CHK_CSR_OP()                                                           \
    {                                                                          \
        if (!succ)                                                             \
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);           \
    }
    INSTPAT("??????? ????? ????? 011 ????? 11100 11", csrrc   ,I,
        bool succ = true;
        uint64_t t = cpu_read_csr(imm, &succ);
        CHK_CSR_OP();
        cpu_write_csr(imm, t & ~src1, &succ);
        CHK_CSR_OP();
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 111 ????? 11100 11", csrrci  ,I,
        uint64_t zimm = BITS(s->inst, 19, 15);
        bool succ = true;
        uint64_t t = cpu_read_csr(imm, &succ);
        CHK_CSR_OP();
        cpu_write_csr(imm, t & ~zimm, &succ);
        CHK_CSR_OP();
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 010 ????? 11100 11", csrrs  , I,
        bool succ = true;
        uint64_t t = cpu_read_csr(imm, &succ);
        CHK_CSR_OP();
        cpu_write_csr(imm, t | src1, &succ);
        CHK_CSR_OP();
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 110 ????? 11100 11", csrrsi , I,
        uint64_t zimm = BITS(s->inst, 19, 15);
        bool succ = true;
        uint64_t t = cpu_read_csr(imm, &succ);
        CHK_CSR_OP();
        cpu_write_csr(imm, t | zimm, &succ);
        CHK_CSR_OP();
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 001 ????? 11100 11", csrrw  , I,
        bool succ = true;
        uint64_t t = cpu_read_csr(imm, &succ);
        CHK_CSR_OP();
        cpu_write_csr(imm, src1, &succ);
        CHK_CSR_OP();
        R(rd) = t;
    );
    INSTPAT("??????? ????? ????? 101 ????? 11100 11", csrrwi , I,
        uint64_t zimm = BITS(s->inst, 19, 15);
        bool succ = true;
        uint64_t t = cpu_read_csr(imm, &succ);
        CHK_CSR_OP();
        R(rd) = t;
        cpu_write_csr(imm, zimm, &succ);
        CHK_CSR_OP();
    );
#undef CHK_CSR_OP

    INSTPAT("0000000 00001 00000 000 00000 11100 11", ebreak , N, cpu_raise_exception(CAUSE_BREAKPOINT, 0));
    INSTPAT("0000000 00000 00000 000 00000 11100 11", ecall  , N, _ecall(s));
    INSTPAT("0011000 00010 00000 000 00000 11100 11", mret   , N, _mret(s));
    INSTPAT("0001000 00101 00000 000 00000 11100 11", wfi    , N, _wfi(s));

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

void cpu_start() {
    if (rv.halt)
        rv.halt = false;
    cpu_step(-1);
}

void cpu_step(size_t step) {
    if (rv.halt)
        rv.halt = false;
    for (size_t i = 0; i < step && !rv.halt; i++) {
        clint_tick();

        // handle interrupt
        interrupt_t intr = rv_get_pending_interrupt();
        if (unlikely(intr != CAUSE_INTERRUPT_NONE))
            cpu_process_intr(intr);

        // decode and execute
        cpu_exec_once(&rv.decode, rv.PC);
    }
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

uint64_t *cpu_get_csr(uint32_t csr) {
    // clang-format off
    switch (csr & 0xFFF) {
#define macro(csr_name) case CSR_##csr_name: return &rv.csr_name;
        macro(MVENDORID) macro(MARCHID) macro(MIMPID) macro(MHARTID)
        macro(MSTATUS)   macro(MISA)    macro(MTVEC)  macro(MSCRATCH)
        macro(MEPC)      macro(MCAUSE)  macro(MTVAL)  macro(MIE)
        macro(MIP)
#undef macro

        default:
            printf("Invalid CSR requestde: 0x%" PRIx32 "\n", csr & 0xFFF);
            assert(0);
    }
    // clang-format on
}
