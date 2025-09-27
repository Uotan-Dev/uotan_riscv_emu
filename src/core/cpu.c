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

#include "core/cpu.h"
#include "core/decode.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "device/clint.h"
#include "device/uart.h"
#include "ui/ui.h"
#include "utils/logger.h"
#include "utils/slowtimer.h"

// Raise an exception
// This should only be called in the decode / exec proccess
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

// Get current rounding mode from fcsr or instruction rm field
FORCE_INLINE uint8_t get_rounding_mode(uint8_t rm) {
    if (rm == FRM_DYN)
        return rv.fcsr.frm;
    return rm;
}

// Convert softfloat exception flags to RISC-V fflags
FORCE_INLINE uint8_t softfloat_flags_to_riscv(uint8_t sf_flags) {
    uint8_t riscv_flags = 0;
    if (sf_flags & softfloat_flag_inexact)
        riscv_flags |= FFLAGS_NX;
    if (sf_flags & softfloat_flag_underflow)
        riscv_flags |= FFLAGS_UF;
    if (sf_flags & softfloat_flag_overflow)
        riscv_flags |= FFLAGS_OF;
    if (sf_flags & softfloat_flag_infinite)
        riscv_flags |= FFLAGS_DZ;
    if (sf_flags & softfloat_flag_invalid)
        riscv_flags |= FFLAGS_NV;
    return riscv_flags;
}

// Set floating-point exception flags
FORCE_INLINE void set_fflags(uint8_t flags) { rv.fcsr.fflags |= flags; }

FORCE_INLINE void update_fflags() {
    uint8_t sf_flags = softfloat_exceptionFlags;
    set_fflags(softfloat_flags_to_riscv(sf_flags));
    softfloat_exceptionFlags = 0; // Clear for next operation
}

// Set softfloat rounding mode
FORCE_INLINE void set_softfloat_rounding_mode(uint8_t rm) {
    switch (rm) {
        case FRM_RNE: softfloat_roundingMode = softfloat_round_near_even; break;
        case FRM_RTZ: softfloat_roundingMode = softfloat_round_minMag; break;
        case FRM_RDN: softfloat_roundingMode = softfloat_round_min; break;
        case FRM_RUP: softfloat_roundingMode = softfloat_round_max; break;
        case FRM_RMM:
            softfloat_roundingMode = softfloat_round_near_maxMag;
            break;
        default:
            // Invalid rounding mode
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            break;
    }
}

// Check if floating-point operations are enabled
FORCE_INLINE bool fp_enabled() {
    // Check FS field in MSTATUS (bits [14:13])
    uint64_t fs = (rv.MSTATUS >> 13) & 0x3;
    return fs != 0; // FS = 0 means FP disabled
}

// Set FS field to dirty when FP state is modified
FORCE_INLINE void set_fs_dirty() {
    rv.MSTATUS =
        (rv.MSTATUS & ~(0x3ULL << 13)) | (0x3ULL << 13); // FS = 11 (dirty)
}

// NaN boxing for single precision in RV64F
FORCE_INLINE uint64_t nan_box_f32(uint32_t val) {
    return val | 0xFFFFFFFF00000000ULL;
}

// Check if value is properly NaN-boxed for single precision
FORCE_INLINE bool is_nan_boxed_f32(uint64_t val) {
    return (val >> 32) == 0xFFFFFFFF;
}

// Get single precision value, returning canonical NaN if not NaN-boxed
FORCE_INLINE float32_t get_f32(uint64_t val) {
    if (!is_nan_boxed_f32(val))
        return (float32_t){0x7FC00000}; // Canonical NaN
    return (float32_t){(uint32_t)val};
}

FORCE_INLINE bool f32_isNaN(float32_t f) {
    uint32_t ui = f.v;
    uint32_t exp = (ui >> 23) & 0xFF; // 8-bit exponent
    uint32_t frac = ui & 0x7FFFFF;    // 23-bit fraction
    return (exp == 0xFF) && (frac != 0);
}

FORCE_INLINE bool f64_isNaN(float64_t f) {
    uint64_t ui = f.v;
    uint64_t exp = (ui >> 52) & 0x7FF;       // 11-bit exponent
    uint64_t frac = ui & 0xFFFFFFFFFFFFFULL; // 52-bit fraction
    return (exp == 0x7FF) && (frac != 0);
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

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

typedef enum {
    TYPE_I,
    TYPE_U,
    TYPE_S,
    TYPE_J,
    TYPE_R,
    TYPE_B,
    TYPE_R4,
    TYPE_N, // none
} inst_type_t;

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

FORCE_INLINE void decode_operand(Decode *s, int *rd, int *rs1, int *rs2,
                                 int *rs3, uint64_t *imm, inst_type_t type) {
    uint32_t i = s->inst;
    *rs1 = BITS(i, 19, 15);
    *rs2 = BITS(i, 24, 20);
    *rs3 = BITS(i, 31, 27);
    *rd = BITS(i, 11, 7);
    switch (type) {
        case TYPE_I: immI(); break;
        case TYPE_U: immU(); break;
        case TYPE_S: immS(); break;
        case TYPE_N: break;
        case TYPE_J: immJ(); break;
        case TYPE_R: break;
        case TYPE_B: immB(); break;
        case TYPE_R4: break;
        default: __UNREACHABLE;
    }
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

#define CSR_CHECK_PERM(csr)                                                    \
    do {                                                                       \
        if ((((csr >> 8) & 0x3) == 3 && rv.privilege < PRIV_M) ||              \
            ((((csr) >> 8) & 0x3) == 1 && rv.privilege < PRIV_S))              \
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);      \
    } while (0)

static inline void decode_exec(Decode *s) {
    // FIXME: function ‘decode_exec’ can never be inlined because it contains a
    // computed goto

#define INSTPAT_INST(s) ((s)->inst)

#define INSTPAT_MATCH(s, name, type, ... /* execute body */)                   \
    {                                                                          \
        int rd = 0, rs1 = 0, rs2 = 0, rs3 = 0;                                 \
        uint64_t imm = 0;                                                      \
        decode_operand(s, &rd, &rs1, &rs2, &rs3, &imm, concat(TYPE_, type));   \
        __VA_ARGS__;                                                           \
    }

    // clang-format off
    INSTPAT_START();

    // RV64I instructions
    INSTPAT("0000000 ????? ????? 000 ????? 01100 11", add    , R, R(rd) = R(rs1) + R(rs2));
    INSTPAT("??????? ????? ????? 000 ????? 00100 11", addi   , I, R(rd) = R(rs1) + imm);
    INSTPAT("??????? ????? ????? 000 ????? 00110 11", addiw  , I, R(rd) = SEXT(BITS(R(rs1) + imm, 31, 0), 32));
    INSTPAT("0000000 ????? ????? 000 ????? 01110 11", addw   , R, R(rd) = SEXT(BITS(R(rs1) + R(rs2), 31, 0), 32));
    INSTPAT("0000000 ????? ????? 111 ????? 01100 11", and    , R, R(rd) = R(rs1) & R(rs2));
    INSTPAT("??????? ????? ????? 111 ????? 00100 11", andi   , I, R(rd) = R(rs1) & imm);
    INSTPAT("??????? ????? ????? ??? ????? 00101 11", auipc  , U, R(rd) = s->pc + imm);
    INSTPAT("??????? ????? ????? 000 ????? 11000 11", beq    , B,
        if (R(rs1) == R(rs2)) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 101 ????? 11000 11", bge    , B,
        if ((int64_t)R(rs1) >= (int64_t)R(rs2)) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 111 ????? 11000 11", bgeu   , B,
        if (R(rs1) >= R(rs2)) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 100 ????? 11000 11", blt    , B,
        if ((int64_t)R(rs1) < (int64_t)R(rs2)) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 110 ????? 11000 11", bltu   , B,
        if (R(rs1) < R(rs2)) {
            uint64_t target = s->pc + imm;
            if (unlikely((target & 3) != 0))
                cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
            else
                s->npc = target;
        }
    );
    INSTPAT("??????? ????? ????? 001 ????? 11000 11", bne    , B,
        if (R(rs1) != R(rs2)) {
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
        uint64_t target = (R(rs1) + imm) & ~1ULL;
        if (unlikely(target & 3) != 0) {
            cpu_raise_exception(CAUSE_MISALIGNED_FETCH, target);
        } else {
            s->npc = (R(rs1) + imm) & ~1ULL;
            R(rd) = t;
        }    
    );
    INSTPAT("??????? ????? ????? 000 ????? 00000 11", lb     , I, LOAD_SEXT(rd, R(rs1) + imm, uint8_t, b, 8));
    INSTPAT("??????? ????? ????? 100 ????? 00000 11", lbu    , I, LOAD(rd, R(rs1) + imm, uint8_t, b, 8));
    INSTPAT("??????? ????? ????? 011 ????? 00000 11", ld     , I, LOAD(rd, R(rs1) + imm, uint64_t, d, 64));
    INSTPAT("??????? ????? ????? 001 ????? 00000 11", lh     , I, LOAD_SEXT(rd, R(rs1) + imm, uint16_t, s, 16));
    INSTPAT("??????? ????? ????? 101 ????? 00000 11", lhu    , I, LOAD(rd, R(rs1) + imm, uint16_t, s, 16));
    INSTPAT("??????? ????? ????? ??? ????? 01101 11", lui    , U, R(rd) = SEXT(BITS(imm, 31, 12) << 12, 32));
    INSTPAT("??????? ????? ????? 010 ????? 00000 11", lw     , I, LOAD_SEXT(rd, R(rs1) + imm, uint32_t, w, 32));
    INSTPAT("??????? ????? ????? 110 ????? 00000 11", lwu    , I, LOAD(rd, R(rs1) + imm, uint32_t, w, 32));
    INSTPAT("0000000 ????? ????? 110 ????? 01100 11", or     , R, R(rd) = R(rs1) | R(rs2));
    INSTPAT("??????? ????? ????? 110 ????? 00100 11", ori    , I, R(rd) = R(rs1) | imm);
    INSTPAT("??????? ????? ????? 000 ????? 01000 11", sb     , S, vaddr_write_b(R(rs1) + imm, R(rs2)));
    INSTPAT("??????? ????? ????? 011 ????? 01000 11", sd     , S, vaddr_write_d(R(rs1) + imm, R(rs2)));
    INSTPAT("??????? ????? ????? 001 ????? 01000 11", sh     , S, vaddr_write_s(R(rs1) + imm, R(rs2)));
    INSTPAT("0000000 ????? ????? 001 ????? 01100 11", sll    , R, R(rd) = R(rs1) << BITS(R(rs2), 5, 0));
    INSTPAT("000000? ????? ????? 001 ????? 00100 11", slli   , I, R(rd) = R(rs1) << BITS(imm, 5, 0));
    INSTPAT("0000000 ????? ????? 001 ????? 00110 11", slliw  , I, R(rd) = SEXT(BITS(R(rs1), 31, 0) << BITS(imm, 4, 0), 32));
    INSTPAT("0000000 ????? ????? 001 ????? 01110 11", sllw   , R, R(rd) = SEXT((uint32_t)BITS(R(rs1), 31, 0) << (BITS(R(rs2), 4, 0)), 32));
    INSTPAT("0000000 ????? ????? 010 ????? 01100 11", slt    , R, R(rd) = (int64_t)R(rs1) < (int64_t)R(rs2));
    INSTPAT("??????? ????? ????? 010 ????? 00100 11", slti   , I, R(rd) = (int64_t)R(rs1) < (int64_t)imm);
    INSTPAT("??????? ????? ????? 011 ????? 00100 11", sltiu  , I, R(rd) = R(rs1) < imm);
    INSTPAT("0000000 ????? ????? 011 ????? 01100 11", sltu   , R, R(rd) = R(rs1) < R(rs2));
    INSTPAT("0100000 ????? ????? 101 ????? 01100 11", sra    , R, R(rd) = (int64_t)R(rs1) >> BITS(R(rs2), 5, 0));
    INSTPAT("010000? ????? ????? 101 ????? 00100 11", srai   , I, R(rd) = (int64_t)R(rs1) >> BITS(imm, 5, 0));
    INSTPAT("0100000 ????? ????? 101 ????? 00110 11", sraiw  , I, R(rd) = SEXT((int32_t)(BITS(R(rs1), 31, 0)) >> BITS(imm, 4, 0), 32));
    INSTPAT("0100000 ????? ????? 101 ????? 01110 11", sraw   , R, R(rd) = SEXT((int32_t)(BITS(R(rs1), 31, 0)) >> BITS(R(rs2), 4, 0), 32));
    INSTPAT("0000000 ????? ????? 101 ????? 01100 11", srl    , R, R(rd) = R(rs1) >> BITS(R(rs2), 5, 0));
    INSTPAT("000000? ????? ????? 101 ????? 00100 11", srli   , I, R(rd) = R(rs1) >> BITS(imm, 5, 0));
    INSTPAT("0000000 ????? ????? 101 ????? 00110 11", srliw  , I, R(rd) = SEXT(BITS(R(rs1), 31, 0) >> BITS(imm, 4, 0), 32));
    INSTPAT("0000000 ????? ????? 101 ????? 01110 11", srlw   , R, R(rd) = SEXT(BITS(R(rs1), 31, 0) >> BITS(R(rs2), 4, 0), 32));
    INSTPAT("0100000 ????? ????? 000 ????? 01100 11", sub    , R, R(rd) = R(rs1) - R(rs2));
    INSTPAT("0100000 ????? ????? 000 ????? 01110 11", subw   , R, R(rd) = SEXT(BITS(R(rs1) - R(rs2), 31, 0), 32));
    INSTPAT("??????? ????? ????? 010 ????? 01000 11", sw     , S, vaddr_write_w(R(rs1) + imm, BITS(R(rs2), 31, 0)));
    INSTPAT("0000000 ????? ????? 100 ????? 01100 11", xor    , R, R(rd) = R(rs1) ^ R(rs2));
    INSTPAT("??????? ????? ????? 100 ????? 00100 11", xori   , I, R(rd) = R(rs1) ^ imm);
    INSTPAT("??????? ????? ????? 011 ????? 11100 11", csrrc   ,I,
        CSR_CHECK_PERM(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            uint64_t t = cpu_read_csr(imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                cpu_write_csr(imm, t & ~R(rs1));
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
                cpu_write_csr(imm, t | R(rs1));
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
                cpu_write_csr(imm, R(rs1));
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
    INSTPAT("0000000 00001 00000 000 00000 11100 11", ebreak     , N, cpu_raise_exception(CAUSE_BREAKPOINT, 0));
    INSTPAT("0000000 00000 00000 000 00000 11100 11", ecall      , N, _ecall(s));
    INSTPAT("0011000 00010 00000 000 00000 11100 11", mret       , N, _mret(s));
    INSTPAT("0001001 ????? ????? 000 00000 11100 11", sfence.vma , R, _sfence_vma(s));
    INSTPAT("0001000 00010 00000 000 00000 11100 11", sret       , N, _sret(s));
    INSTPAT("0001000 00101 00000 000 00000 11100 11", wfi        , N, _wfi(s));

    // RV64M instructions
    INSTPAT("0000001 ????? ????? 100 ????? 01100 11", div    , R,
        if (unlikely((int64_t)R(rs2) == 0))
            R(rd) = ~0ULL;
        else if (unlikely((int64_t)R(rs1) == INT64_MIN && (int64_t)R(rs2) == -1))
            R(rd) = (int64_t)R(rs1);
        else
            R(rd) = (int64_t)R(rs1) / (int64_t)R(rs2);
    );
    INSTPAT("0000001 ????? ????? 101 ????? 01100 11", divu   , R,
        if (unlikely(R(rs2) == 0))
            R(rd) = ~0ULL;
        else
            R(rd) = R(rs1) / R(rs2);
    );
    INSTPAT("0000001 ????? ????? 101 ????? 01110 11", divuw  , R,
        uint32_t v1 = BITS(R(rs1), 31, 0);
        uint32_t v2 = BITS(R(rs2), 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = ~0ULL;
        else
            R(rd) = SEXT(v1 / v2, 32);
    );
    INSTPAT("0000001 ????? ????? 100 ????? 01110 11", divw   , R,
        int32_t v1 = (int32_t)BITS(R(rs1), 31, 0);
        int32_t v2 = (int32_t)BITS(R(rs2), 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = ~0ULL;
        else if (unlikely(v1 == INT32_MIN && v2 == -1))
            R(rd) = SEXT(v1, 32);
        else
            R(rd) = SEXT(v1 / v2, 32);
    );
    INSTPAT("0000001 ????? ????? 000 ????? 01100 11", mul    , R, R(rd) = R(rs1) * R(rs2));
    INSTPAT("0000001 ????? ????? 001 ????? 01100 11", mulh   , R, 
        R(rd) = (int64_t)(((__int128_t)(int64_t)R(rs1) * (__int128_t)(int64_t)R(rs2)) >> 64)
    );
    INSTPAT("0000001 ????? ????? 010 ????? 01100 11", mulhsu , R, 
        R(rd) = (int64_t)(((__int128_t)(int64_t)R(rs1) * (__uint128_t)R(rs2)) >> 64)
    );
    INSTPAT("0000001 ????? ????? 011 ????? 01100 11", mulhu  , R,
        R(rd) = (uint64_t)((__uint128_t)R(rs1) * (__uint128_t)R(rs2) >> 64)
    );
    INSTPAT("0000001 ????? ????? 000 ????? 01110 11", mulw   , R, R(rd) = SEXT(BITS(R(rs1) * R(rs2), 31, 0), 32));
    INSTPAT("0000001 ????? ????? 110 ????? 01100 11", rem    , R,
        if (unlikely((int64_t)R(rs2) == 0))
            R(rd) = (int64_t)R(rs1);
        else if (unlikely((int64_t)R(rs1) == INT64_MIN && (int64_t)R(rs2) == -1))
            R(rd) = 0;  // overflow case: remainder is 0
        else
            R(rd) = (int64_t)R(rs1) % (int64_t)R(rs2);
    );
    INSTPAT("0000001 ????? ????? 111 ????? 01100 11", remu   , R,
        if (unlikely(R(rs2) == 0))
            R(rd) = R(rs1);
        else
            R(rd) = R(rs1) % R(rs2);
    );
    INSTPAT("0000001 ????? ????? 111 ????? 01110 11", remuw  , R, 
        uint32_t v1 = BITS(R(rs1), 31, 0);
        uint32_t v2 = BITS(R(rs2), 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = SEXT(v1, 32);
        else
            R(rd) = SEXT(v1 % v2, 32);
    );
    INSTPAT("0000001 ????? ????? 110 ????? 01110 11", remw   , R, 
        int32_t v1 = (int32_t)BITS(R(rs1), 31, 0);
        int32_t v2 = (int32_t)BITS(R(rs2), 31, 0);
        if (unlikely(v2 == 0))
            R(rd) = SEXT(v1, 32);
        else if (unlikely(v1 == INT32_MIN && v2 == -1))
            R(rd) = 0;
        else
            R(rd) = SEXT(v1 % v2, 32);
    );

    // RV64A instructions
    INSTPAT("00010?? 00000 ????? 011 ????? 01011 11", lr.d   , R,
        uint64_t v = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = v;
            rv.reservation_address = R(rs1);
            rv.reservation_valid = true;
        }
    );
    INSTPAT("00010?? 00000 ????? 010 ????? 01011 11", lr.w   , R,
        uint32_t v = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = SEXT(v, 32);
            rv.reservation_address = R(rs1);
            rv.reservation_valid = true;
        }
    );
    INSTPAT("00011?? ????? ????? 011 ????? 01011 11", sc.d   , R,
        if (rv.reservation_valid && rv.reservation_address == R(rs1)) {
            vaddr_write_d(R(rs1), R(rs2));
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
        if (rv.reservation_valid && rv.reservation_address == R(rs1)) {
            vaddr_write_w(R(rs1), R(rs2));
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
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), (int64_t)t + (int64_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("00000?? ????? ????? 010 ????? 01011 11", amoadd.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), (int32_t)t + (int32_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("01100?? ????? ????? 011 ????? 01011 11", amoand.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), (int64_t)t & (int64_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("01100?? ????? ????? 010 ????? 01011 11", amoand.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), (int32_t)t & (int32_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("01000?? ????? ????? 011 ????? 01011 11", amoor.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), (int64_t)t | (int64_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("01000?? ????? ????? 010 ????? 01011 11", amoor.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), (int32_t)t | (int32_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("00100?? ????? ????? 011 ????? 01011 11", amoxor.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), (int64_t)t ^ (int64_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("00100?? ????? ????? 010 ????? 01011 11", amoxor.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), (int32_t)t ^ (int32_t)R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("10100?? ????? ????? 011 ????? 01011 11", amomax.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), MAX((int64_t)t, (int64_t)R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("10100?? ????? ????? 010 ????? 01011 11", amomax.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), MAX((int32_t)t, (int32_t)R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("11100?? ????? ????? 011 ????? 01011 11", amomaxu.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), MAX(t, R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("11100?? ????? ????? 010 ????? 01011 11", amomaxu.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), MAX((uint32_t)t, (uint32_t)R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("10000?? ????? ????? 011 ????? 01011 11", amomin.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), MIN((int64_t)t, (int64_t)R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("10000?? ????? ????? 010 ????? 01011 11", amomin.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), MIN((int32_t)t, (int32_t)R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("11000?? ????? ????? 011 ????? 01011 11", amominu.d , R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), MIN(t, R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("11000?? ????? ????? 010 ????? 01011 11", amominu.w , R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), MIN((uint32_t)t, (uint32_t)R(rs2)));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );
    INSTPAT("00001?? ????? ????? 011 ????? 01011 11", amoswap.d, R,
        uint64_t t = vaddr_read_d(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_d(R(rs1), R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    );
    INSTPAT("00001?? ????? ????? 010 ????? 01011 11", amoswap.w, R,
        uint32_t t = vaddr_read_w(R(rs1));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            vaddr_write_w(R(rs1), R(rs2));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = SEXT(t, 32);
        }
    );

    // RV64F instructions
    INSTPAT("??????? ????? ????? 010 ????? 00001 11", flw, I,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint32_t val = vaddr_read_w(R(rs1) + imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                rv.F[rd].u64 = nan_box_f32(val);
                set_fs_dirty();
            }
        }
    );
    INSTPAT("??????? ????? ????? 010 ????? 01001 11", fsw, S,
        if (!fp_enabled())
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        else
            vaddr_write_w(R(rs1) + imm, get_f32(rv.F[rs2].u64).v);
    );
    INSTPAT("0000000 ????? ????? ??? ????? 10100 11", fadd.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f32_add(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0000100 ????? ????? ??? ????? 10100 11", fsub.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f32_sub(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0001000 ????? ????? ??? ????? 10100 11", fmul.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f32_mul(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0001100 ????? ????? ??? ????? 10100 11", fdiv.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f32_div(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0101100 00000 ????? ??? ????? 10100 11", fsqrt.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f32_sqrt(get_f32(rv.F[rs1].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0010000 ????? ????? 000 ????? 10100 11", fsgnj.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint32_t val1 = get_f32(rv.F[rs1].u64).v;
            uint32_t val2 = get_f32(rv.F[rs2].u64).v;
            uint32_t result = (val1 & 0x7FFFFFFF) | (val2 & 0x80000000);
            rv.F[rd].u64 = nan_box_f32(result);
            set_fs_dirty();
        }
    );
    INSTPAT("0010000 ????? ????? 001 ????? 10100 11", fsgnjn.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint32_t val1 = get_f32(rv.F[rs1].u64).v;
            uint32_t val2 = get_f32(rv.F[rs2].u64).v;
            uint32_t result = (val1 & 0x7FFFFFFF) | ((~val2) & 0x80000000);
            rv.F[rd].u64 = nan_box_f32(result);
            set_fs_dirty();
        }
    );
    INSTPAT("0010000 ????? ????? 010 ????? 10100 11", fsgnjx.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint32_t val1 = get_f32(rv.F[rs1].u64).v;
            uint32_t val2 = get_f32(rv.F[rs2].u64).v;
            uint32_t result = val1 ^ (val2 & 0x80000000);
            rv.F[rd].u64 = nan_box_f32(result);
            set_fs_dirty();
        }
    );
    INSTPAT("0010100 ????? ????? 000 ????? 10100 11", fmin.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            float32_t f1 = get_f32(rv.F[rs1].u64);
            float32_t f2 = get_f32(rv.F[rs2].u64);
            bool f1_nan = f32_isSignalingNaN(f1) || f32_isNaN(f1);
            bool f2_nan = f32_isSignalingNaN(f2) || f32_isNaN(f2);
            float32_t result;
            if (f1_nan && f2_nan)
                result.v = 0x7fc00000; // Canonical NaN
            else if (f1_nan)
                result = f2;
            else if (f2_nan)
                result = f1;
            else
                result = f32_le(f1, f2) ? f1 : f2;
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0010100 ????? ????? 001 ????? 10100 11", fmax.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            float32_t f1 = get_f32(rv.F[rs1].u64);
            float32_t f2 = get_f32(rv.F[rs2].u64);
            bool f1_nan = f32_isSignalingNaN(f1) || f32_isNaN(f1);
            bool f2_nan = f32_isSignalingNaN(f2) || f32_isNaN(f2);
            float32_t result;
            if (f1_nan && f2_nan)
                result.v = 0x7fc00000; // Canonical NaN
            else if (f1_nan)
                result = f2;
            else if (f2_nan)
                result = f1;
            else
                result = f32_le(f2, f1) ? f1 : f2;
            
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1100000 00000 ????? ??? ????? 10100 11", fcvt.w.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            int32_t result = f32_to_i32(get_f32(rv.F[rs1].u64), softfloat_roundingMode, true);
            R(rd) = SEXT(result, 32);
            update_fflags();
        }
    );
    INSTPAT("1100000 00001 ????? ??? ????? 10100 11", fcvt.wu.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            uint32_t result = f32_to_ui32(get_f32(rv.F[rs1].u64), softfloat_roundingMode, true);
            R(rd) = SEXT(result, 32);
            update_fflags();
        }
    );
    INSTPAT("1100000 00010 ????? ??? ????? 10100 11", fcvt.l.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            R(rd) = f32_to_i64(get_f32(rv.F[rs1].u64), softfloat_roundingMode, true);
            update_fflags();
        }
    );
    INSTPAT("1100000 00011 ????? ??? ????? 10100 11", fcvt.lu.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            R(rd) = f32_to_ui64(get_f32(rv.F[rs1].u64), softfloat_roundingMode, true);
            update_fflags();
        }
    );
    INSTPAT("1101000 00000 ????? ??? ????? 10100 11", fcvt.s.w, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = i32_to_f32((int32_t)R(rs1));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1101000 00001 ????? ??? ????? 10100 11", fcvt.s.wu, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = ui32_to_f32((uint32_t)R(rs1));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1101000 00010 ????? ??? ????? 10100 11", fcvt.s.l, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = i64_to_f32(R(rs1));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1101000 00011 ????? ??? ????? 10100 11", fcvt.s.lu, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = ui64_to_f32(R(rs1));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1110000 00000 ????? 000 ????? 10100 11", fmv.x.w, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = SEXT(get_f32(rv.F[rs1].u64).v, 32);
        }
    );
    INSTPAT("1111000 00000 ????? 000 ????? 10100 11", fmv.w.x, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            rv.F[rd].u64 = nan_box_f32((uint32_t)R(rs1));
            set_fs_dirty();
        }
    );
    INSTPAT("1110000 00000 ????? 001 ????? 10100 11", fclass.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            float32_t val = get_f32(rv.F[rs1].u64);
            uint64_t result = 0;
            if (f32_isSignalingNaN(val)) result |= (1 << 8);
            else if (f32_isNaN(val)) result |= (1 << 9);
            else if (val.v == 0xFF800000) result |= (1 << 0); // -inf
            else if (val.v == 0x7F800000) result |= (1 << 7); // +inf
            else if ((val.v & 0x7F800000) == 0) {
                if (val.v & 0x80000000) result |= (1 << 2); // -subnormal
                else result |= (1 << 5); // +subnormal
            } else if (val.v == 0x80000000) result |= (1 << 3); // -0
            else if (val.v == 0x00000000) result |= (1 << 4); // +0
            else if (val.v & 0x80000000) result |= (1 << 1); // -normal
            else result |= (1 << 6); // +normal
            R(rd) = result;
        }
    );
    INSTPAT("1010000 ????? ????? 010 ????? 10100 11", feq.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = f32_eq(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            update_fflags();
        }
    );
    INSTPAT("1010000 ????? ????? 001 ????? 10100 11", flt.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = f32_lt(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            update_fflags();
        }
    );
    INSTPAT("1010000 ????? ????? 000 ????? 10100 11", fle.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = f32_le(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64));
            update_fflags();
        }
    );
    INSTPAT("?????00 ????? ????? ??? ????? 10000 11", fmadd.s, R4,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f32_mulAdd(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64), get_f32(rv.F[rs3].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("?????00 ????? ????? ??? ????? 10001 11", fmsub.s, R4,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t neg_rs3 = {get_f32(rv.F[rs3].u64).v ^ 0x80000000};
            float32_t result = f32_mulAdd(get_f32(rv.F[rs1].u64), get_f32(rv.F[rs2].u64), neg_rs3);
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("?????00 ????? ????? ??? ????? 10010 11", fnmsub.s, R4,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t rs1_val = get_f32(rv.F[rs1].u64);
            float32_t neg_rs1_val = {rs1_val.v ^ 0x80000000};
            float32_t result = f32_mulAdd(neg_rs1_val, get_f32(rv.F[rs2].u64), get_f32(rv.F[rs3].u64));
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("?????00 ????? ????? ??? ????? 10011 11", fnmadd.s, R4,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t rs1_val = get_f32(rv.F[rs1].u64);
            float32_t rs3_val = get_f32(rv.F[rs3].u64);
            float32_t neg_rs1_val = {rs1_val.v ^ 0x80000000};
            float32_t neg_rs3_val = {rs3_val.v ^ 0x80000000};
            float32_t result = f32_mulAdd(neg_rs1_val, get_f32(rv.F[rs2].u64), neg_rs3_val);
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );

    // RV64D instructions
    INSTPAT("??????? ????? ????? 011 ????? 00001 11", fld, I,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint64_t val = vaddr_read_d(R(rs1) + imm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
                rv.F[rd].u64 = val;
                set_fs_dirty();
            }
        }
    );
    INSTPAT("??????? ????? ????? 011 ????? 01000 11", fsd, S,
        if (!fp_enabled())
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        else
            vaddr_write_d(R(rs1) + imm, rv.F[rs2].u64);
    );
    INSTPAT("0000001 ????? ????? ??? ????? 10100 11", fadd.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = f64_add(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0000101 ????? ????? ??? ????? 10100 11", fsub.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = f64_sub(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0001001 ????? ????? ??? ????? 10100 11", fmul.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = f64_mul(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0001101 ????? ????? ??? ????? 10100 11", fdiv.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = f64_div(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0101101 00000 ????? ??? ????? 10100 11", fsqrt.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = f64_sqrt(rv.F[rs1].f64);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0010001 ????? ????? 000 ????? 10100 11", fsgnj.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint64_t sign_mask = 0x8000000000000000ULL;
            rv.F[rd].u64 = (rv.F[rs1].u64 & ~sign_mask) | (rv.F[rs2].u64 & sign_mask);
            set_fs_dirty();
        }
    );
    INSTPAT("0010001 ????? ????? 001 ????? 10100 11", fsgnjn.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint64_t sign_mask = 0x8000000000000000ULL;
            rv.F[rd].u64 = (rv.F[rs1].u64 & ~sign_mask) | ((~rv.F[rs2].u64) & sign_mask);
            set_fs_dirty();
        }
    );
    INSTPAT("0010001 ????? ????? 010 ????? 10100 11", fsgnjx.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint64_t sign_mask = 0x8000000000000000ULL;
            uint64_t xor_sign = (rv.F[rs1].u64 ^ rv.F[rs2].u64) & sign_mask;
            rv.F[rd].u64 = (rv.F[rs1].u64 & ~sign_mask) | xor_sign;
            set_fs_dirty();
        }
    );
    INSTPAT("0010101 ????? ????? 000 ????? 10100 11", fmin.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            float64_t a = rv.F[rs1].f64;
            float64_t b = rv.F[rs2].f64;
            if (f64_isNaN(a) && f64_isNaN(b))
                rv.F[rd].f64 = (float64_t){0x7FF8000000000000ULL}; // Canonical NaN
            else if (f64_isNaN(a))
                rv.F[rd].f64 = b;
            else if (f64_isNaN(b))
                rv.F[rd].f64 = a;
            else
                rv.F[rd].f64 = f64_le(a, b) ? a : b;
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0010101 ????? ????? 001 ????? 10100 11", fmax.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            float64_t a = rv.F[rs1].f64;
            float64_t b = rv.F[rs2].f64;
            if (f64_isNaN(a) && f64_isNaN(b))
                rv.F[rd].f64 = (float64_t){0x7FF8000000000000ULL}; // Canonical NaN
            else if (f64_isNaN(a))
                rv.F[rd].f64 = b;
            else if (f64_isNaN(b))
                rv.F[rd].f64 = a;
            else
                rv.F[rd].f64 = f64_le(a, b) ? b : a;
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1100001 00000 ????? ??? ????? 10100 11", fcvt.w.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            int32_t result = f64_to_i32(rv.F[rs1].f64, softfloat_roundingMode, true);
            R(rd) = SEXT(result, 32);
            update_fflags();
        }
    );
    INSTPAT("1100001 00001 ????? ??? ????? 10100 11", fcvt.wu.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            uint32_t result = f64_to_ui32(rv.F[rs1].f64, softfloat_roundingMode, true);
            R(rd) = SEXT(result, 32);
            update_fflags();
        }
    );
    INSTPAT("1100001 00010 ????? ??? ????? 10100 11", fcvt.l.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            R(rd) = f64_to_i64(rv.F[rs1].f64, softfloat_roundingMode, true);
            update_fflags();
        }
    );
    INSTPAT("1100001 00011 ????? ??? ????? 10100 11", fcvt.lu.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            R(rd) = f64_to_ui64(rv.F[rs1].f64, softfloat_roundingMode, true);
            update_fflags();
        }
    );
    INSTPAT("1101001 00000 ????? ??? ????? 10100 11", fcvt.d.w, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = i32_to_f64((int32_t)R(rs1));
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1101001 00001 ????? ??? ????? 10100 11", fcvt.d.wu, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = ui32_to_f64((uint32_t)R(rs1));
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1101001 00010 ????? ??? ????? 10100 11", fcvt.d.l, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = i64_to_f64(R(rs1));
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1101001 00011 ????? ??? ????? 10100 11", fcvt.d.lu, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = ui64_to_f64(R(rs1));
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0100000 00001 ????? ??? ????? 10100 11", fcvt.s.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float32_t result = f64_to_f32(rv.F[rs1].f64);
            rv.F[rd].u64 = nan_box_f32(result.v);
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("0100001 00000 ????? ??? ????? 10100 11", fcvt.d.s, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            rv.F[rd].f64 = f32_to_f64(get_f32(rv.F[rs1].u64));
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("1111001 00000 ????? 000 ????? 10100 11", fmv.x.d, R,
        if (!fp_enabled())
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        else
            R(rd) = rv.F[rs1].u64;
    );
    INSTPAT("1111101 00000 ????? 000 ????? 10100 11", fmv.d.x, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            rv.F[rd].u64 = R(rs1);
            set_fs_dirty();
        }
    );
    INSTPAT("1110001 00000 ????? 001 ????? 10100 11", fclass.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            float64_t val = rv.F[rs1].f64;
            uint64_t result = 0;
            
            if (f64_isSignalingNaN(val)) result |= (1 << 8);
            else if (f64_isNaN(val)) result |= (1 << 9);
            else if (val.v == 0xFFF0000000000000ULL) result |= (1 << 0); // -inf
            else if (val.v == 0x7FF0000000000000ULL) result |= (1 << 7); // +inf
            else if ((val.v & 0x7FF0000000000000ULL) == 0) {
                if (val.v & 0x8000000000000000ULL) result |= (1 << 2); // -subnormal
                else result |= (1 << 5); // +subnormal
            } else if (val.v == 0x8000000000000000ULL) result |= (1 << 3); // -0
            else if (val.v == 0x0000000000000000ULL) result |= (1 << 4); // +0
            else if (val.v & 0x8000000000000000ULL) result |= (1 << 1); // -normal
            else result |= (1 << 6); // +normal
            R(rd) = result;
        }
    );
    INSTPAT("1010001 ????? ????? 010 ????? 10100 11", feq.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = f64_eq(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
        }
    );
    INSTPAT("1010001 ????? ????? 001 ????? 10100 11", flt.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = f64_lt(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
        }
    );
    INSTPAT("1010001 ????? ????? 000 ????? 10100 11", fle.d, R,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            R(rd) = f64_le(rv.F[rs1].f64, rv.F[rs2].f64);
            update_fflags();
        }
    );
    INSTPAT("????? ?? ????? ????? ??? ????? 10000 11", fmadd.d, R4,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float64_t result = f64_mulAdd(rv.F[rs1].f64, rv.F[rs2].f64, rv.F[rs3].f64);
            rv.F[rd].f64 = result;
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("????? ?? ????? ????? ??? ????? 10001 11", fmsub.d, R4,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float64_t neg_rs3 = {rv.F[rs3].u64 ^ 0x8000000000000000ULL};
            float64_t result = f64_mulAdd(rv.F[rs1].f64, rv.F[rs2].f64, neg_rs3);
            rv.F[rd].f64 = result;
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("????? ?? ????? ????? ??? ????? 10010 11", fnmsub.d, R4, // Note: Corrected opcode pattern
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float64_t neg_rs1 = {rv.F[rs1].u64 ^ 0x8000000000000000ULL};
            float64_t result = f64_mulAdd(neg_rs1, rv.F[rs2].f64, rv.F[rs3].f64);
            rv.F[rd].f64 = result;
            update_fflags();
            set_fs_dirty();
        }
    );
    INSTPAT("????? ?? ????? ????? ??? ????? 10011 11", fnmadd.d, R4, // Note: Corrected opcode pattern
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t rm = get_rounding_mode(BITS(s->inst, 14, 12));
            set_softfloat_rounding_mode(rm);
            float64_t neg_rs1 = {rv.F[rs1].u64 ^ 0x8000000000000000ULL};
            float64_t neg_rs3 = {rv.F[rs3].u64 ^ 0x8000000000000000ULL};
            float64_t result = f64_mulAdd(neg_rs1, rv.F[rs2].f64, neg_rs3);
            rv.F[rd].f64 = result;
            update_fflags();
            set_fs_dirty();
        }
    );

    // CSR instructions for floating-point control and status register
    INSTPAT("0000000 00001 00000 010 ????? 11100 11", frcsr, I,
        if (!fp_enabled())
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        else
            R(rd) = rv.fcsr.raw;
    );
    INSTPAT("0000000 00001 ????? 001 00000 11100 11", fscsr, I,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint32_t old_fcsr = rv.fcsr.raw;
            rv.fcsr.raw = R(rs1) & 0xFF; // Only bits [7:0] are writable
            R(rd) = old_fcsr;
        }
    );
    INSTPAT("0000000 00010 00000 010 ????? 11100 11", frrm, I,
        if (!fp_enabled())
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        else
            R(rd) = rv.fcsr.frm;
    );
    INSTPAT("0000000 00010 ????? 001 00000 11100 11", fsrm, I,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t old_frm = rv.fcsr.frm;
            rv.fcsr.frm = R(rs1) & 0x7; // Only bits [2:0] are valid
            R(rd) = old_frm;
        }
    );
    INSTPAT("0000000 00011 00000 010 ????? 11100 11", frflags, I,
        if (!fp_enabled())
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        else
            R(rd) = rv.fcsr.fflags;
    );
    INSTPAT("0000000 00011 ????? 001 00000 11100 11", fsflags, I,
        if (!fp_enabled()) {
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->pc);
        } else {
            uint8_t old_fflags = rv.fcsr.fflags;
            rv.fcsr.fflags = R(rs1) & 0x1F; // Only bits [4:0] are valid
            R(rd) = old_fflags;
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
    // printf("%" PRIx64 " %" PRIx32 "\n", s->pc, s->inst);
    // assert(s->pc);
    decode_exec(s);
    rv.PC = s->npc;
    rv.MCYCLE++;
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE &&
               !rv.suppress_minstret_increase))
        rv.MINSTRET++;
    rv.suppress_minstret_increase = false;
}

#define CPU_EXEC_COMMON()                                                      \
    do {                                                                       \
        softfloat_exceptionFlags = 0;                                          \
        rv.last_exception = CAUSE_EXCEPTION_NONE;                              \
        clint_tick();                                                          \
        uart_tick();                                                           \
        interrupt_t intr = rv_get_pending_interrupt();                         \
        if (unlikely(intr != CAUSE_INTERRUPT_NONE))                            \
            cpu_process_intr(intr);                                            \
        cpu_exec_once(&rv.decode, rv.PC);                                      \
    } while (0)

// This should only be used for tests
void __cpu_exec_once() {
    if (!unlikely(rv.shutdown))
        CPU_EXEC_COMMON();
}

// This can also be called directly from tests
void __cpu_start() {
    uint64_t start = slowtimer_get_microseconds();
    uint64_t inst_cnt = 0;
    while (!unlikely(rv.shutdown)) {
        CPU_EXEC_COMMON();
        inst_cnt++;
    }
    uint64_t end = slowtimer_get_microseconds();
    double delta = (double)(end - start) / 1000000.0;
    log_info("Simulation time: %f seconds (%" PRIu64 " microseconds)", delta,
             end - start);
    log_info("Simulation speed: %f insts per second", inst_cnt / delta);
}

void cpu_start() {
    __cpu_start();
    log_info("Machine has shutdown, Starting the UI");
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

    printf("priv: %" PRIu64 "\n", (uint64_t)rv.privilege);
    // printf("last exception: 0x%08" PRIx64 "\n", (uint64_t)rv.last_exception);
}
