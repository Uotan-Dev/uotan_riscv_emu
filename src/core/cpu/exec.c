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

#include "core/cpu/csr.h"
#include "core/cpu/decode.h"
#include "core/mem.h"
#include "core/riscv.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define R(i) rv.X[i]
#define F(i) rv.F[i]

void cpu_exec_inst(Decode *s) {
    s->exec(s);
    R(0) = 0; // reset $zero to 0
}

#define EXTRACT_OPRAND()                                                       \
    __attribute__((__unused__)) int rd = s->rd, rs1 = s->rs1, rs2 = s->rs2,    \
                                    rs3 = s->rs3;                              \
    __attribute__((__unused__)) uint64_t imm = s->imm;

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

#define FP_INST_PREP()                                                         \
    do {                                                                       \
        assert(softfloat_exceptionFlags == 0);                                 \
        if ((rv.MSTATUS & MSTATUS_FS) == 0)                                    \
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);      \
    } while (0)

#define FP_SETUP_RM()                                                          \
    do {                                                                       \
        uint64_t rm = BITS(s->inst, 14, 12);                                   \
        if (rm == FRM_DYN)                                                     \
            rm = rv.FCSR.fields.frm;                                           \
        if (unlikely(rm > FRM_RMM))                                            \
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);      \
        else                                                                   \
            softfloat_roundingMode = rm;                                       \
    } while (0)

#define FP_SET_DIRTY()                                                         \
    do {                                                                       \
        rv.MSTATUS |= MSTATUS_SD;                                              \
        rv.MSTATUS |= MSTATUS_FS;                                              \
    } while (0)

#define FP_UPDATE_EXCEPTION_FLAGS()                                            \
    do {                                                                       \
        if (softfloat_exceptionFlags) {                                        \
            FP_SET_DIRTY();                                                    \
            rv.FCSR.fields.fflags |= softfloat_exceptionFlags;                 \
            softfloat_exceptionFlags = 0;                                      \
        }                                                                      \
    } while (0)

#define FP_INST_END()                                                          \
    do {                                                                       \
        FP_SET_DIRTY();                                                        \
        FP_UPDATE_EXCEPTION_FLAGS();                                           \
    } while (0)

void exec_add(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) + R(rs2);
}

void exec_addi(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) + imm;
}

void exec_addiw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) + imm, 31, 0), 32);
}

void exec_addw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) + R(rs2), 31, 0), 32);
}

void exec_and(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) & R(rs2);
}

void exec_andi(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) & imm;
}

void exec_auipc(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = s->pc + imm;
}

void exec_beq(Decode *s) {
    EXTRACT_OPRAND();
    if (R(rs1) == R(rs2))
        s->npc = s->pc + imm;
}

void exec_bge(Decode *s) {
    EXTRACT_OPRAND();
    if ((int64_t)R(rs1) >= (int64_t)R(rs2))
        s->npc = s->pc + imm;
}

void exec_bgeu(Decode *s) {
    EXTRACT_OPRAND();
    if (R(rs1) >= R(rs2))
        s->npc = s->pc + imm;
}

void exec_blt(Decode *s) {
    EXTRACT_OPRAND();
    if ((int64_t)R(rs1) < (int64_t)R(rs2))
        s->npc = s->pc + imm;
}

void exec_bltu(Decode *s) {
    EXTRACT_OPRAND();
    if (R(rs1) < R(rs2))
        s->npc = s->pc + imm;
}

void exec_bne(Decode *s) {
    EXTRACT_OPRAND();
    if (R(rs1) != R(rs2))
        s->npc = s->pc + imm;
}

void exec_fence(Decode *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_fence_i(Decode *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_jal(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = s->pc + 4;
    s->npc = s->pc + imm;
}

void exec_jalr(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = s->pc + 4;
    s->npc = (R(rs1) + imm) & ~1ULL;
    R(rd) = t;
}

void exec_lb(Decode *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint8_t, b, 8);
}

void exec_lbu(Decode *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint8_t, b, 8);
}

void exec_ld(Decode *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint64_t, d, 64);
}

void exec_lh(Decode *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint16_t, s, 16);
}

void exec_lhu(Decode *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint16_t, s, 16);
}

void exec_lui(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(imm, 31, 12) << 12, 32);
}

void exec_lw(Decode *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint32_t, w, 32);
}

void exec_lwu(Decode *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint32_t, w, 32);
}

void exec_or(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) | R(rs2);
}

void exec_ori(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) | imm;
}

void exec_sb(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_b(R(rs1) + imm, R(rs2));
}

void exec_sd(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, R(rs2));
}

void exec_sh(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_s(R(rs1) + imm, R(rs2));
}

void exec_sll(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) << BITS(R(rs2), 5, 0);
}

void exec_slli(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) << BITS(imm, 5, 0);
}

void exec_slliw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1), 31, 0) << BITS(imm, 4, 0), 32);
}

void exec_sllw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT((uint32_t)BITS(R(rs1), 31, 0) << (BITS(R(rs2), 4, 0)), 32);
}

void exec_slt(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) < (int64_t)R(rs2);
}

void exec_slti(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) < (int64_t)imm;
}

void exec_sltiu(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) < imm;
}

void exec_sltu(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) < R(rs2);
}

void exec_sra(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) >> BITS(R(rs2), 5, 0);
}

void exec_srai(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) >> BITS(imm, 5, 0);
}

void exec_sraiw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT((int32_t)(BITS(R(rs1), 31, 0)) >> BITS(imm, 4, 0), 32);
}

void exec_sraw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT((int32_t)(BITS(R(rs1), 31, 0)) >> BITS(R(rs2), 4, 0), 32);
}

void exec_srl(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) >> BITS(R(rs2), 5, 0);
}

void exec_srli(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) >> BITS(imm, 5, 0);
}

void exec_srliw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1), 31, 0) >> BITS(imm, 4, 0), 32);
}

void exec_srlw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1), 31, 0) >> BITS(R(rs2), 4, 0), 32);
}

void exec_sub(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) - R(rs2);
}

void exec_subw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) - R(rs2), 31, 0), 32);
}

void exec_sw(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(rs1) + imm, BITS(R(rs2), 31, 0));
}

void exec_xor(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) ^ R(rs2);
}

void exec_xori(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) ^ imm;
}

void exec_csrrc(Decode *s) {
    EXTRACT_OPRAND();
    CSR_CHECK_PERM(imm);
    bool lk = cpu_csr_need_lock(imm);
    if (lk)
        pthread_mutex_lock(&rv.csr_lock);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        uint64_t t = cpu_read_csr(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            cpu_write_csr(imm, t & ~R(rs1));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    }
    if (lk)
        pthread_mutex_unlock(&rv.csr_lock);
}

void exec_csrrci(Decode *s) {
    EXTRACT_OPRAND();
    CSR_CHECK_PERM(imm);
    bool lk = cpu_csr_need_lock(imm);
    if (lk)
        pthread_mutex_lock(&rv.csr_lock);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        uint64_t zimm = BITS(s->inst, 19, 15);
        uint64_t t = cpu_read_csr(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            cpu_write_csr(imm, t & ~zimm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    }
    if (lk)
        pthread_mutex_unlock(&rv.csr_lock);
}

void exec_csrrs(Decode *s) {
    EXTRACT_OPRAND();
    CSR_CHECK_PERM(imm);
    bool lk = cpu_csr_need_lock(imm);
    if (lk)
        pthread_mutex_lock(&rv.csr_lock);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        uint64_t t = cpu_read_csr(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            cpu_write_csr(imm, t | R(rs1));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    }
    if (lk)
        pthread_mutex_unlock(&rv.csr_lock);
}

void exec_csrrsi(Decode *s) {
    EXTRACT_OPRAND();
    CSR_CHECK_PERM(imm);
    bool lk = cpu_csr_need_lock(imm);
    if (lk)
        pthread_mutex_lock(&rv.csr_lock);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        uint64_t zimm = BITS(s->inst, 19, 15);
        uint64_t t = cpu_read_csr(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            cpu_write_csr(imm, t | zimm);
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    }
    if (lk)
        pthread_mutex_unlock(&rv.csr_lock);
}

void exec_csrrw(Decode *s) {
    EXTRACT_OPRAND();
    CSR_CHECK_PERM(imm);
    bool lk = cpu_csr_need_lock(imm);
    if (lk)
        pthread_mutex_lock(&rv.csr_lock);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        uint64_t t = cpu_read_csr(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            cpu_write_csr(imm, R(rs1));
            if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
                R(rd) = t;
        }
    }
    if (lk)
        pthread_mutex_unlock(&rv.csr_lock);
}

void exec_csrrwi(Decode *s) {
    EXTRACT_OPRAND();
    CSR_CHECK_PERM(imm);
    bool lk = cpu_csr_need_lock(imm);
    if (lk)
        pthread_mutex_lock(&rv.csr_lock);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        uint64_t zimm = BITS(s->inst, 19, 15);
        uint64_t t = cpu_read_csr(imm);
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = t;
            cpu_write_csr(imm, zimm);
        }
    }
    if (lk)
        pthread_mutex_unlock(&rv.csr_lock);
}

void exec_ebreak(Decode *s) {
    EXTRACT_OPRAND();
    cpu_raise_exception(CAUSE_BREAKPOINT, s->pc);
}

void exec_ecall(Decode *s) {
    EXTRACT_OPRAND();
    switch (rv.privilege) {
        case PRIV_M: cpu_raise_exception(CAUSE_MACHINE_ECALL, s->pc); break;
        case PRIV_S: cpu_raise_exception(CAUSE_SUPERVISOR_ECALL, s->pc); break;
        case PRIV_U: cpu_raise_exception(CAUSE_USER_ECALL, s->pc); break;
        default: __UNREACHABLE;
    }
}

void exec_mret(Decode *s) {
    EXTRACT_OPRAND();
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

void exec_sfence_vma(Decode *s) {
    EXTRACT_OPRAND();
    // TODO: TLB
}

void exec_sret(Decode *s) {
    EXTRACT_OPRAND();
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

void exec_wfi(Decode *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_div(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely((int64_t)R(rs2) == 0))
        R(rd) = ~0ULL;
    else if (unlikely((int64_t)R(rs1) == INT64_MIN && (int64_t)R(rs2) == -1))
        R(rd) = (int64_t)R(rs1);
    else
        R(rd) = (int64_t)R(rs1) / (int64_t)R(rs2);
}

void exec_divu(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(R(rs2) == 0))
        R(rd) = ~0ULL;
    else
        R(rd) = R(rs1) / R(rs2);
}

void exec_divuw(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t v1 = BITS(R(rs1), 31, 0);
    uint32_t v2 = BITS(R(rs2), 31, 0);
    if (unlikely(v2 == 0))
        R(rd) = ~0ULL;
    else
        R(rd) = SEXT(v1 / v2, 32);
}

void exec_divw(Decode *s) {
    EXTRACT_OPRAND();
    int32_t v1 = (int32_t)BITS(R(rs1), 31, 0);
    int32_t v2 = (int32_t)BITS(R(rs2), 31, 0);
    if (unlikely(v2 == 0))
        R(rd) = ~0ULL;
    else if (unlikely(v1 == INT32_MIN && v2 == -1))
        R(rd) = SEXT(v1, 32);
    else
        R(rd) = SEXT(v1 / v2, 32);
}

void exec_mul(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) * R(rs2);
}

void exec_mulh(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) =
        (int64_t)(((__int128_t)(int64_t)R(rs1) * (__int128_t)(int64_t)R(rs2)) >>
                  64);
}

void exec_mulhsu(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) =
        (int64_t)(((__int128_t)(int64_t)R(rs1) * (__uint128_t)R(rs2)) >> 64);
}

void exec_mulhu(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = (uint64_t)((__uint128_t)R(rs1) * (__uint128_t)R(rs2) >> 64);
}

void exec_mulw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) * R(rs2), 31, 0), 32);
}

void exec_rem(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely((int64_t)R(rs2) == 0))
        R(rd) = (int64_t)R(rs1);
    else if (unlikely((int64_t)R(rs1) == INT64_MIN && (int64_t)R(rs2) == -1))
        R(rd) = 0; // overflow case: remainder is 0
    else
        R(rd) = (int64_t)R(rs1) % (int64_t)R(rs2);
}

void exec_remu(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(R(rs2) == 0))
        R(rd) = R(rs1);
    else
        R(rd) = R(rs1) % R(rs2);
}

void exec_remuw(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t v1 = BITS(R(rs1), 31, 0);
    uint32_t v2 = BITS(R(rs2), 31, 0);
    if (unlikely(v2 == 0))
        R(rd) = SEXT(v1, 32);
    else
        R(rd) = SEXT(v1 % v2, 32);
}

void exec_remw(Decode *s) {
    EXTRACT_OPRAND();
    int32_t v1 = (int32_t)BITS(R(rs1), 31, 0);
    int32_t v2 = (int32_t)BITS(R(rs2), 31, 0);
    if (unlikely(v2 == 0))
        R(rd) = SEXT(v1, 32);
    else if (unlikely(v1 == INT32_MIN && v2 == -1))
        R(rd) = 0;
    else
        R(rd) = SEXT(v1 % v2, 32);
}

void exec_lr_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t v = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = v;
        rv.reservation_address = R(rs1);
        rv.reservation_valid = true;
    }
}

void exec_lr_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t v = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = SEXT(v, 32);
        rv.reservation_address = R(rs1);
        rv.reservation_valid = true;
    }
}

void exec_sc_d(Decode *s) {
    EXTRACT_OPRAND();
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
}

void exec_sc_w(Decode *s) {
    EXTRACT_OPRAND();
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
}

void exec_amoadd_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t + (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoadd_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t + (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoand_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t & (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoand_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t & (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoor_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t | (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoor_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t | (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoxor_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t ^ (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoxor_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t ^ (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amomax_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MAX((int64_t)t, (int64_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amomax_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MAX((int32_t)t, (int32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amomaxu_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MAX(t, R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amomaxu_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MAX((uint32_t)t, (uint32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amomin_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MIN((int64_t)t, (int64_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amomin_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MIN((int32_t)t, (int32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amominu_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MIN(t, R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amominu_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MIN((uint32_t)t, (uint32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoswap_d(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoswap_w(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_flw(Decode *s) {
    EXTRACT_OPRAND();
    uint32_t val = vaddr_read_w(R(rs1) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        fpr_write32(&F(rd), (float32_t){val});
}

void exec_fsw(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(rs1) + imm, (uint32_t)F(rs2).v);
}

void exec_fadd_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_add(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2))));
            FP_INST_END();
        }
    }
}

void exec_fsub_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_sub(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2))));
            FP_INST_END();
        }
    }
}

void exec_fmul_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_mul(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2))));
            FP_INST_END();
        }
    }
}

void exec_fdiv_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_div(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2))));
            FP_INST_END();
        }
    }
}

void exec_fsqrt_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), f32_sqrt(fpr_get_f32(F(rs1))));
            FP_INST_END();
        }
    }
}

void exec_fsgnj_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float32_t f1 = fpr_get_f32(F(rs1));
        float32_t f2 = fpr_get_f32(F(rs2));
        fpr_write32(&F(rd),
                    (float32_t){(f1.v & ~F32_SIGN) | (f2.v & F32_SIGN)});
        FP_SET_DIRTY();
    }
}

void exec_fsgnjn_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float32_t f1 = fpr_get_f32(F(rs1));
        float32_t f2 = fpr_get_f32(F(rs2));
        fpr_write32(&F(rd),
                    (float32_t){(f1.v & ~F32_SIGN) | (~f2.v & F32_SIGN)});
        FP_SET_DIRTY();
    }
}

void exec_fsgnjx_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float32_t f1 = fpr_get_f32(F(rs1));
        float32_t f2 = fpr_get_f32(F(rs2));
        fpr_write32(&F(rd), (float32_t){f1.v ^ (f2.v & F32_SIGN)});
        FP_SET_DIRTY();
    }
}

void exec_fmin_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        if (f32_isSignalingNaN(fpr_get_f32(F(rs1))) ||
            f32_isSignalingNaN(fpr_get_f32(F(rs2))))
            rv.FCSR.fflags.NV = 1;
        bool smaller = f32_lt_quiet(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2))) ||
                       (f32_eq(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2))) &&
                        f32_isNegative(fpr_get_f32(F(rs1))));
        if (f32_isNaN(fpr_get_f32(F(rs1))) && f32_isNaN(fpr_get_f32(F(rs2)))) {
            fpr_write32(&F(rd), (float32_t){F32_DEFAULT_NAN});
        } else {
            if (smaller || f32_isNaN(fpr_get_f32(F(rs2))))
                fpr_write32(&F(rd), fpr_get_f32(F(rs1)));
            else
                fpr_write32(&F(rd), fpr_get_f32(F(rs2)));
        }
        FP_INST_END();
    }
}

void exec_fmax_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        if (f32_isSignalingNaN(fpr_get_f32(F(rs1))) ||
            f32_isSignalingNaN(fpr_get_f32(F(rs2))))
            rv.FCSR.fflags.NV = 1;
        bool greater = f32_lt_quiet(fpr_get_f32(F(rs2)), fpr_get_f32(F(rs1))) ||
                       (f32_eq(fpr_get_f32(F(rs2)), fpr_get_f32(F(rs1))) &&
                        f32_isNegative(fpr_get_f32(F(rs2))));
        if (f32_isNaN(fpr_get_f32(F(rs1))) && f32_isNaN(fpr_get_f32(F(rs2)))) {
            fpr_write32(&F(rd), (float32_t){F32_DEFAULT_NAN});
        } else {
            if (greater || f32_isNaN(fpr_get_f32(F(rs2))))
                fpr_write32(&F(rd), fpr_get_f32(F(rs1)));
            else
                fpr_write32(&F(rd), fpr_get_f32(F(rs2)));
        }
        FP_INST_END();
    }
}

void exec_fcvt_w_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = (int64_t)f32_to_i32(fpr_get_f32(F(rs1)),
                                        softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_wu_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = (int64_t)(int32_t)f32_to_ui32(fpr_get_f32(F(rs1)),
                                                  softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_l_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) =
                f32_to_i64(fpr_get_f32(F(rs1)), softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_lu_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) =
                f32_to_ui64(fpr_get_f32(F(rs1)), softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_s_w(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), i32_to_f32((int32_t)R(rs1)));
            FP_INST_END();
        }
    }
}

void exec_fcvt_s_wu(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), ui32_to_f32((int32_t)R(rs1)));
            FP_INST_END();
        }
    }
}

void exec_fcvt_s_l(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), i64_to_f32(R(rs1)));
            FP_INST_END();
        }
    }
}

void exec_fcvt_s_lu(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), ui64_to_f32(R(rs1)));
            FP_INST_END();
        }
    }
}

void exec_fmv_x_w(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = (int64_t)(int32_t)(uint32_t)F(rs1).v;
}

void exec_fmv_w_x(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        fpr_write32(&F(rd), (float32_t){(uint32_t)((int32_t)R(rs1))});
        FP_SET_DIRTY();
    }
}

void exec_fclass_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = (int64_t)(int32_t)f32_classify(fpr_get_f32(F(rs1)));
}

void exec_feq_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f32_eq(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_flt_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f32_lt(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fle_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f32_le(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fmadd_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_mulAdd(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)),
                                   fpr_get_f32(F(rs3))));
            FP_INST_END();
        }
    }
}

void exec_fmsub_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_mulAdd(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)),
                                   f32_neg(fpr_get_f32(F(rs3)))));
            FP_INST_END();
        }
    }
}

void exec_fnmsub_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd),
                        f32_mulAdd(f32_neg(fpr_get_f32(F(rs1))),
                                   fpr_get_f32(F(rs2)), fpr_get_f32(F(rs3))));
            FP_INST_END();
        }
    }
}

void exec_fnmadd_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), f32_mulAdd(f32_neg(fpr_get_f32(F(rs1))),
                                           fpr_get_f32(F(rs2)),
                                           f32_neg(fpr_get_f32(F(rs3)))));
            FP_INST_END();
        }
    }
}

void exec_fld(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t val = vaddr_read_d(R(rs1) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        F(rd) = (float64_t){val};
}

void exec_fsd(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, F(rs2).v);
}

void exec_fadd_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_add(F(rs1), F(rs2));
            FP_INST_END();
        }
    }
}

void exec_fsub_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_sub(F(rs1), F(rs2));
            FP_INST_END();
        }
    }
}

void exec_fmul_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_mul(F(rs1), F(rs2));
            FP_INST_END();
        }
    }
}

void exec_fdiv_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_div(F(rs1), F(rs2));
            FP_INST_END();
        }
    }
}

void exec_fsqrt_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_sqrt(F(rs1));
            FP_INST_END();
        }
    }
}

void exec_fsgnj_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float64_t f1 = F(rs1), f2 = F(rs2);
        F(rd) = (float64_t){(f1.v & ~F64_SIGN) | (f2.v & F64_SIGN)};
        FP_SET_DIRTY();
    }
}

void exec_fsgnjn_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float64_t f1 = F(rs1), f2 = F(rs2);
        F(rd) = (float64_t){(f1.v & ~F64_SIGN) | (~f2.v & F64_SIGN)};
        FP_SET_DIRTY();
    }
}

void exec_fsgnjx_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float64_t f1 = F(rs1), f2 = F(rs2);
        F(rd) = (float64_t){f1.v ^ (f2.v & F64_SIGN)};
        FP_SET_DIRTY();
    }
}

void exec_fmin_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        if (f64_isSignalingNaN(F(rs1)) || f64_isSignalingNaN(F(rs2)))
            rv.FCSR.fflags.NV = 1;
        bool smaller = f64_lt_quiet(F(rs1), F(rs2)) ||
                       (f64_eq(F(rs1), F(rs2)) && f64_isNegative(F(rs1)));
        if (f64_isNaN(F(rs1)) && f64_isNaN(F(rs2))) {
            F(rd) = (float64_t){F64_DEFAULT_NAN};
        } else {
            if (smaller || f64_isNaN(F(rs2)))
                F(rd) = F(rs1);
            else
                F(rd) = F(rs2);
        }
        FP_INST_END();
    }
}

void exec_fmax_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        if (f64_isSignalingNaN(F(rs1)) || f64_isSignalingNaN(F(rs2)))
            rv.FCSR.fflags.NV = 1;
        bool greater = f64_lt_quiet(F(rs2), F(rs1)) ||
                       (f64_eq(F(rs2), F(rs1)) && f64_isNegative(F(rs2)));
        if (f64_isNaN(F(rs1)) && f64_isNaN(F(rs2))) {
            F(rd) = (float64_t){F64_DEFAULT_NAN};
        } else {
            if (greater || f64_isNaN(F(rs2)))
                F(rd) = F(rs1);
            else
                F(rd) = F(rs2);
        }
        FP_INST_END();
    }
}

void exec_fcvt_w_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = (int64_t)f64_to_i32(F(rs1), softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_wu_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = (int64_t)(int32_t)f64_to_ui32(F(rs1),
                                                  softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_l_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = f64_to_i64(F(rs1), softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_lu_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            R(rd) = f64_to_ui64(F(rs1), softfloat_roundingMode, true);
            FP_INST_END();
        }
    }
}

void exec_fcvt_d_w(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = i32_to_f64((int32_t)R(rs1));
            FP_INST_END();
        }
    }
}

void exec_fcvt_d_wu(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = ui32_to_f64((int32_t)R(rs1));
            FP_INST_END();
        }
    }
}

void exec_fcvt_d_l(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = i64_to_f64(R(rs1));
            FP_INST_END();
        }
    }
}

void exec_fcvt_d_lu(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = ui64_to_f64(R(rs1));
            FP_INST_END();
        }
    }
}

void exec_fcvt_s_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            fpr_write32(&F(rd), f64_to_f32(F(rs1)));
            FP_INST_END();
        }
    }
}

void exec_fcvt_d_s(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f32_to_f64(fpr_get_f32(F(rs1)));
            FP_INST_END();
        }
    }
}

void exec_fmv_x_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = F(rs1).v;
}

void exec_fmv_d_x(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        F(rd) = (float64_t){R(rs1)};
        FP_SET_DIRTY();
    }
}

void exec_fclass_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = (int64_t)f64_classify(F(rs1));
}

void exec_feq_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f64_eq(F(rs1), F(rs2));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_flt_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f64_lt(F(rs1), F(rs2));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fle_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f64_le(F(rs1), F(rs2));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fmadd_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_mulAdd(F(rs1), F(rs2), F(rs3));
            FP_INST_END();
        }
    }
}

void exec_fmsub_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
            F(rd) = f64_mulAdd(F(rs1), F(rs2), f64_neg(F(rs3)));
            FP_INST_END();
        }
    }
}

void exec_fnmsub_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (rv.last_exception == CAUSE_EXCEPTION_NONE) {
            F(rd) = f64_mulAdd((f64_neg(F(rs1))), F(rs2), F(rs3));
            FP_INST_END();
        }
    }
}

void exec_fnmadd_d(Decode *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        FP_SETUP_RM();
        if (rv.last_exception == CAUSE_EXCEPTION_NONE) {
            F(rd) = f64_mulAdd((f64_neg(F(rs1))), F(rs2), f64_neg(F(rs3)));
            FP_INST_END();
        }
    }
}

void exec_c_nop(Decode *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_c_addi(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) += imm;
}

void exec_c_addiw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rd) + imm, 31, 0), 32);
}

void exec_c_li(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = imm;
}

void exec_c_addi16sp(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(imm == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(2) += imm;
}

void exec_c_lui(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(rd == 2 || imm == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(rd) = imm;
}

void exec_c_srli(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) >>= imm;
}

void exec_c_srai(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rd) >> imm;
}

void exec_c_andi(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) &= imm;
}

void exec_c_sub(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) -= R(rs2);
}

void exec_c_xor(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) ^= R(rs2);
}

void exec_c_or(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) |= R(rs2);
}

void exec_c_and(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) &= R(rs2);
}

void exec_c_subw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rd) - R(rs2), 31, 0), 32);
}

void exec_c_addw(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rd) + R(rs2), 31, 0), 32);
}

void exec_c_j(Decode *s) {
    EXTRACT_OPRAND();
    s->npc = s->pc + imm;
}

void exec_c_beqz(Decode *s) {
    EXTRACT_OPRAND();
    if (R(rs1) == 0)
        s->npc = s->pc + imm;
}

void exec_c_bnez(Decode *s) {
    EXTRACT_OPRAND();
    if (R(rs1) != 0)
        s->npc = s->pc + imm;
}

void exec_c_inv(Decode *s) {
    EXTRACT_OPRAND();
    exec_inv(s);
}

void exec_c_addi4spn(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(imm == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(rd) = R(2) + imm;
}

void exec_c_fld(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t val = vaddr_read_d(R(rs1) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        F(rd) = (float64_t){val};
}

void exec_c_lw(Decode *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint32_t, w, 32);
}

void exec_c_ld(Decode *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint64_t, d, 64);
}

void exec_c_fsd(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, F(rs2).v);
}

void exec_c_sw(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(rs1) + imm, BITS(R(rs2), 31, 0));
}

void exec_c_sd(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, R(rs2));
}

void exec_c_slli(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) <<= imm;
}

void exec_c_fldsp(Decode *s) {
    EXTRACT_OPRAND();
    uint64_t val = vaddr_read_d(R(2) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        F(rd) = (float64_t){val};
}

void exec_c_lwsp(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(rd == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        LOAD_SEXT(rd, R(2) + imm, uint32_t, w, 32);
}

void exec_c_ldsp(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(rd == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        LOAD(rd, R(2) + imm, uint64_t, d, 64);
}

void exec_c_jr(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(rs1 == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        s->npc = R(rs1) & ~1ULL;
}

void exec_c_mv(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(rs2 == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(rd) = R(rs2);
}

void exec_c_ebreak(Decode *s) {
    EXTRACT_OPRAND();
    exec_ebreak(s);
}

void exec_c_jalr(Decode *s) {
    EXTRACT_OPRAND();
    if (unlikely(rs1 == 0)) {
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    } else {
        uint64_t t = s->pc + 2;
        s->npc = R(rs1) & ~1ULL;
        R(1) = t;
    }
}

void exec_c_add(Decode *s) {
    EXTRACT_OPRAND();
    R(rd) += R(rs2);
}

void exec_c_fsdsp(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(2) + imm, F(rs2).v);
}

void exec_c_swsp(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(2) + imm, BITS(R(rs2), 31, 0));
}

void exec_c_sdsp(Decode *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(2) + imm, R(rs2));
}

void exec_inv(Decode *s) {
    EXTRACT_OPRAND();
    cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
}
