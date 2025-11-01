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

void cpu_exec_inst(rv_insn_t *s) {
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

void exec_add(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) + R(rs2);
}

void exec_addi(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) + imm;
}

void exec_addiw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) + imm, 31, 0), 32);
}

void exec_addw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) + R(rs2), 31, 0), 32);
}

void exec_and(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) & R(rs2);
}

void exec_andi(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) & imm;
}

void exec_auipc(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = s->pc + imm;
}

void exec_beq(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (R(rs1) == R(rs2))
        s->npc = s->pc + imm;
}

void exec_bge(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if ((int64_t)R(rs1) >= (int64_t)R(rs2))
        s->npc = s->pc + imm;
}

void exec_bgeu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (R(rs1) >= R(rs2))
        s->npc = s->pc + imm;
}

void exec_blt(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if ((int64_t)R(rs1) < (int64_t)R(rs2))
        s->npc = s->pc + imm;
}

void exec_bltu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (R(rs1) < R(rs2))
        s->npc = s->pc + imm;
}

void exec_bne(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (R(rs1) != R(rs2))
        s->npc = s->pc + imm;
}

void exec_fence(rv_insn_t *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_fence_i(rv_insn_t *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_jal(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = s->pc + 4;
    s->npc = s->pc + imm;
}

void exec_jalr(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = s->pc + 4;
    s->npc = (R(rs1) + imm) & ~1ULL;
    R(rd) = t;
}

void exec_lb(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint8_t, b, 8);
}

void exec_lbu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint8_t, b, 8);
}

void exec_ld(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint64_t, d, 64);
}

void exec_lh(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint16_t, s, 16);
}

void exec_lhu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint16_t, s, 16);
}

void exec_lui(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(imm, 31, 12) << 12, 32);
}

void exec_lw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint32_t, w, 32);
}

void exec_lwu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint32_t, w, 32);
}

void exec_or(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) | R(rs2);
}

void exec_ori(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) | imm;
}

void exec_sb(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_b(R(rs1) + imm, R(rs2));
}

void exec_sd(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, R(rs2));
}

void exec_sh(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_s(R(rs1) + imm, R(rs2));
}

void exec_sll(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) << BITS(R(rs2), 5, 0);
}

void exec_slli(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) << BITS(imm, 5, 0);
}

void exec_slliw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1), 31, 0) << BITS(imm, 4, 0), 32);
}

void exec_sllw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT((uint32_t)BITS(R(rs1), 31, 0) << (BITS(R(rs2), 4, 0)), 32);
}

void exec_slt(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) < (int64_t)R(rs2);
}

void exec_slti(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) < (int64_t)imm;
}

void exec_sltiu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) < imm;
}

void exec_sltu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) < R(rs2);
}

void exec_sra(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) >> BITS(R(rs2), 5, 0);
}

void exec_srai(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rs1) >> BITS(imm, 5, 0);
}

void exec_sraiw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT((int32_t)(BITS(R(rs1), 31, 0)) >> BITS(imm, 4, 0), 32);
}

void exec_sraw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT((int32_t)(BITS(R(rs1), 31, 0)) >> BITS(R(rs2), 4, 0), 32);
}

void exec_srl(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) >> BITS(R(rs2), 5, 0);
}

void exec_srli(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) >> BITS(imm, 5, 0);
}

void exec_srliw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1), 31, 0) >> BITS(imm, 4, 0), 32);
}

void exec_srlw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1), 31, 0) >> BITS(R(rs2), 4, 0), 32);
}

void exec_sub(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) - R(rs2);
}

void exec_subw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) - R(rs2), 31, 0), 32);
}

void exec_sw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(rs1) + imm, BITS(R(rs2), 31, 0));
}

void exec_xor(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) ^ R(rs2);
}

void exec_xori(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) ^ imm;
}

void exec_csrrc(rv_insn_t *s) {
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

void exec_csrrci(rv_insn_t *s) {
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

void exec_csrrs(rv_insn_t *s) {
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

void exec_csrrsi(rv_insn_t *s) {
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

void exec_csrrw(rv_insn_t *s) {
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

void exec_csrrwi(rv_insn_t *s) {
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

void exec_ebreak(rv_insn_t *s) {
    EXTRACT_OPRAND();
    cpu_raise_exception(CAUSE_BREAKPOINT, s->pc);
}

void exec_ecall(rv_insn_t *s) {
    EXTRACT_OPRAND();
    switch (rv.privilege) {
        case PRIV_M: cpu_raise_exception(CAUSE_MACHINE_ECALL, s->pc); break;
        case PRIV_S: cpu_raise_exception(CAUSE_SUPERVISOR_ECALL, s->pc); break;
        case PRIV_U: cpu_raise_exception(CAUSE_USER_ECALL, s->pc); break;
        default: __UNREACHABLE;
    }
}

void exec_mret(rv_insn_t *s) {
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

void exec_sfence_vma(rv_insn_t *s) {
    EXTRACT_OPRAND();
    // TODO: TLB
}

void exec_sret(rv_insn_t *s) {
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

void exec_wfi(rv_insn_t *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_div(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely((int64_t)R(rs2) == 0))
        R(rd) = ~0ULL;
    else if (unlikely((int64_t)R(rs1) == INT64_MIN && (int64_t)R(rs2) == -1))
        R(rd) = (int64_t)R(rs1);
    else
        R(rd) = (int64_t)R(rs1) / (int64_t)R(rs2);
}

void exec_divu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(R(rs2) == 0))
        R(rd) = ~0ULL;
    else
        R(rd) = R(rs1) / R(rs2);
}

void exec_divuw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t v1 = BITS(R(rs1), 31, 0);
    uint32_t v2 = BITS(R(rs2), 31, 0);
    if (unlikely(v2 == 0))
        R(rd) = ~0ULL;
    else
        R(rd) = SEXT(v1 / v2, 32);
}

void exec_divw(rv_insn_t *s) {
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

void exec_mul(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = R(rs1) * R(rs2);
}

void exec_mulh(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) =
        (int64_t)(((__int128_t)(int64_t)R(rs1) * (__int128_t)(int64_t)R(rs2)) >>
                  64);
}

void exec_mulhsu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) =
        (int64_t)(((__int128_t)(int64_t)R(rs1) * (__uint128_t)R(rs2)) >> 64);
}

void exec_mulhu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = (uint64_t)((__uint128_t)R(rs1) * (__uint128_t)R(rs2) >> 64);
}

void exec_mulw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rs1) * R(rs2), 31, 0), 32);
}

void exec_rem(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely((int64_t)R(rs2) == 0))
        R(rd) = (int64_t)R(rs1);
    else if (unlikely((int64_t)R(rs1) == INT64_MIN && (int64_t)R(rs2) == -1))
        R(rd) = 0; // overflow case: remainder is 0
    else
        R(rd) = (int64_t)R(rs1) % (int64_t)R(rs2);
}

void exec_remu(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(R(rs2) == 0))
        R(rd) = R(rs1);
    else
        R(rd) = R(rs1) % R(rs2);
}

void exec_remuw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t v1 = BITS(R(rs1), 31, 0);
    uint32_t v2 = BITS(R(rs2), 31, 0);
    if (unlikely(v2 == 0))
        R(rd) = SEXT(v1, 32);
    else
        R(rd) = SEXT(v1 % v2, 32);
}

void exec_remw(rv_insn_t *s) {
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

void exec_lr_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t v = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = v;
        rv.reservation_address = R(rs1);
        rv.reservation_valid = true;
    }
}

void exec_lr_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t v = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = SEXT(v, 32);
        rv.reservation_address = R(rs1);
        rv.reservation_valid = true;
    }
}

void exec_sc_d(rv_insn_t *s) {
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

void exec_sc_w(rv_insn_t *s) {
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

void exec_amoadd_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t + (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoadd_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t + (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoand_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t & (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoand_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t & (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoor_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t | (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoor_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t | (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoxor_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), (int64_t)t ^ (int64_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoxor_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), (int32_t)t ^ (int32_t)R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amomax_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MAX((int64_t)t, (int64_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amomax_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MAX((int32_t)t, (int32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amomaxu_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MAX(t, R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amomaxu_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MAX((uint32_t)t, (uint32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amomin_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MIN((int64_t)t, (int64_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amomin_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MIN((int32_t)t, (int32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amominu_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), MIN(t, R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amominu_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), MIN((uint32_t)t, (uint32_t)R(rs2)));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_amoswap_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t t = vaddr_read_d(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_d(R(rs1), R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = t;
    }
}

void exec_amoswap_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t t = vaddr_read_w(R(rs1));
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        vaddr_write_w(R(rs1), R(rs2));
        if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
            R(rd) = SEXT(t, 32);
    }
}

void exec_flw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint32_t val = vaddr_read_w(R(rs1) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        fpr_write32(&F(rd), (float32_t){val});
}

void exec_fsw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(rs1) + imm, (uint32_t)F(rs2).v);
}

void exec_fadd_s(rv_insn_t *s) {
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

void exec_fsub_s(rv_insn_t *s) {
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

void exec_fmul_s(rv_insn_t *s) {
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

void exec_fdiv_s(rv_insn_t *s) {
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

void exec_fsqrt_s(rv_insn_t *s) {
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

void exec_fsgnj_s(rv_insn_t *s) {
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

void exec_fsgnjn_s(rv_insn_t *s) {
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

void exec_fsgnjx_s(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float32_t f1 = fpr_get_f32(F(rs1));
        float32_t f2 = fpr_get_f32(F(rs2));
        fpr_write32(&F(rd), (float32_t){f1.v ^ (f2.v & F32_SIGN)});
        FP_SET_DIRTY();
    }
}

void exec_fmin_s(rv_insn_t *s) {
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

void exec_fmax_s(rv_insn_t *s) {
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

void exec_fcvt_w_s(rv_insn_t *s) {
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

void exec_fcvt_wu_s(rv_insn_t *s) {
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

void exec_fcvt_l_s(rv_insn_t *s) {
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

void exec_fcvt_lu_s(rv_insn_t *s) {
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

void exec_fcvt_s_w(rv_insn_t *s) {
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

void exec_fcvt_s_wu(rv_insn_t *s) {
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

void exec_fcvt_s_l(rv_insn_t *s) {
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

void exec_fcvt_s_lu(rv_insn_t *s) {
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

void exec_fmv_x_w(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = (int64_t)(int32_t)(uint32_t)F(rs1).v;
}

void exec_fmv_w_x(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        fpr_write32(&F(rd), (float32_t){(uint32_t)((int32_t)R(rs1))});
        FP_SET_DIRTY();
    }
}

void exec_fclass_s(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = (int64_t)(int32_t)f32_classify(fpr_get_f32(F(rs1)));
}

void exec_feq_s(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f32_eq(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_flt_s(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f32_lt(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fle_s(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f32_le(fpr_get_f32(F(rs1)), fpr_get_f32(F(rs2)));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fmadd_s(rv_insn_t *s) {
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

void exec_fmsub_s(rv_insn_t *s) {
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

void exec_fnmsub_s(rv_insn_t *s) {
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

void exec_fnmadd_s(rv_insn_t *s) {
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

void exec_fld(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t val = vaddr_read_d(R(rs1) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        F(rd) = (float64_t){val};
}

void exec_fsd(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, F(rs2).v);
}

void exec_fadd_d(rv_insn_t *s) {
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

void exec_fsub_d(rv_insn_t *s) {
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

void exec_fmul_d(rv_insn_t *s) {
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

void exec_fdiv_d(rv_insn_t *s) {
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

void exec_fsqrt_d(rv_insn_t *s) {
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

void exec_fsgnj_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float64_t f1 = F(rs1), f2 = F(rs2);
        F(rd) = (float64_t){(f1.v & ~F64_SIGN) | (f2.v & F64_SIGN)};
        FP_SET_DIRTY();
    }
}

void exec_fsgnjn_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float64_t f1 = F(rs1), f2 = F(rs2);
        F(rd) = (float64_t){(f1.v & ~F64_SIGN) | (~f2.v & F64_SIGN)};
        FP_SET_DIRTY();
    }
}

void exec_fsgnjx_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        float64_t f1 = F(rs1), f2 = F(rs2);
        F(rd) = (float64_t){f1.v ^ (f2.v & F64_SIGN)};
        FP_SET_DIRTY();
    }
}

void exec_fmin_d(rv_insn_t *s) {
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

void exec_fmax_d(rv_insn_t *s) {
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

void exec_fcvt_w_d(rv_insn_t *s) {
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

void exec_fcvt_wu_d(rv_insn_t *s) {
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

void exec_fcvt_l_d(rv_insn_t *s) {
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

void exec_fcvt_lu_d(rv_insn_t *s) {
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

void exec_fcvt_d_w(rv_insn_t *s) {
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

void exec_fcvt_d_wu(rv_insn_t *s) {
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

void exec_fcvt_d_l(rv_insn_t *s) {
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

void exec_fcvt_d_lu(rv_insn_t *s) {
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

void exec_fcvt_s_d(rv_insn_t *s) {
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

void exec_fcvt_d_s(rv_insn_t *s) {
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

void exec_fmv_x_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = F(rs1).v;
}

void exec_fmv_d_x(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        F(rd) = (float64_t){R(rs1)};
        FP_SET_DIRTY();
    }
}

void exec_fclass_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        R(rd) = (int64_t)f64_classify(F(rs1));
}

void exec_feq_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f64_eq(F(rs1), F(rs2));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_flt_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f64_lt(F(rs1), F(rs2));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fle_d(rv_insn_t *s) {
    EXTRACT_OPRAND();
    FP_INST_PREP();
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        R(rd) = f64_le(F(rs1), F(rs2));
        FP_UPDATE_EXCEPTION_FLAGS();
    }
}

void exec_fmadd_d(rv_insn_t *s) {
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

void exec_fmsub_d(rv_insn_t *s) {
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

void exec_fnmsub_d(rv_insn_t *s) {
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

void exec_fnmadd_d(rv_insn_t *s) {
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

void exec_c_nop(rv_insn_t *s) {
    EXTRACT_OPRAND();
    /* nop */
}

void exec_c_addi(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) += imm;
}

void exec_c_addiw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rd) + imm, 31, 0), 32);
}

void exec_c_li(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = imm;
}

void exec_c_addi16sp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(imm == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(2) += imm;
}

void exec_c_lui(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(rd == 2 || imm == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(rd) = imm;
}

void exec_c_srli(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) >>= imm;
}

void exec_c_srai(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = (int64_t)R(rd) >> imm;
}

void exec_c_andi(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) &= imm;
}

void exec_c_sub(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) -= R(rs2);
}

void exec_c_xor(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) ^= R(rs2);
}

void exec_c_or(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) |= R(rs2);
}

void exec_c_and(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) &= R(rs2);
}

void exec_c_subw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rd) - R(rs2), 31, 0), 32);
}

void exec_c_addw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) = SEXT(BITS(R(rd) + R(rs2), 31, 0), 32);
}

void exec_c_j(rv_insn_t *s) {
    EXTRACT_OPRAND();
    s->npc = s->pc + imm;
}

void exec_c_beqz(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (R(rs1) == 0)
        s->npc = s->pc + imm;
}

void exec_c_bnez(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (R(rs1) != 0)
        s->npc = s->pc + imm;
}

void exec_c_inv(rv_insn_t *s) {
    EXTRACT_OPRAND();
    exec_inv(s);
}

void exec_c_addi4spn(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(imm == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(rd) = R(2) + imm;
}

void exec_c_fld(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t val = vaddr_read_d(R(rs1) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        F(rd) = (float64_t){val};
}

void exec_c_lw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD_SEXT(rd, R(rs1) + imm, uint32_t, w, 32);
}

void exec_c_ld(rv_insn_t *s) {
    EXTRACT_OPRAND();
    LOAD(rd, R(rs1) + imm, uint64_t, d, 64);
}

void exec_c_fsd(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, F(rs2).v);
}

void exec_c_sw(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(rs1) + imm, BITS(R(rs2), 31, 0));
}

void exec_c_sd(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(rs1) + imm, R(rs2));
}

void exec_c_slli(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) <<= imm;
}

void exec_c_fldsp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    uint64_t val = vaddr_read_d(R(2) + imm);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE))
        F(rd) = (float64_t){val};
}

void exec_c_lwsp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(rd == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        LOAD_SEXT(rd, R(2) + imm, uint32_t, w, 32);
}

void exec_c_ldsp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(rd == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        LOAD(rd, R(2) + imm, uint64_t, d, 64);
}

void exec_c_jr(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(rs1 == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        s->npc = R(rs1) & ~1ULL;
}

void exec_c_mv(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(rs2 == 0))
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    else
        R(rd) = R(rs2);
}

void exec_c_ebreak(rv_insn_t *s) {
    EXTRACT_OPRAND();
    exec_ebreak(s);
}

void exec_c_jalr(rv_insn_t *s) {
    EXTRACT_OPRAND();
    if (unlikely(rs1 == 0)) {
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
    } else {
        uint64_t t = s->pc + 2;
        s->npc = R(rs1) & ~1ULL;
        R(1) = t;
    }
}

void exec_c_add(rv_insn_t *s) {
    EXTRACT_OPRAND();
    R(rd) += R(rs2);
}

void exec_c_fsdsp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(2) + imm, F(rs2).v);
}

void exec_c_swsp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_w(R(2) + imm, BITS(R(rs2), 31, 0));
}

void exec_c_sdsp(rv_insn_t *s) {
    EXTRACT_OPRAND();
    vaddr_write_d(R(2) + imm, R(rs2));
}

void exec_inv(rv_insn_t *s) {
    EXTRACT_OPRAND();
    cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, s->inst);
}
