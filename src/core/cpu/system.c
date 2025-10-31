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

#include "core/cpu/csr.h"
#include "core/cpu/system.h"
#include "core/riscv.h"

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

void cpu_process_intr(interrupt_t intr) {
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

interrupt_t cpu_get_pending_intr() {
    pthread_mutex_lock(&rv.csr_lock);
    uint64_t m_pending = cpu_read_csr(CSR_MIE) & cpu_read_csr(CSR_MIP) &
                         ~cpu_read_csr(CSR_MIDELEG);
    uint64_t s_pending = cpu_read_csr(CSR_SIE) & cpu_read_csr(CSR_SIP);
    pthread_mutex_unlock(&rv.csr_lock);

    uint64_t pending = 0;
    switch (rv.privilege) {
        case PRIV_M:
            if (cpu_read_csr(CSR_MSTATUS) & MSTATUS_MIE)
                pending = m_pending;
            break;
        case PRIV_S:
            if (cpu_read_csr(CSR_MSTATUS) & MSTATUS_MIE)
                pending = m_pending;
            else if (cpu_read_csr(CSR_SSTATUS) & SSTATUS_SIE)
                pending = s_pending;
            break;
        case PRIV_U: break;
    }

    if (pending == 0)
        return CAUSE_INTERRUPT_NONE;

    // External
    if (pending & MIP_MEIP)
        return CAUSE_MACHINE_EXTERNAL;
    if (pending & SIP_SEIP)
        return CAUSE_SUPERVISOR_EXTERNAL;

    // Software
    if (pending & MIP_MSIP)
        return CAUSE_MACHINE_SOFTWARE;
    if (pending & SIP_SSIP)
        return CAUSE_SUPERVISOR_SOFTWARE;

    // Timer
    if (pending & MIP_MTIP)
        return CAUSE_MACHINE_TIMER;
    if (pending & SIP_STIP)
        return CAUSE_SUPERVISOR_TIMER;

    return CAUSE_INTERRUPT_NONE;
}

void cpu_raise_intr(uint64_t ip, privilege_level_t priv) {
    pthread_mutex_lock(&rv.csr_lock);
    if (priv == PRIV_M)
        rv.MIP |= ip;
    else if (priv == PRIV_S)
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
