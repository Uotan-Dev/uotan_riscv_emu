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

#pragma once

#include <assert.h>
#include <stdint.h>

#include "entropy.h"
#include "fpu.h"
#include "mem.h"
#include "riscv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Let the CPU step once.
 *
 * This function is usually for debugging and testing purposes.
 */
void cpu_step();

/**
 * @brief Starts normal CPU execution.
 *
 * This function enters the main execution loop and only returns when the
 * machine is shut down by the SiFive test mechanism.
 */
void cpu_start();

/**
 * @brief Starts CPU execution for riscv-arch-test.
 *
 * This function enters the main execution loop and only returns when it has
 * reached the time limit.
 */
void cpu_start_archtest();

/**
 * @brief Prints the state of registers.
 */
void cpu_print_registers();

/**
 * @brief Raise (set) a machine interrupt pending bit in CSR_MIP.
 *
 * This function is used by interrupt controllers (such as CLINT or PLIC)
 * to notify the CPU that an interrupt source has become pending.
 *
 * @details
 * - Each bit in the MIP CSR corresponds to a different interrupt source:
 *   - MIP_MSIP  (bit 3): Machine software interrupt
 *   - MIP_MTIP  (bit 7): Machine timer interrupt
 *   - MIP_MEIP  (bit 11): Machine external interrupt
 *   - Other bits may be implementation-defined.
 *
 * - Calling this function will atomically set the bits specified by `ip`
 *   in the MIP CSR, without affecting other bits.
 *
 * - This function internally locks the CSR subsystem to ensure thread-safety,
 *   since PLIC and CLINT may raise interrupts concurrently in multi-threaded
 *   simulation environments.
 *
 * @param ip Bitmask corresponding to one or more interrupt-pending bits
 *           (e.g. MIP_MSIP, MIP_MTIP, MIP_MEIP).
 * @param priv Privilege level for the target CSR.
 *
 * @note
 * - Typically invoked by CLINT (for MSIP/MTIP) and PLIC (for MEIP).
 * - This only marks the interrupt as pending; whether it actually traps
 *   depends on MIE/MSTATUS enable bits and the current privilege level.
 * - Should never be called from within the CPU core without proper locking,
 *   as it directly modifies interrupt state visible to privileged code.
 */
void cpu_raise_intr(uint64_t ip, privilege_level_t priv);

/**
 * @brief Clear (unset) a machine interrupt pending bit in CSR_MIP.
 *
 * This function clears specific interrupt-pending bits in the MIP CSR.
 * It is the logical counterpart of `cpu_raise_intr()`.
 *
 * @details
 * - Each bit in MIP represents whether a corresponding interrupt source
 *   is pending; clearing it means that interrupt source is no longer active.
 *
 * - This function performs a read–modify–write on the MIP CSR under lock,
 *   ensuring atomicity and thread safety.
 *
 * @param ip Bitmask corresponding to one or more interrupt-pending bits
 *           (e.g. MIP_MSIP, MIP_MTIP, MIP_MEIP).
 * @param priv Privilege level for the target CSR.
 *
 * @note
 * - Typically used by CLINT (when timer has been reset or MSIP cleared)
 *   or by PLIC (after an interrupt has been acknowledged and completed).
 * - Does not modify interrupt enable state (MIE); it only updates the
 *   pending bits.
 * - Internal locking ensures consistency across concurrent device updates.
 */
void cpu_clear_intr(uint64_t ip, privilege_level_t priv);

/**
 * @brief Raises a CPU exception.
 *
 * This function triggers an exception with the given cause and trap value. It
 * should only be called inside a CPU loop.
 *
 * @param cause  The exception cause.
 * @param tval   The trap value associated with the exception (e.g., faulting
 * address or instruction).
 */
void cpu_raise_exception(exception_t cause, uint64_t tval);

/**
 * @brief Judges whether current CSR must be locked before accessing.
 *
 * @param csr  The CSR address.
 * @return  The result indicating whether current CSR must be locked before
 * accessing.
 */
FORCE_INLINE bool cpu_csr_need_lock(uint64_t csr) {
    csr &= 0xFFF;
    return csr == CSR_MIP || csr == CSR_SIP || csr == CSR_TIME;
}

/**
 * @brief Reads the value of a control and status register (CSR).
 *
 * This function retrieves the current value of the specified CSR from the
 * simulated CPU state. It should only be used during instruction execution or
 * when simulating CSR read operations.
 *
 * @param csr  The CSR address (e.g., `CSR_MSTATUS`, `CSR_MEPC`, etc.).
 * @return The 64-bit value currently stored in the specified CSR.
 */
FORCE_INLINE uint64_t cpu_read_csr(uint64_t csr) {
    // clang-format off
#define macro(csr_name)                                                        \
    case CSR_##csr_name: return rv.csr_name;

    // hpmcounter3 ~ hpmcounter31
    if (unlikely(csr >= 0xC03 && csr <= 0xC1F)) {
        cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
        return 0;
    }

    switch (csr & 0xFFF) {
        // M-mode
        case CSR_MCOUNTEREN:
            return rv.MCOUNTEREN & (MCOUNTEREN_CY | MCOUNTEREN_TM | MCOUNTEREN_IR);
        case CSR_MIP:
            // csr_lock must be held here
            return rv.MIP;
        macro(MVENDORID) macro(MARCHID) macro(MIMPID) macro(MHARTID)
        macro(MISA) macro(MTVEC) macro(MSCRATCH) macro(MEPC) macro(MCAUSE)
        macro(MTVAL) macro(MIE) macro(MCYCLE) macro(MINSTRET) macro(MIDELEG)
        macro(MEDELEG) macro(MSTATUS)

        // S-mode
        case CSR_SSTATUS: return rv.MSTATUS & SSTATUS_MASK;
        case CSR_SIE: return rv.MIE & rv.MIDELEG;
        case CSR_SIP: {
            // csr_lock must be held here
            uint64_t r = rv.MIP;
            return r & rv.MIDELEG;
        }
        case CSR_SCOUNTEREN:
            return rv.SCOUNTEREN;
        macro(STVEC) macro(SSCRATCH) macro(SEPC) macro(SCAUSE) macro(STVAL)
        macro(SATP)

        // Unprivileged
        case CSR_CYCLE: {
            uint32_t counteren = 0xFFFFFFFFU;
            if (rv.privilege == PRIV_S)
                counteren &= rv.MCOUNTEREN;
            if (rv.privilege == PRIV_U)
                counteren = counteren & rv.MCOUNTEREN & rv.SCOUNTEREN;
            if (counteren & MCOUNTEREN_CY)
                return rv.MCYCLE;
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            return 0;
        }
        case CSR_TIME: {
            uint32_t counteren = 0xFFFFFFFFU;
            if (rv.privilege == PRIV_S)
                counteren &= rv.MCOUNTEREN;
            if (rv.privilege == PRIV_U)
                counteren = counteren & rv.MCOUNTEREN & rv.SCOUNTEREN;
            if (counteren & MCOUNTEREN_TM)
                return rv.MTIME; // csr_lock must be held here
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            return 0;
        }
        case CSR_INSTRET: {
            uint32_t counteren = 0xFFFFFFFFU;
            if (rv.privilege == PRIV_S)
                counteren &= rv.MCOUNTEREN;
            if (rv.privilege == PRIV_U)
                counteren = counteren & rv.MCOUNTEREN & rv.SCOUNTEREN;
            if (counteren & MCOUNTEREN_IR)
                return rv.MINSTRET;
            cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            return 0;
        }
        case CSR_SEED:
            if (!rv.seed_written) {
                // The seed CSR is always available in machine mode as normal (with a CSR
                // readwrite instruction.) Attempted read without a write raises an
                // illegal-instruction exception regardless of mode and access control bits.
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
                return 0;
            } else if (rv.privilege == PRIV_S && !(rv.MSECCFG & MSECCFG_SSEED)) {
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
                return 0;
            } else if (rv.privilege == PRIV_U && !(rv.MSECCFG & MSECCFG_USEED)) {
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
                return 0;
            }
            rv.seed_written = false;
            return (SEED_OPST_ES16 << 30) | generate_entropy();
        case CSR_FCSR:
            return rv.FCSR.value & FCSR_MASK;
        case CSR_FFLAGS:
            return rv.FCSR.fields.fflags;
        case CSR_FRM:
            return rv.FCSR.fields.frm;

        // CSR not implemented
        default: return 0;
    }

#undef macro
    // clang-format on
    __UNREACHABLE;
}

/**
 * @brief Writes the value of a control and status register (CSR).
 *
 * This function should only be used during instruction execution or
 * when simulating CSR read operations.
 *
 * @param csr  The CSR address (e.g., `CSR_MSTATUS`, `CSR_MEPC`, etc.).
 * @param value The value to be assigned to the register.
 */
FORCE_INLINE void cpu_write_csr(uint64_t csr, uint64_t value) {
    // clang-format off
#define macro(csr_name)                                                        \
    case CSR_##csr_name: rv.csr_name = value; break;

    switch (csr & 0xFFF) {
        // M-mode
        case CSR_MEPC:
            rv.MEPC = value & ~3ULL;
            break; // support only IALIGN=32
        case CSR_MCOUNTEREN:
            rv.MCOUNTEREN = (uint32_t)(value & 0xFFFFFFFFU);
            break;
        case CSR_MINSTRET:
            rv.MINSTRET = value;
            rv.suppress_minstret_increase = true;
            break;
        case CSR_MIP:
            // csr_lock must be held here
            rv.MIP = value;
            break;
        macro(MTVEC) macro(MSCRATCH) macro(MCAUSE) macro(MTVAL) macro(MIE)
        macro(MSTATUS) macro(MCYCLE) macro(MSECCFG) macro(MIDELEG)
        macro(MEDELEG)

        // S-mode
        case CSR_SEPC:
            rv.SEPC = value & ~3ULL;
            break; // support only IALIGN=32
        case CSR_SATP: {
            // Implementations are not required to support all MODE settings,
            // and if satp is written with an unsupported MODE,
            // the entire write has no effect;
            // no fields in satp are modified.
            uint64_t mode = GET_SATP_MODE(value);
            if (mode == 0 || mode == SATP_MODE_SV39)
                rv.SATP = value;
            break;
        }
        case CSR_SSTATUS: {
            uint64_t v = (rv.MSTATUS & ~SSTATUS_MASK) | (value & SSTATUS_MASK);
            rv.MSTATUS = v;
            break;
        }
        case CSR_SIE: {
            uint64_t v = (rv.MIE & ~rv.MIDELEG) | (value & rv.MIDELEG);
            rv.MIE = v;
            break;
        }
        case CSR_SIP: {
            // csr_lock must be held here
            uint64_t v = (rv.MIP & ~rv.MIDELEG) | (value & rv.MIDELEG);
            rv.MIP = v;
            break;
        }
        case CSR_SCOUNTEREN:
            rv.SCOUNTEREN = (uint32_t)(value & 0xFFFFFFFFU);
            break;
        macro(STVEC) macro(SSCRATCH) macro(SCAUSE) macro(STVAL)

        // Unprivileged
        case CSR_CYCLE:
            if (value != rv.MCYCLE)
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            break;
        case CSR_INSTRET:
            if (value != rv.MINSTRET)
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            break;
        case CSR_TIME:
            // csr_lock must be held here
            if (value != rv.MTIME)
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
            break;
        case CSR_SEED:
            if (rv.privilege == PRIV_S && !(rv.MSECCFG & MSECCFG_SSEED)) {
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
                break;
            } else if (rv.privilege == PRIV_U && !(rv.MSECCFG & MSECCFG_USEED)) {
                cpu_raise_exception(CAUSE_ILLEGAL_INSTRUCTION, rv.decode.pc);
                break;
            }
            rv.seed_written = true;
            break;
        case CSR_FCSR:
            rv.FCSR.value = (rv.FCSR.value & ~FCSR_MASK) | (value & FCSR_MASK);
            break;
        case CSR_FFLAGS:
            rv.FCSR.fields.fflags = value;
            break;
        case CSR_FRM:
            rv.FCSR.fields.frm = value;
            break;

        // CSR not implemented
        default: break;
    }

#undef macro

    // clang-format on
}

#ifdef __cplusplus
}
#endif
