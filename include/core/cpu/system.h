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

#include <stdint.h>

// riscv privilege level
typedef enum : uint64_t {
    PRIV_U = 0, // User mode
    PRIV_S = 1, // Supervisor mode
    PRIV_M = 3  // Machine mode
} privilege_level_t;

// Exceptions
typedef enum : uint64_t {
    CAUSE_MISALIGNED_FETCH = 0,    // Instruction address misaligned
    CAUSE_FETCH_ACCESS = 1,        // Instruction access fault
    CAUSE_ILLEGAL_INSTRUCTION = 2, // Illegal instruction
    CAUSE_BREAKPOINT = 3,          // Breakpoint
    CAUSE_MISALIGNED_LOAD = 4,     // Load address misaligned
    CAUSE_LOAD_ACCESS = 5,         // Load access fault
    CAUSE_MISALIGNED_STORE = 6,    // Store/AMO address misaligned
    CAUSE_STORE_ACCESS = 7,        // Store/AMO access fault
    CAUSE_USER_ECALL = 8,          // Environment call from U-mode
    CAUSE_SUPERVISOR_ECALL = 9,    // Environment call from S-mode
    CAUSE_MACHINE_ECALL = 11,      // Environment call from M-mode
    CAUSE_INSN_PAGEFAULT = 12,     // Instruction page fault
    CAUSE_LOAD_PAGEFAULT = 13,     // Load page fault
    CAUSE_STORE_PAGEFAULT = 15,    // Store/AMO page fault

    CAUSE_EXCEPTION_NONE = ~0ULL
} exception_t;

// Interrupt
#define INTERRUPT_FLAG (1ULL << 63)

typedef enum : uint64_t {
    // Software interrupt
    CAUSE_SUPERVISOR_SOFTWARE = 1ULL | INTERRUPT_FLAG,
    CAUSE_MACHINE_SOFTWARE = 3ULL | INTERRUPT_FLAG,

    // Timer interrupt
    CAUSE_SUPERVISOR_TIMER = 5ULL | INTERRUPT_FLAG,
    CAUSE_MACHINE_TIMER = 7ULL | INTERRUPT_FLAG,

    // External interrupt
    CAUSE_SUPERVISOR_EXTERNAL = 9ULL | INTERRUPT_FLAG,
    CAUSE_MACHINE_EXTERNAL = 11ULL | INTERRUPT_FLAG,

    // Counter-overflow interrupt
    CAUSE_COUNTER_OVERFLOW = 13ULL | INTERRUPT_FLAG,

    CAUSE_INTERRUPT_NONE = ~0ULL
} interrupt_t;

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Gets a pending interruption.
 *
 * This function calculates and returns the interruption with highest priority.
 *
 * @return A 64-bit value indicating the interruption type.
 */
interrupt_t cpu_get_pending_intr();

/**
 * @brief Processes an interruption.
 *
 * This function should only be used during instruction execution.
 *
 * @param intr  The interruption number.
 */
void cpu_process_intr(interrupt_t intr);

/**
 * @brief Checks and processes an interruption at runtime.
 *
 * @param intr  true if an interruption has been proccessed or false if it
 * hasn't.
 */
bool cpu_check_and_process_intr();

#ifdef __cplusplus
}
#endif
