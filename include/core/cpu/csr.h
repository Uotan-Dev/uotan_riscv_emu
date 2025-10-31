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

#include <stdbool.h>
#include <stdint.h>

#include "../../common.h"

#define MVENDORID_DEFAULT                                                      \
    UINT64_C(0x00000000)                     // 0 = unspecified / non-commercial
#define MARCHID_DEFAULT UINT64_C(0x00114514) // Magic number for homo
#define MIMPID_DEFAULT UINT64_C(0x00010000)  // Follows UEMU version

// MISA
#define MISA_SUPER (1ULL << ('S' - 'A'))
#define MISA_USER (1ULL << ('U' - 'A'))
#define MISA_I (1ULL << ('I' - 'A'))
#define MISA_E (1ULL << ('E' - 'A'))
#define MISA_M (1ULL << ('M' - 'A'))
#define MISA_A (1ULL << ('A' - 'A'))
#define MISA_F (1ULL << ('F' - 'A'))
#define MISA_D (1ULL << ('D' - 'A'))
#define MISA_C (1ULL << ('C' - 'A'))
#define MISA_XLEN_64 (2ULL << 62)

// MSTATUS
#define MSTATUS_SIE_SHIFT 1
#define MSTATUS_MIE_SHIFT 3
#define MSTATUS_SPIE_SHIFT 5
#define MSTATUS_UBE_SHIFT 6
#define MSTATUS_MPIE_SHIFT 7
#define MSTATUS_SPP_SHIFT 8
#define MSTATUS_MPP_SHIFT 11
#define MSTATUS_FS_SHIFT 13
#define MSTATUS_XS_SHIFT 15
#define MSTATUS_MPRV_SHIFT 17
#define MSTATUS_SUM_SHIFT 18
#define MSTATUS_MXR_SHIFT 19
#define MSTATUS_TVM_SHIFT 20
#define MSTATUS_TW_SHIFT 21
#define MSTATUS_TSR_SHIFT 22
#define MSTATUS_UXL_SHIFT 32
#define MSTATUS_SD_SHIFT 63
#define MSTATUS_SIE (1ULL << MSTATUS_SIE_SHIFT)
#define MSTATUS_MIE (1ULL << MSTATUS_MIE_SHIFT)
#define MSTATUS_SPIE (1ULL << MSTATUS_SPIE_SHIFT)
#define MSTATUS_UBE (1ULL << MSTATUS_UBE_SHIFT)
#define MSTATUS_MPIE (1ULL << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP (1ULL << MSTATUS_SPP_SHIFT)
#define MSTATUS_MPP (3ULL << MSTATUS_MPP_SHIFT)
#define MSTATUS_FS (3ULL << MSTATUS_FS_SHIFT)
#define MSTATUS_XS (3ULL << MSTATUS_XS_SHIFT)
#define MSTATUS_MPRV (1ULL << MSTATUS_MPRV_SHIFT)
#define MSTATUS_SUM (1ULL << MSTATUS_SUM_SHIFT)
#define MSTATUS_MXR (1ULL << MSTATUS_MXR_SHIFT)
#define MSTATUS_TVM (1ULL << MSTATUS_TVM_SHIFT)
#define MSTATUS_TW (1ULL << MSTATUS_TW_SHIFT)
#define MSTATUS_TSR (1ULL << MSTATUS_TSR_SHIFT)
#define MSTATUS_UXL (3ULL << MSTATUS_UXL_SHIFT)
#define MSTATUS_SD (1ULL << MSTATUS_SD_SHIFT)

// MIP
#define MIP_MSIP (1ULL << 3)
#define MIP_MTIP (1ULL << 7)
#define MIP_MEIP (1ULL << 11)

// MIE
#define MIE_MSIE (1ULL << 3)
#define MIE_MTIE (1ULL << 7)
#define MIE_MEIE (1ULL << 11)

// MCOUNTEREN
#define MCOUNTEREN_CY (1U << 0)
#define MCOUNTEREN_TM (1U << 1)
#define MCOUNTEREN_IR (1U << 2)

// MENVCFG
#define MENVCFG_FIOM (1ULL << 0)
#define MENVCFG_ADUE (1ULL << 61)
#define MENVCFG_STCE (1ULL << 63)
#define MENVCFG_MASK (MENVCFG_FIOM | MENVCFG_ADUE | MENVCFG_STCE)

// MSECCFG
#define MSECCFG_MML (1ULL << 0)   // Machine Mode Lockdown
#define MSECCFG_MMWP (1ULL << 1)  // Machine Mode Whitelist Policy
#define MSECCFG_RLB (1ULL << 2)   // Rule Locking Bypass
#define MSECCFG_USEED (1ULL << 8) // User seed access
#define MSECCFG_SSEED (1ULL << 9) // Supervisor seed access

// SSTATUS
#define SSTATUS_SIE_SHIFT 1
#define SSTATUS_SPIE_SHIFT 5
#define SSTATUS_UBE_SHIFT 6
#define SSTATUS_SPP_SHIFT 8
#define SSTATUS_FS_SHIFT 13
#define SSTATUS_XS_SHIFT 15
#define SSTATUS_SUM_SHIFT 18
#define SSTATUS_MXR_SHIFT 19
#define SSTATUS_SD_SHIFT 63
#define SSTATUS_SIE (1ULL << SSTATUS_SIE_SHIFT)
#define SSTATUS_SPIE (1ULL << SSTATUS_SPIE_SHIFT)
#define SSTATUS_UBE (1ULL << SSTATUS_UBE_SHIFT)
#define SSTATUS_SPP (1ULL << SSTATUS_SPP_SHIFT)
#define SSTATUS_FS (3ULL << SSTATUS_FS_SHIFT)
#define SSTATUS_XS (3ULL << SSTATUS_XS_SHIFT)
#define SSTATUS_SUM (1ULL << SSTATUS_SUM_SHIFT)
#define SSTATUS_MXR (1ULL << SSTATUS_MXR_SHIFT)
#define SSTATUS_SD (1ULL << SSTATUS_SD_SHIFT)
#define SSTATUS_MASK                                                           \
    (MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_UBE | MSTATUS_SPP | MSTATUS_FS |     \
     MSTATUS_XS | MSTATUS_SUM | MSTATUS_MXR | MSTATUS_UXL | MSTATUS_SD)

// SIP
#define SIP_SSIP (1ULL << 1)
#define SIP_STIP (1ULL << 5)
#define SIP_SEIP (1ULL << 9)

// SIE
#define SIE_SSIE (1ULL << 1)
#define SIE_STIE (1ULL << 5)
#define SIE_SEIE (1ULL << 9)

// SATP
#define SATP_MODE_SHIFT 60
#define SATP_ASID_SHIFT 44
#define SATP_PPN_SHIFT 0
#define SATP_PPN_MASK (((1ULL << 44) - 1) << SATP_PPN_SHIFT)
#define SATP_ASID_MASK (((1ULL << 16) - 1) << SATP_ASID_SHIFT)
#define SATP_MODE_MASK ((15ULL) << SATP_MODE_SHIFT) // 4 bits for mode
#define GET_SATP_MODE(satp) ((satp & SATP_MODE_MASK) >> SATP_MODE_SHIFT)
#define GET_SATP_ASID(satp) ((satp & SATP_ASID_MASK) >> SATP_ASID_SHIFT)
#define GET_SATP_PPN(satp) ((satp & SATP_PPN_MASK) >> SATP_PPN_SHIFT)

// SEED
#define SEED_OPST_BIST 0x00000000U
#define SEED_OPST_WAIT 0x00000001U
#define SEED_OPST_ES16 0x00000002U
#define SEED_OPST_DEAD 0x00000003U

enum {
    // Machine information registers
    CSR_MVENDORID = 0xF11, // Vendor ID
    CSR_MARCHID = 0xF12,   // Architecture ID
    CSR_MIMPID = 0xF13,    // Implementation ID
    CSR_MHARTID = 0xF14,   // Hardware thread ID

    // Machine trap setup
    CSR_MSTATUS = 0x300,    // Machine status register
    CSR_MISA = 0x301,       // ISA and extensions
    CSR_MEDELEG = 0x302,    // Machine exception delegate register
    CSR_MIDELEG = 0x303,    // Machine interrupt delegate register
    CSR_MIE = 0x304,        // Machine interrupt-enable register
    CSR_MTVEC = 0x305,      // Machine trap-handler base address
    CSR_MCOUNTEREN = 0x306, // Machine counter enable

    // Machine trap handling
    CSR_MSCRATCH = 0x340, // Scratch register for machine trap handlers
    CSR_MEPC = 0x341,     // Machine exception program counter
    CSR_MCAUSE = 0x342,   // Machine trap cause
    CSR_MTVAL = 0x343,    // Machine bad address or instruction
    CSR_MIP = 0x344,      // Machine interrupt pending

    // Machine Configuration
    CSR_MENVCFG = 0x30A, // Machine environment configuration register
    CSR_MSECCFG = 0x747, // Machine security configuration register

    // Machine Counter/Timers
    CSR_MCYCLE = 0xB00,   // Machine cycle counter
    CSR_MINSTRET = 0xB02, // Machine instructions-retired counter

    // Supervisor trap setup
    CSR_SSTATUS = 0x100,    // Supervisor status register
    CSR_SIE = 0x104,        // Supervisor interrupt-enable register
    CSR_STVEC = 0x105,      // Supervisor trap-handler base address
    CSR_SCOUNTEREN = 0x106, // Supervisor counter enable

    // Supervisor trap handling
    CSR_SSCRATCH = 0x140, // Supervisor register for machine trap handlers
    CSR_SEPC = 0x141,     // Supervisor exception program counter
    CSR_SCAUSE = 0x142,   // Supervisor trap cause
    CSR_STVAL = 0x143,    // Supervisor bad address or instruction
    CSR_SIP = 0x144,      // Supervisor interrupt pending

    // Supervisor Timer Compare
    CSR_STIMECMP = 0x14D, // Supervisor timer compare.

    // Supervisor protection and translation
    CSR_SATP = 0x180, // Supervisor address translation and protection

    // Unprivileged Counter/Timers
    CSR_CYCLE = 0xC00, // Cycle counter for RDCYCLE instruction
    CSR_TIME = 0xC01,  // Timer for RDTIME instruction
    CSR_INSTRET =
        0xC02, // Instructions-retired counter for RDINSTRET instruction

    // Unprivileged Entropy Source Extension CSR
    CSR_SEED = 0x015, // Seed for cryptographic random bit generators

    // Unprivileged Floating-Point CSRs
    CSR_FFLAGS = 0x001, // Floating-Point Accrued Exceptions
    CSR_FRM = 0x002,    // Floating-Point Dynamic Rounding Mode
    CSR_FCSR =
        0x003, // Floating-Point Control and Status Register (frm +fflags)
};

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Checks if access to certain csr must trap
 *
 * @param csr  The CSR address (e.g., `CSR_MSTATUS`, `CSR_MEPC`, etc.).
 * @return  whether access to certain csr must trap
 */
FORCE_INLINE bool cpu_csr_trap_on_access(uint64_t csr) {
    csr &= 0xFFF;
    return (csr >= 0xC03 && csr <= 0xC1F)     // hpmcounter3 ~ hpmcounter31
           || csr == 0xda0                    // Sscofpmf not implemented
           || (csr == 0xfb0 || csr == 0x35c)  // Smaia not implemented
           || (csr >= 0x30C && csr <= 0x30F)  // mstateen not implemented
           || (csr >= 0x10C && csr <= 0x10F)  // stateen not implemented
           || (csr == 0x321 || csr == 0x322)  // smcntrpmf not implemented
           || (csr >= 0x7a0 && csr <= 0x7a4); // sdtrig not implemented
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
uint64_t cpu_read_csr(uint64_t csr);

/**
 * @brief Writes the value of a control and status register (CSR).
 *
 * This function should only be used during instruction execution or
 * when simulating CSR read operations.
 *
 * @param csr  The CSR address (e.g., `CSR_MSTATUS`, `CSR_MEPC`, etc.).
 * @param value The value to be assigned to the register.
 */
void cpu_write_csr(uint64_t csr, uint64_t value);

#ifdef __cplusplus
}
#endif
