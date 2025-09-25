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

#include "../device/bus.h"
#include "decode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESET_PC 0x80000000

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

enum {
    // Machine information registers
    CSR_MVENDORID = 0xF11, // Vendor ID
    CSR_MARCHID = 0xF12,   // Architecture ID
    CSR_MIMPID = 0xF13,    // Implementation ID
    CSR_MHARTID = 0xF14,   // Hardware thread ID

    // Machine trap setup
    CSR_MSTATUS = 0x300, // Machine status register
    CSR_MISA = 0x301,    // ISA and extensions
    CSR_MEDELEG = 0x302, // Machine exception delegate register
    CSR_MIDELEG = 0x303, // Machine interrupt delegate register
    CSR_MIE = 0x304,     // Machine interrupt-enable register
    CSR_MTVEC = 0x305,   // Machine trap-handler base address

    // Machine trap handling
    CSR_MSCRATCH = 0x340, // Scratch register for machine trap handlers
    CSR_MEPC = 0x341,     // Machine exception program counter
    CSR_MCAUSE = 0x342,   // Machine trap cause
    CSR_MTVAL = 0x343,    // Machine bad address or instruction
    CSR_MIP = 0x344,      // Machine interrupt pending

    // Supervisor trap setup
    CSR_SSTATUS = 0x100, // Supervisor status register
    CSR_SIE = 0x104,     // Supervisor interrupt-enable register
    CSR_STVEC = 0x105,   // Supervisor trap-handler base address

    // Supervisor trap handling
    CSR_SSCRATCH = 0x140, // Supervisor register for machine trap handlers
    CSR_SEPC = 0x141,     // Supervisor exception program counter
    CSR_SCAUSE = 0x142,   // Supervisor trap cause
    CSR_STVAL = 0x143,    // Supervisor bad address or instruction
    CSR_SIP = 0x144,      // Supervisor interrupt pending

    // Supervisor protection and translation
    CSR_SATP = 0x180, // Supervisor address translation and protection
};

typedef enum : int {
    SHUTDOWN_CAUSE_GUEST_PANIC,
    SHUTDOWN_CAUSE_GUEST_SHUTDOWN
} shutdown_cause_t;

typedef struct {
    // Interger registers
#define NR_GPR 32
    uint64_t X[NR_GPR];

    // Program counter
    uint64_t PC;

    // Control and Status registers
    // Instruction implementations should not write these fields directly, see
    // include/core/cpu.h for a set of valid functions
#define NR_CSR 4096

    uint64_t MVENDORID; // Vendor ID
    uint64_t MARCHID;   // Architecture ID
    uint64_t MIMPID;    // Implementation ID
    uint64_t MHARTID;   // Hardware thread ID
    uint64_t MSTATUS;   // Machine status register
    uint64_t MISA;      // ISA and extensions
    uint64_t MEDELEG;   // Machine exception delegate register
    uint64_t MIDELEG;   // Machine interrupt delegate register
    uint64_t MIE;       // Machine interrupt-enable register
    uint64_t MTVEC;     // Machine trap-handler base address
    uint64_t MSCRATCH;  // Scratch register for machine trap handlers
    uint64_t MEPC;      // Machine exception program counter
    uint64_t MCAUSE;    // Machine trap cause
    uint64_t MTVAL;     // Machine bad address or instruction
    uint64_t MIP;       // Machine interrupt pending

    // SSTATUS, SIE, SIP are commented out because they will be inferred
    // from M-mode CSRs

    // uint64_t SSTATUS;  // Supervisor status register
    // uint64_t SIE;      // Supervisor interrupt-enable register
    uint64_t STVEC;    // Supervisor trap-handler base address
    uint64_t SSCRATCH; // Supervisor register for machine trap handlers
    uint64_t SEPC;     // Supervisor exception program counter
    uint64_t SCAUSE;   // Supervisor trap cause
    uint64_t STVAL;    // Supervisor bad address or instruction
    // uint64_t SIP;      // Supervisor interrupt pending
    uint64_t SATP; // Supervisor address translation and protection

    // Privilege level
    privilege_level_t privilege;

    // Last exception
    exception_t last_exception; // this is now only used in memory system

    // Memory
#define MSIZE 0x8000000
#define MBASE 0x80000000
    uint8_t memory[MSIZE] __attribute((aligned(4096)));

    // Decoder status
    Decode decode;

    // Bus status
    bus_t bus;

    // Misc
    bool shutdown;
    int shutdown_code;
    shutdown_cause_t shutdown_cause;
} riscv_t;

extern riscv_t rv __attribute((aligned(4096)));

// Initialize the machine
void rv_init(const void *buf, size_t buf_size);

// Add a device
void rv_add_device(device_t dev);

// Get an interrupt
interrupt_t rv_get_pending_interrupt();

// Shutdown the machine
void rv_shutdown(int code, shutdown_cause_t cause);

#ifdef __cplusplus
}
#endif
