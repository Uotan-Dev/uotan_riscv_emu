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

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESET_PC 0x80000000

#define MVENDORID_DEFAULT                                                      \
    UINT64_C(0x00000000)                     // 0 = unspecified / non-commercial
#define MARCHID_DEFAULT UINT64_C(0x00114514) // Magic number for homo
#define MIMPID_DEFAULT UINT64_C(0x00010000)  // Follows UEMU version

#define MISA_SUPER (1 << ('S' - 'A'))
#define MISA_USER (1 << ('U' - 'A'))
#define MISA_I (1 << ('I' - 'A'))
#define MISA_E (1 << ('E' - 'A'))
#define MISA_M (1 << ('M' - 'A'))
#define MISA_A (1 << ('A' - 'A'))
#define MISA_F (1 << ('F' - 'A'))
#define MISA_C (1 << ('C' - 'A'))

// riscv privilege level
typedef enum {
    PRIV_U = 0, // User mode
    PRIV_S = 1, // Supervisor mode
    PRIV_M = 3  // Machine mode
} privilege_level_t;

// Exceptions
#define CAUSE_MISALIGNED_FETCH 0
#define CAUSE_FETCH_ACCESS 1
#define CAUSE_ILLEGAL_INSTRUCTION 2
#define CAUSE_BREAKPOINT 3
#define CAUSE_MISALIGNED_LOAD 4
#define CAUSE_LOAD_ACCESS 5
#define CAUSE_MISALIGNED_STORE 6
#define CAUSE_STORE_ACCESS 7
#define CAUSE_USER_ECALL 8
#define CAUSE_SUPERVISOR_ECALL 9
#define CAUSE_MACHINE_ECALL 11

// Interrupt
#define INTERRUPT_FLAG (1ULL << 63)
#define CAUSE_SOFTWARE_INTERRUPT (0 | INTERRUPT_FLAG)
#define CAUSE_TIMER_INTERRUPT (1 | INTERRUPT_FLAG)
#define CAUSE_EXTERNAL_INTERRUPT (2 | INTERRUPT_FLAG)

// The MSTATUS CSR
#define MSTATUS_SIE_SHIFT 1
#define MSTATUS_MIE_SHIFT 3
#define MSTATUS_SPIE_SHIFT 5
#define MSTATUS_UBE_SHIFT 6
#define MSTATUS_MPIE_SHIFT 7
#define MSTATUS_SPP_SHIFT 8
#define MSTATUS_MPP_SHIFT 11
#define MSTATUS_MPRV_SHIFT 17
#define MSTATUS_SUM_SHIFT 18
#define MSTATUS_MXR_SHIFT 18
#define MSTATUS_TVM_SHIFT 20
#define MSTATUS_TW_SHIFT 21
#define MSTATUS_TSR_SHIFT 22
#define MSTATUS_SIE (1 << MSTATUS_SIE_SHIFT)
#define MSTATUS_MIE (1 << MSTATUS_MIE_SHIFT)
#define MSTATUS_SPIE (1 << MSTATUS_SPIE_SHIFT)
#define MSTATUS_UBE (1 << MSTATUS_UBE_SHIFT)
#define MSTATUS_MPIE (1 << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP (1 << MSTATUS_SPP_SHIFT)
#define MSTATUS_MPP (3 << MSTATUS_MPP_SHIFT)
#define MSTATUS_MPRV (1 << MSTATUS_MPRV_SHIFT)
#define MSTATUS_SUM (1 << MSTATUS_SUM_SHIFT)
#define MSTATUS_MXR (1 << MSTATUS_MXR_SHIFT)
#define MSTATUS_TVM (1 << MSTATUS_TVM_SHIFT)
#define MSTATUS_TW (1 << MSTATUS_TW_SHIFT)
#define MSTATUS_TSR (1 << MSTATUS_TSR_SHIFT)

enum {
    // Machine information registers
    CSR_MVENDORID = 0xF11, // Vendor ID
    CSR_MARCHID = 0xF12,   // Architecture ID
    CSR_MIMPID = 0xF13,    // Implementation ID
    CSR_MHARTID = 0xF14,   // Hardware thread ID

    // Machine trap setup
    CSR_MSTATUS = 0x300, // Machine status register
    CSR_MISA = 0x301,    // ISA and extensions
    CSR_MTVEC = 0x305,   // Machine trap-handler base address

    // machine trap handling
    CSR_MSCRATCH = 0x340, // Scratch register for machine trap handlers
    CSR_MEPC = 0x341,     // Machine exception program counter
    CSR_MCAUSE = 0x342,   // Machine trap cause
    CSR_MTVAL = 0x343,    // Machine bad address or instruction
};

// The whole status
typedef struct {
    // Interger registers
#define NR_GPR 32
    uint64_t X[NR_GPR];

    // Program counter
    uint64_t PC;

    // Control and Status registers
#define NR_CSR 4096
    uint64_t MVENDORID; // Vendor ID
    uint64_t MARCHID;   // Architecture ID
    uint64_t MIMPID;    // Implementation ID
    uint64_t MHARTID;   // Hardware thread ID
    uint64_t MSTATUS;   // Machine status register
    uint64_t MISA;      // ISA and extensions
    uint64_t MTVEC;     // Machine trap-handler base address
    uint64_t MSCRATCH;  // Scratch register for machine trap handlers
    uint64_t MEPC;      // Machine exception program counter
    uint64_t MCAUSE;    // Machine trap cause
    uint64_t MTVAL;     // Machine bad address or instruction

    // Privilege level
    privilege_level_t privilege;

    // Memory
#define MSIZE 0x8000000
#define MBASE 0x80000000
    uint8_t memory[MSIZE] __attribute((aligned(4096)));

    // Debugger status
    bool has_debugger; // NEMU sdb-like debugger

    // Only take effect if (has_debugger == true)
    bool halt;     // whether the machine has halted
    int halt_code; // halt code, usually defined by rv.X[10] / a0
    uint64_t halt_pc;
    uint32_t halt_inst;
    // note: trigger with ebreak

    // Some misc status
    bool image_loaded; // whether we have loaded the image
} riscv_t;

extern riscv_t rv __attribute((aligned(4096)));

// Initialize the machine
void rv_init();

// Load a image
void rv_load_image(const char *path);
void rv_load_default_image();

// Halt the machine
FORCE_INLINE void rv_halt(int code, uint64_t pc, uint32_t inst) {
    rv.halt = true;
    rv.halt_code = code;
    rv.halt_pc = pc;
    rv.halt_inst = inst;
}

// Raise an exception
void rv_exception(uint64_t cause, uint64_t tval, uint64_t *pc);

#ifdef __cplusplus
}
#endif
