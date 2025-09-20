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

#include "core/decode.h"

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

    // Memory
#define MSIZE 0x8000000
#define MBASE 0x80000000
    uint8_t memory[MSIZE] __attribute((aligned(4096)));

    // Decoder status
    Decode decode;

    // Some status
    bool image_loaded; // whether we have loaded the image
    bool halt;         // whether the machine has halted
    int halt_code;     // halt code
    uint64_t halt_pc;
    uint32_t halt_inst;
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

#ifdef __cplusplus
}
#endif
