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

#include "common.h"
#include "riscv.h"

#ifdef __cplusplus
extern "C" {
#endif

void cpu_start();
void cpu_print_registers();

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

    // machine trap handling
    CSR_MSCRATCH = 0x340, // Scratch register for machine trap handlers
    CSR_MEPC = 0x341,     // Machine exception program counter
    CSR_MCAUSE = 0x342,   // Machine trap cause
    CSR_MTVAL = 0x343,    // Machine bad address or instruction
    CSR_MIP = 0x344,      // Machine interrupt pending
};

FORCE_INLINE uint64_t *cpu_get_csr(uint32_t csr) {
    // clang-format off
    switch (csr & 0xFFF) {
#define macro(csr_name) case CSR_##csr_name: return &rv.csr_name;
        macro(MVENDORID) macro(MARCHID) macro(MIMPID) macro(MHARTID)
        macro(MSTATUS)   macro(MISA)    macro(MTVEC)  macro(MSCRATCH)
        macro(MEPC)      macro(MCAUSE)  macro(MTVAL)
#undef macro

        default:
            printf("Invalid CSR requestde: 0x%" PRIx32 "\n", csr & 0xFFF);
            assert(0);
    }
    // clang-format on
}

#ifdef __cplusplus
}
#endif
