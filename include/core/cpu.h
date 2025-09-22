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
void cpu_step(size_t step);
void cpu_print_registers();
uint64_t *cpu_get_csr(uint32_t csr);

void cpu_raise_exception(exception_t cause, uint64_t tval);

// CSR read, should only be used for instruction simulation
FORCE_INLINE uint64_t cpu_read_csr(uint64_t csr, bool *succ) {
    // clang-format off
    switch (csr & 0xFFF) {
#define macro(csr_name) case CSR_##csr_name: return rv.csr_name;
        // M-mode
        macro(MVENDORID) macro(MARCHID) macro(MIMPID) macro(MHARTID)
        macro(MSTATUS)   macro(MISA)    macro(MTVEC)  macro(MSCRATCH)
        macro(MEPC)      macro(MCAUSE)  macro(MTVAL)  macro(MIE)
        macro(MIP)

        // S-mode
        macro(SSTATUS)   macro(SIE)     macro(STVEC)  macro(SSCRATCH)
        macro(SEPC)      macro(SCAUSE)  macro(STVAL)  macro(SIP)
        macro(SATP)
#undef macro

        default:
            *succ = false;
            return -1;
    }
    // clang-format on
    __UNREACHABLE;
}

// CSR write, should only be used for instruction simulation
FORCE_INLINE void cpu_write_csr(uint64_t csr, uint64_t value, bool *succ) {
    // clang-format off
    switch (csr & 0xFFF) {
#define macro(csr_name) case CSR_##csr_name: rv.csr_name = value; break;
        // M-mode
        case CSR_MSTATUS:
            rv.MSTATUS = value & 0x807FFFFF; // Filter some read-only bits
            break;
        case CSR_MEPC: rv.MEPC = value & ~1ULL; break;
        macro(MTVEC) macro(MSCRATCH) macro(MCAUSE) macro(MTVAL)
        macro(MIE)   macro(MIP)

        // S-mode
        macro(SSTATUS)   macro(SIE)     macro(STVEC)  macro(SSCRATCH)
        macro(SEPC)      macro(SCAUSE)  macro(STVAL)  macro(SIP)
        macro(SATP)
#undef macro

        default: *succ = false; break;
    }
    // clang-format on
}

#ifdef __cplusplus
}
#endif
