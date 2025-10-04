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

#define REF_NR_GPR 32
#define REF_MSIZE 0x10000000

enum : bool { DIFFTEST_TO_DUT, DIFFTEST_TO_REF };

#define CSR_LIST                                                               \
    X(uint64_t, MSTATUS, mstatus)                                              \
    X(uint64_t, MISA, misa)                                                    \
    X(uint64_t, MEDELEG, medeleg)                                              \
    X(uint64_t, MIDELEG, mideleg)                                              \
    X(uint64_t, MIE, mie)                                                      \
    X(uint64_t, MTVEC, mtvec)                                                  \
    X(uint32_t, MCOUNTEREN, mcounteren)                                        \
    X(uint64_t, MEPC, mepc)                                                    \
    X(uint64_t, MCAUSE, mcause)                                                \
    X(uint64_t, MTVAL, mtval)                                                  \
    X(uint64_t, MIP, mip)                                                      \
    X(uint64_t, MCYCLE, mcycle)                                                \
    X(uint64_t, MINSTRET, minstret)                                            \
    X(uint64_t, MSECCFG, mseccfg)                                              \
    X(uint64_t, STVEC, stvec)                                                  \
    X(uint32_t, SCOUNTEREN, scounteren)                                        \
    X(uint64_t, SEPC, sepc)                                                    \
    X(uint64_t, SCAUSE, scause)                                                \
    X(uint64_t, STVAL, stval)                                                  \
    X(uint64_t, SATP, satp)

struct diff_context_t {
    uint64_t gpr[REF_NR_GPR];
    uint64_t pc;
#define X(type, name1, name2) type name1;
    CSR_LIST
#undef X
};
