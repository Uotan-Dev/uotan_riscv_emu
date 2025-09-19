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

#include "common.h"
#include "core/cpu.h"
#include "core/decode.h"
#include "core/mem.h"
#include "core/riscv.h"

#define R(i) rv.X[i]

/*
 * The decoding algorithm is taken from NJU emulator
 * Keeping the original license here
 */

/***************************************************************************************
 * Copyright (c) 2014-2024 Zihao Yu, Nanjing University
 *
 * NEMU is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 *PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 * See the Mulan PSL v2 for more details.
 ***************************************************************************************/

// clang-format off
typedef enum {
    TYPE_I, TYPE_U, TYPE_S,
    TYPE_N, // none
} inst_type_t;

#define src1R() do { *src1 = R(rs1); } while (0)
#define src2R() do { *src2 = R(rs2); } while (0)
#define immI() do { *imm = SEXT(BITS(i, 31, 20), 12); } while(0)
#define immU() do { *imm = SEXT(BITS(i, 31, 12), 20) << 12; } while(0)
#define immS() do { *imm = (SEXT(BITS(i, 31, 25), 7) << 5) | BITS(i, 11, 7); } while(0)
// clang-format on

FORCE_INLINE void decode_operand(Decode *s, int *rd, uint64_t *src1,
                                 uint64_t *src2, uint64_t *imm,
                                 inst_type_t type) {
    // clang-format off
    uint32_t i = s->inst;
    int rs1 = BITS(i, 19, 15);
    int rs2 = BITS(i, 24, 20);
    *rd     = BITS(i, 11, 7);
    switch (type) {
        case TYPE_I: src1R();          immI(); break;
        case TYPE_U:                   immU(); break;
        case TYPE_S: src1R(); src2R(); immS(); break;
        case TYPE_N: break;
        default: __UNREACHABLE;
    }
    // clang-format on
}

FORCE_INLINE void decode_exec(Decode *s) {
#define INSTPAT_INST(s) ((s)->inst)

#define INSTPAT_MATCH(s, name, type, ... /* execute body */)                   \
    {                                                                          \
        int rd = 0;                                                            \
        uint64_t src1 = 0, src2 = 0, imm = 0;                                  \
        decode_operand(s, &rd, &src1, &src2, &imm, concat(TYPE_, type));       \
        __VA_ARGS__;                                                           \
    }

    // clang-format off
    INSTPAT_START();
    INSTPAT("??????? ????? ????? ??? ????? 00101 11", auipc  , U, R(rd) = s->pc + imm);
    INSTPAT("??????? ????? ????? 100 ????? 00000 11", lbu    , I, R(rd) = vaddr_read_b(src1 + imm));
    INSTPAT("??????? ????? ????? 000 ????? 01000 11", sb     , S, vaddr_write_b(src1 + imm, src2));
    INSTPAT("0000000 00001 00000 000 00000 11100 11", ebreak , N, rv.halt = true); // R(10) is $a0
    INSTPAT("??????? ????? ????? ??? ????? ????? ??", inv    , N, assert(0)); // TODO: Use proper handling
    INSTPAT_END();
    // clang-format on

    R(0) = 0; // reset $zero to 0
}

FORCE_INLINE void cpu_exec_once(Decode *s, uint64_t pc) {
    s->pc = pc;
    s->npc = pc + 4;
    s->inst = vaddr_ifetch(pc);
    // printf("%" PRIx32 "\n", s->inst);
    decode_exec(s);
    rv.PC = s->npc;
}

void cpu_start() {
    Decode s;
    while (!rv.halt)
        cpu_exec_once(&s, rv.PC);
}
