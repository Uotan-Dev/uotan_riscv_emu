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

#include "core/cpu/interpreter.h"
#include "core/cpu/decode.h"
#include "core/cpu/exec.h"
#include "core/cpu/system.h"
#include "core/mem.h"
#include "core/riscv.h"

void cpu_interp_step(rv_insn_t *s) {
    size_t len;
    s->inst = vaddr_ifetch(rv.PC, &len);
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE)) {
        rv.npc = rv.PC + len;
        len == 4 ? cpu_decode_32(s) : cpu_decode_16(s);
        cpu_exec_inst(s);
    }
    rv.PC = rv.npc;
    rv.MCYCLE++;
    if (likely(rv.last_exception == CAUSE_EXCEPTION_NONE &&
               !rv.suppress_minstret_increase))
        rv.MINSTRET++;
    rv.suppress_minstret_increase = false;
}
