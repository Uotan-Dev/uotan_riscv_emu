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

#include <cassert>
#include <stack>

#include "core/cpu/jit_v1.hpp"
#include "core/mem.h"
#include "core/riscv.h"
#include "utils/logger.h"

jit_v1_step::jit_v1_step() {
    memset(&ir, 0, sizeof(ir));
    len = 0;
}

size_t jit_v1_step::find_nxt(uint64_t npc) const {
    for (size_t i = 0; i < nxt.size(); i++)
        if (npc == nxt[i].first)
            return nxt[i].second;
    return SIZE_MAX;
}

void jit_v1_step::add_nxt(uint64_t npc, size_t idx) {
    if (find_nxt(npc) != SIZE_MAX)
        return;
    nxt.emplace_back(npc, idx);
    assert(nxt.size() <= 2);
}

jit_v1_block::jit_v1_block() {
    // TODO: Do research for a better value
    block.reserve(256);
}

uint64_t jit_v1_block::run(bool &invalidate) {
    assert(!block.empty());

    invalidate = false;

    auto check_mapping = [this](uint64_t pc, uint64_t paddr) -> bool {
        if (!paddr_in_pmem(paddr))
            return false;

        // Check rounddown(pc)->(rounddown(pa),ppv) mapping
        auto it = pc_map.find(ROUNDDOWN(pc, PAGE_SIZE));
        if (it == pc_map.end()) [[unlikely]]
            return false;
        const auto [pa, ppv] = it->second;
        if (pa != ROUNDDOWN(paddr, PAGE_SIZE) ||
            ppv != rv.ppv[paddr_get_pmem_pg_id(pa)]) [[unlikely]]
            return false;
        return true;
    };

    size_t idx = 0;
    size_t start_mcycle = rv.MCYCLE;

#define STEPS() (rv.MCYCLE - start_mcycle)

    bool check_new_page = true, check_cross_page_insn = true;

    while (true) {
        if (rv.shutdown) [[unlikely]]
            return rv.MCYCLE - start_mcycle;

        if (check_new_page) [[unlikely]] {
            uint64_t paddr;

            // Check translation
            mmu_result_t r = vaddr_translate(rv.PC, &paddr, ACCESS_INSN, false);

            if (r != TRANSLATE_OK) [[unlikely]] {
                vaddr_raise_exception(r, rv.PC); // modifies npc
                rv.PC = rv.npc;
                invalidate = true;
                return STEPS();
            }

            if (!check_mapping(rv.PC, paddr)) {
                invalidate = true;
                return STEPS();
            }
        }

        if (check_cross_page_insn) [[unlikely]] {
            uint64_t paddr;

            // Check translation
            mmu_result_t r =
                vaddr_translate(rv.PC + 2, &paddr, ACCESS_INSN, false);

            if (r != TRANSLATE_OK) [[unlikely]] {
                vaddr_raise_exception(r, rv.PC + 2); // modifies npc
                rv.PC = rv.npc;
                invalidate = true;
                return STEPS();
            }

            if (!check_mapping(rv.PC + 2, paddr)) {
                invalidate = true;
                return STEPS();
            }
        }

        rv.last_exception = CAUSE_EXCEPTION_NONE;
        rv.satp_dirty = false;
        rv.dirty_vm = 0;

        if ((rv.MCYCLE & 32767) == 0) {
            interrupt_t intr = cpu_get_pending_intr();
            if (intr != CAUSE_INTERRUPT_NONE) {
                cpu_process_intr(intr);
                return STEPS();
            }
        }

        jit_v1_step &js = block[idx];

        // Some unexpected mismatch happened
        if (js.pc != rv.PC) [[unlikely]] {
            // assert(0);
            log_warn("Possible bug: pc mismatch");
            invalidate = true;
            return STEPS();
        }

        if (js.ir.exec == nullptr) [[unlikely]]
            return STEPS();

        // Fill the npc
        rv.npc = js.pc + js.len;

        // Run the instruction
        cpu_exec_inst(&js.ir);

        // Update global status
        rv.PC = rv.npc;
        rv.MCYCLE++;
        if (rv.last_exception == CAUSE_EXCEPTION_NONE &&
            !rv.suppress_minstret_increase) [[likely]]
            rv.MINSTRET++;
        rv.suppress_minstret_increase = false;

        // The step is an indirect jmp or sfence.vma
        if (js.nxt.empty()) [[unlikely]]
            return STEPS();

        // An exception happened
        if (rv.last_exception != CAUSE_EXCEPTION_NONE) [[unlikely]]
            return STEPS();

        // SATP is modified
        if (rv.satp_dirty) [[unlikely]]
            return STEPS();

        // SMC detected
        if (rv.dirty_vm && ON_SAME_PAGE(rv.dirty_vm, rv.npc)) [[unlikely]] {
            invalidate = true;
            return STEPS();
        }

        idx = js.find_nxt(rv.npc);
        if (idx == SIZE_MAX)
            return STEPS();

        if (idx >= block.size()) [[unlikely]] {
            log_warn("Possible bug: idx overflow");
            return STEPS();
        }

        // Request checks
        check_new_page = !ON_SAME_PAGE(js.pc, rv.npc);
        check_cross_page_insn =
            ((rv.npc & (PAGE_SIZE - 1)) > PAGE_SIZE - 4 && block[idx].len == 4);
    }

    __UNREACHABLE;
}

uint64_t jit_v1::try_run(uint64_t pc) {
    if (pc & 0x1) [[unlikely]]
        return 0;

    uint64_t satp = rv.SATP;
    jit_v1_block *jb = _jcache.get({pc, satp});

    if (jb == nullptr) {
        if (++_jhotness[{pc, satp}] >= _jhotness_threshold) {
            _jhotness.erase({pc, satp});
            jb = __compile(pc);
            if (jb == nullptr)
                return 0;
        } else {
            return 0;
        }
    }

    bool invalidate = false;
    uint64_t steps = jb->run(invalidate);

    if (invalidate)
        _jcache.remove({pc, satp});

    return steps;
}

jit_v1_block *jit_v1::__compile(uint64_t start_pc) {
    if (start_pc & 0x1) [[unlikely]]
        return nullptr;

    jit_v1_block *jb = new jit_v1_block;

    std::stack<uint64_t> tasks;
    absl::flat_hash_map<uint64_t, size_t>
        finished; // pc->idx map for finished tasks
    absl::flat_hash_map<uint64_t, std::vector<size_t>> holes;

    tasks.push(start_pc);

    while (!tasks.empty()) {
        uint64_t pc = tasks.top();
        tasks.pop();

        if (finished.contains(pc))
            continue;

        uint64_t pa = 0;
        size_t len = 0;
        bool succ = false;
        uint32_t inst = vaddr_ifetch_offline(pc, &pa, &len, &succ);

        // Build current step
        {
            jit_v1_step js;
            js.pc = pc;

            if (!succ) [[unlikely]] {
                // The data might not be executable in JIT
                js.ir.exec = nullptr; // The runner will handle that
            } else {
                // Decode
                js.ir.inst = inst;
                js.len = len;
                len == 4 ? cpu_decode_32(&js.ir) : cpu_decode_16(&js.ir);

                // Write pc_map
                jb->pc_map[ROUNDDOWN(pc, PAGE_SIZE)] = {
                    ROUNDDOWN(pa, PAGE_SIZE), rv.ppv[paddr_get_pmem_pg_id(pa)]};
            }

            // Add to the JIT block
            jb->block.push_back(js);

            finished[pc] = jb->block.size() - 1;

            // now current block is finished, fill holes caused by this task
            if (holes.contains(pc)) {
                for (size_t idx : holes[pc]) {
                    jit_v1_step &js_ = jb->block[idx];
                    js_.add_nxt(pc, finished[pc]);
                }
                holes.erase(pc);
            }
        }

        jit_v1_step &js = jb->block.back();

#define HANDLE_BRANCH_TAKEN()                                                  \
    do {                                                                       \
        uint64_t npc = pc + js.ir.imm;                                         \
        if (finished.contains(npc)) {                                          \
            js.add_nxt(npc, finished[npc]);                                    \
        } else {                                                               \
            tasks.push(npc);                                                   \
            holes[npc].push_back(finished[pc]);                                \
        }                                                                      \
    } while (0)

#define HANDLE_NORMAL()                                                        \
    do {                                                                       \
        uint64_t npc = pc + len;                                               \
        if (finished.contains(npc)) {                                          \
            js.add_nxt(npc, finished[npc]);                                    \
        } else {                                                               \
            /* tasks is a stack, npc will become the just following task */    \
            tasks.push(npc);                                                   \
            js.add_nxt(npc, jb->block.size());                                 \
        }                                                                      \
    } while (0)

#define HANDLE_JUMP()                                                          \
    do {                                                                       \
        uint64_t npc = pc + js.ir.imm;                                         \
        if (finished.contains(npc)) {                                          \
            js.add_nxt(npc, finished[npc]);                                    \
        } else {                                                               \
            /* tasks is a stack, npc will become the just following task */    \
            tasks.push(npc);                                                   \
            js.add_nxt(npc, jb->block.size());                                 \
        }                                                                      \
    } while (0)

        // Fill nxt
        if (js.ir.exec == nullptr || cpu_insn_is_indirect_jmp(&js.ir) ||
            cpu_insn_is_sfence_vma(&js.ir)) {
            js.nxt.clear();
        } else if (cpu_insn_is_branch(&js.ir)) {
            HANDLE_BRANCH_TAKEN();
            HANDLE_NORMAL();
        } else if (cpu_insn_is_direct_jmp(&js.ir)) {
            HANDLE_JUMP();
        } else {
            HANDLE_NORMAL();
        }
    }

    _jcache.put({start_pc, rv.SATP}, jb);

    return jb;
}
