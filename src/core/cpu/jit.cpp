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

#include <queue>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/cpu/decode.h"
#include "core/cpu/exec.h"
#include "core/mem.h"
#include "utils/lru_cache.hpp"

class jit_block {
public:
    explicit jit_block() { _block.reserve(512); }

    void add_insn(const rv_insn_t &ir) {
        if (!_block.empty())
            assert(ir.pa > _block.back().pa);
        _block.push_back(ir);
    }

    void run() {
        assert(!_block.empty());

        size_t idx = 0;
        size_t steps = 0;
        uint64_t snpc = 0; // static next pc

        while (idx < _block.size()) {
            if (rv.shutdown) [[unlikely]]
                return;

            rv.last_exception = CAUSE_EXCEPTION_NONE;

            // Check intr
            if ((steps & 131071) == 0) {
                interrupt_t intr = cpu_get_pending_intr();
                if (intr != CAUSE_INTERRUPT_NONE) {
                    cpu_process_intr(intr);
                    return;
                }
            }

            // Fill in the ir and upload to the rv struct
            rv_insn_t &ir = _block[idx];
            ir.pc = rv.PC;
            snpc = ir.npc = rv.PC + ir.len;
            rv.ir = &ir;

            // Run the inst
            cpu_exec_inst(&ir);

            // Update global status
            rv.PC = ir.npc;
            rv.MCYCLE++;
            if (rv.last_exception == CAUSE_EXCEPTION_NONE &&
                !rv.suppress_minstret_increase) [[likely]]
                rv.MINSTRET++;
            rv.suppress_minstret_increase = false;

            // Check SMC

            // Handle possible jumps
            if (snpc != ir.npc) {
                // A jump has occured, check if we are still on the same page
                if (_block[0].pc >> PAGE_SHIFT == ir.npc >> PAGE_SHIFT) {
                    // still on the same page, try to do in-block jump
                    uint64_t target_pa = _block[0].pa + ir.npc - _block[0].pc;
                    size_t nxt = __find_code_by_pa(target_pa);

                    // go back to the dispatcher
                    if (nxt == SIZE_MAX) [[unlikely]]
                        return;

                    idx = nxt;
                } else {
                    // jump out of the block
                    return;
                }
            } else {
                // no jumps have occured, increase normally
                idx++;
            }

            steps++;
        }
    }

private:
    size_t __find_code_by_pa(uint64_t pa) {
        // todo: use bsearch
        for (size_t i = 0; i < _block.size(); i++)
            if (_block[i].pa == pa)
                return i;
        return SIZE_MAX;
    }

    std::vector<rv_insn_t> _block;
};

class jit_cache : public LruCache<uint64_t, jit_block *> {
public:
    jit_cache() : LruCache<uint64_t, jit_block *>(_max_size) {}

private:
    static constexpr size_t _max_size = 10920;
};

enum jit_task_status : uint8_t {
    status_compiling,
    status_requested,
    statuc_smc,
    status_none,
};

static jit_cache jcache;
static std::queue<uint64_t> jqueue;
static std::unordered_map<uint64_t, uint64_t> jhotness;
static std::unordered_map<uint64_t, jit_task_status> jstatus;

static std::unique_ptr<std::thread> jth;
static std::mutex jmtx;

// called by the compiler thread
static bool jit_compile(uint64_t pa) {
    assert(paddr_in_pmem(pa));

    jit_block *jb = new jit_block;

    // Emit a misaligned fetch if addr is not aligned
    if ((pa & 0x1) != 0) [[unlikely]] {
        rv_insn_t ir;
        ir.exec = [](rv_insn_t *s) -> void {
            cpu_raise_exception(CAUSE_MISALIGNED_FETCH, s->pc);
        };
        jb->add_insn(ir);
        jcache.put(pa, jb);
        return true;
    }

    // Compile the code instruction by instruction
    const uint64_t page_end = ROUNDUP(pa, PAGE_SIZE);
    while (pa < page_end) {
        // TODO: check_smc(), check_shutdown()

        uint32_t inst_len = 4;
        uint32_t inst = pmem_read(pa, 4);

        // Handle 16-bit RVC instructions
        if ((inst & 0x3) < 3) {
            inst_len = 2;
            inst &= 0xffff;
        }

        // Handle cross-page 32-bit instructions
        if (inst_len == 4 && (pa & (PAGE_SIZE - 1)) > PAGE_SIZE - 4)
            [[unlikely]]
            break;

        // Decode and register the instruction
        rv_insn_t ir;
        inst_len == 4 ? cpu_decode_32(&ir) : cpu_decode_16(&ir);
        ir.pa = pa;
        ir.len = inst_len;
        jb->add_insn(ir);

        // An illegal insn is detected, no longer safe to continue
        if (ir.exec == exec_inv || ir.exec == exec_c_inv) [[unlikely]]
            break;

        pa += inst_len;
    }

    // TODO: check_smc()
    jcache.put(pa, jb);

    return true;
}

// jit compiler thread
static void jit_compiler_thread() {
    // atomicly fetch a task from jqueue and chk and set jstatus
    { std::lock_guard<std::mutex> guard(jmtx); }

    // start the compilation
    // update jstatus and jhotness
}

// called by jit_try_run
static bool jit_request_compile(uint64_t pa) {
    // push pa to the jqueue and set jstatus atomicly
    return false;
}

// called by the dispatcher thread
bool jit_try_run(uint64_t pa) {
    constexpr uint64_t hotness_threshold = 128;

    jit_block *jb = jcache.get(pa);

    if (jb == nullptr) {
        if (++jhotness[pa] >= hotness_threshold) {
            // notify the compiler thread (erase pa after compiled)
            if (!jit_request_compile(pa)) {
                // the task has been requested or the queue is full, or smc is
                // detected
                return false;
            }
        }
        return false;
    }

    // Run the block if it is compiled
    jb->run();

    return true;
}

// called by the main thread
void jit_init() {
    // create the compiler thread
    jth = std::make_unique<std::thread>(jit_compiler_thread);
}

void jit_destroy() {
    // recycle rubbish
    if (jth && jth->joinable())
        jth->join();
    jth.reset();
}
