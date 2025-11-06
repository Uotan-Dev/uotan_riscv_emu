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

#include "core/cpu/jit_v2.hpp"
#include "core/mem.h"
#include "core/riscv.h"
#include "utils/logger.h"

extern "C" {
bool check_mapping(const void *pc_map, uint64_t pc, uint64_t paddr) {
    auto pc_map_ = static_cast<const typeof(jit_v2_block::pc_map) *>(pc_map);

    if (!paddr_in_pmem(paddr))
        return false;

    // Check rounddown(pc)->(rounddown(pa),ppv) mapping
    auto it = pc_map_->find(ROUNDDOWN(pc, PAGE_SIZE));
    if (it == pc_map_->end()) [[unlikely]]
        return false;
    const auto [pa, ppv] = it->second;
    if (pa != ROUNDDOWN(paddr, PAGE_SIZE) ||
        ppv != rv.ppv[paddr_get_pmem_pg_id(pa)]) [[unlikely]]
        return false;

    return true;
}

bool check_new_page(const void *pc_map) {
    uint64_t paddr;

    // Check translation
    mmu_result_t r = vaddr_translate(rv.PC, &paddr, ACCESS_INSN, false);

    if (r != TRANSLATE_OK) [[unlikely]] {
        vaddr_raise_exception(r, rv.PC); // modifies npc
        rv.PC = rv.npc;
        return false;
    }

    if (!check_mapping(pc_map, rv.PC, paddr))
        return false;

    return true;
}

bool check_cross_page_insn(const void *pc_map) {
    uint64_t paddr;

    // Check translation
    mmu_result_t r = vaddr_translate(rv.PC + 2, &paddr, ACCESS_INSN, false);

    if (r != TRANSLATE_OK) [[unlikely]] {
        vaddr_raise_exception(r, rv.PC + 2); // modifies npc
        rv.PC = rv.npc;
        return false;
    }

    if (!check_mapping(pc_map, rv.PC + 2, paddr))
        return false;
    return true;
}
}

jit_v2_block::jit_v2_block(asmjit::JitRuntime &jrt) : _jf(nullptr), jrt(jrt) {}

jit_v2_block::~jit_v2_block() {
    if (_jf != nullptr) {
        jrt.release(_jf);
        _jf = nullptr;
    }
}

uint64_t jit_v2_block::run(bool &invalidate) {
    assert(_jf);
    return _jf(&invalidate);
}

void jit_v2_block::set(jit_v2_func jf) { _jf = jf; }

uint64_t jit_v2::try_run(uint64_t pc) {
    if (pc & 0x1) [[unlikely]]
        return 0;

    uint64_t satp = rv.SATP;
    jit_v2_block *jb_v2 = _jcache.get({pc, satp});

    if (jb_v2 == nullptr) {
        if (++_jhotness[{pc, satp}] >= _jhotness_threshold) {
            _jhotness.erase({pc, satp});
            jit_v1_block *jb_v1 = _jv1._jcache.get({pc, satp});
            if (jb_v1 == nullptr)
                jb_v1 = _jv1.__compile(pc);
            if (jb_v1 == nullptr) [[unlikely]]
                return 0;

            jb_v2 = __compile(*jb_v1);
            if (jb_v2 == nullptr)
                return 0;
        } else {
            return 0;
        }
    }

    bool invalidate = false;
    uint64_t steps = jb_v2->run(invalidate);

    if (invalidate) {
        _jcache.remove({pc, satp});
        _jv1._jcache.remove({pc, satp});
    }

    return steps;
}

jit_v2_block *jit_v2::__compile(const jit_v1_block &jb_v1) {
    const auto &block_v1 = jb_v1.block;

    assert(!block_v1.empty());

    jit_v2_block *jb = new jit_v2_block(_jrt);
    jb->pc_map = jb_v1.pc_map;

    asmjit::CodeHolder code;
    code.init(_jrt.environment(), _jrt.cpu_features());
    asmjit::x86::Assembler a(&code);

    // Prologue
    a.push(asmjit::x86::rbp);
    a.mov(asmjit::x86::rbp, asmjit::x86::rsp);

    // Push callee-saved registers
    a.push(asmjit::x86::rbx);
    a.push(asmjit::x86::r11);
    a.push(asmjit::x86::r12);
    a.push(asmjit::x86::r13);
    a.push(asmjit::x86::r14);
    a.push(asmjit::x86::r15);

    // Put invalidate ptr in r12
    a.mov(asmjit::x86::r12, asmjit::x86::rdi);

    // Allocate space on stack
    // rv_insn_t ir + bool check_new_page + bool check_cross_page_insn
    constexpr size_t ir_sz = ((sizeof(rv_insn_t) + 15) / 16) * 16;
    constexpr size_t bool_sz = 16;
    constexpr size_t total_sz_unaligned = ir_sz + bool_sz;
    constexpr size_t total_sz = ((total_sz_unaligned + 15) / 16) * 16;
    a.sub(asmjit::x86::rsp, asmjit::Imm(static_cast<int>(total_sz)));

    // rbx = &rv
    a.mov(asmjit::x86::rbx, asmjit::Imm(reinterpret_cast<uint64_t>(&rv)));

    // r13 = start_mcycle
    a.mov(asmjit::x86::r13,
          asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, MCYCLE)));

    int ir_stack_offset = 0;
    int check_new_page_offset = static_cast<int>(ir_sz);
    int check_cross_page_offset = static_cast<int>(ir_sz + 8);

    asmjit::x86::Mem ir_on_stack =
        asmjit::x86::ptr(asmjit::x86::rsp, ir_stack_offset);
    asmjit::x86::Mem check_new_page_flag =
        asmjit::x86::byte_ptr(asmjit::x86::rsp, check_new_page_offset);
    asmjit::x86::Mem check_cross_page_flag =
        asmjit::x86::byte_ptr(asmjit::x86::rsp, check_cross_page_offset);

    // Initialize checking flags for first instruction
    uint64_t first_pc = block_v1.front().pc;
    uint64_t first_len = block_v1.front().len;
    bool initial_check_new_page = true;
    bool initial_check_cross_page =
        ((first_pc & (PAGE_SIZE - 1)) > PAGE_SIZE - 4 && first_len == 4);
    a.mov(check_new_page_flag, asmjit::Imm(initial_check_new_page ? 1 : 0));
    a.mov(check_cross_page_flag, asmjit::Imm(initial_check_cross_page ? 1 : 0));

    // Create labels
    asmjit::Label lb_exit = a.new_label();
    asmjit::Label lb_invalidate = a.new_label();
    std::vector<asmjit::Label> labels;
    labels.reserve(block_v1.size());
    for (size_t i = 0; i < block_v1.size(); i++)
        labels.push_back(a.new_label());

    for (size_t i = 0; i < block_v1.size(); i++) {
        const auto &js = block_v1[i];

        a.bind(labels[i]);

        // Check shutdown
        a.cmp(asmjit::x86::byte_ptr(asmjit::x86::rbx,
                                    offsetof(riscv_t, shutdown)),
              asmjit::Imm(0));
        a.jne(lb_exit);

        // Check new page
        asmjit::Label skip_new_page = a.new_label();
        a.cmp(check_new_page_flag, asmjit::Imm(0));
        a.je(skip_new_page);
        {
            a.mov(asmjit::x86::rdi,
                  asmjit::Imm(reinterpret_cast<uint64_t>(&jb->pc_map)));
            a.call(asmjit::Imm(reinterpret_cast<uintptr_t>(check_new_page)));
            a.test(asmjit::x86::rax, asmjit::x86::rax);
            a.jz(lb_invalidate);
        }
        a.bind(skip_new_page);

        // Check cross page instructions
        asmjit::Label skip_cross_page = a.new_label();
        a.cmp(check_cross_page_flag, asmjit::Imm(0));
        a.je(skip_cross_page);
        {
            a.mov(asmjit::x86::rdi,
                  asmjit::Imm(reinterpret_cast<uint64_t>(&jb->pc_map)));
            a.call(asmjit::Imm(
                reinterpret_cast<uintptr_t>(check_cross_page_insn)));
            a.test(asmjit::x86::rax, asmjit::x86::rax);
            a.jz(lb_invalidate);
        }
        a.bind(skip_cross_page);

        // Reset flags
        a.mov(asmjit::x86::r11,
              asmjit::Imm(static_cast<uint64_t>(CAUSE_EXCEPTION_NONE)));
        a.mov(asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, last_exception)),
              asmjit::x86::r11);
        a.mov(asmjit::x86::byte_ptr(asmjit::x86::rbx,
                                    offsetof(riscv_t, satp_dirty)),
              asmjit::Imm(0));
        a.mov(asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, dirty_vm)),
              asmjit::Imm(0));

        // Check interruptions
        a.mov(asmjit::x86::rax,
              asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, MCYCLE)));
        a.and_(asmjit::x86::rax, asmjit::Imm(8191));
        asmjit::Label skip_intr = a.new_label();
        a.jnz(skip_intr);
        a.call(asmjit::Imm(
            reinterpret_cast<uint64_t>(cpu_check_and_process_intr)));
        a.test(asmjit::x86::rax, asmjit::x86::rax);
        a.jnz(lb_exit);
        a.bind(skip_intr);

        // Check PC mismatch
        a.mov(asmjit::x86::rax,
              asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, PC)));
        a.mov(asmjit::x86::r11, asmjit::Imm(js.pc));
        a.cmp(asmjit::x86::rax, asmjit::x86::r11);
        a.jne(lb_invalidate);

        // Check ir.exec
        if (js.ir.exec == nullptr) {
            a.jmp(lb_exit);
            continue;
        }

        // Fill the npc
        a.mov(asmjit::x86::r11, asmjit::Imm(js.pc + js.len));
        a.mov(asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, npc)),
              asmjit::x86::r11);

        // Prepare the ir
        a.lea(asmjit::x86::rdi, ir_on_stack);
        a.mov(
            asmjit::x86::dword_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, inst)),
            asmjit::Imm(static_cast<uint32_t>(js.ir.inst)));
        a.mov(asmjit::x86::byte_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, rd)),
              asmjit::Imm(static_cast<int32_t>(js.ir.rd)));
        a.mov(asmjit::x86::byte_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, rs1)),
              asmjit::Imm(static_cast<int32_t>(js.ir.rs1)));
        a.mov(asmjit::x86::byte_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, rs2)),
              asmjit::Imm(static_cast<int32_t>(js.ir.rs2)));
        a.mov(asmjit::x86::byte_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, rs3)),
              asmjit::Imm(static_cast<int32_t>(js.ir.rs3)));
        a.mov(asmjit::x86::r11, asmjit::Imm(static_cast<uint64_t>(js.ir.imm)));
        a.mov(
            asmjit::x86::qword_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, imm)),
            asmjit::x86::r11);
        a.mov(asmjit::x86::r11,
              asmjit::Imm(reinterpret_cast<uintptr_t>(js.ir.exec)));
        a.mov(
            asmjit::x86::qword_ptr(asmjit::x86::rdi, offsetof(rv_insn_t, exec)),
            asmjit::x86::r11);

        // Run the instruction
        a.call(asmjit::Imm(reinterpret_cast<uintptr_t>(cpu_exec_inst)));

        // Update PC to npc
        a.mov(asmjit::x86::rax,
              asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, npc)));
        a.mov(asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, PC)),
              asmjit::x86::rax);

        // Update MCYCLE
        a.inc(asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, MCYCLE)));

        // Update MINSTRET
        asmjit::Label skip_minstret = a.new_label();
        a.mov(asmjit::x86::r11,
              asmjit::Imm(static_cast<uint64_t>(CAUSE_EXCEPTION_NONE)));
        a.cmp(asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, last_exception)),
              asmjit::x86::r11);
        a.jne(skip_minstret);
        a.cmp(asmjit::x86::byte_ptr(
                  asmjit::x86::rbx,
                  offsetof(riscv_t, suppress_minstret_increase)),
              asmjit::Imm(0));
        a.jne(skip_minstret);
        a.inc(asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, MINSTRET)));
        a.bind(skip_minstret);
        a.mov(asmjit::x86::byte_ptr(
                  asmjit::x86::rbx,
                  offsetof(riscv_t, suppress_minstret_increase)),
              asmjit::Imm(0));

        // The step is an indirect jmp or sfence.vma
        if (js.nxt_size == 0) {
            a.jmp(lb_exit);
            continue;
        }

        // An exception happened
        a.mov(asmjit::x86::r11,
              asmjit::Imm(static_cast<uint64_t>(CAUSE_EXCEPTION_NONE)));
        a.cmp(asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, last_exception)),
              asmjit::x86::r11);
        a.jne(lb_exit);

        // SMC detected
        a.cmp(asmjit::x86::byte_ptr(asmjit::x86::rbx,
                                    offsetof(riscv_t, satp_dirty)),
              asmjit::Imm(0));
        a.jne(lb_exit);
        a.mov(asmjit::x86::rax,
              asmjit::x86::qword_ptr(asmjit::x86::rbx,
                                     offsetof(riscv_t, dirty_vm)));
        a.test(asmjit::x86::rax, asmjit::x86::rax);
        asmjit::Label skip_smc = a.new_label();
        a.jz(skip_smc);
        a.mov(asmjit::x86::rcx,
              asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, npc)));
        a.xor_(asmjit::x86::rax, asmjit::x86::rcx);
        a.shr(asmjit::x86::rax, asmjit::Imm(PAGE_SHIFT));
        a.jz(lb_invalidate);
        a.bind(skip_smc);

        a.mov(asmjit::x86::r14,
              asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, npc)));

        if (js.nxt_size == 1) {
            auto [nxt_pc, nxt_idx] = js.nxt[0];

            bool next_check_new_page = !ON_SAME_PAGE(js.pc, nxt_pc);
            bool next_check_cross_page = false;
            if (nxt_idx < block_v1.size()) {
                next_check_cross_page =
                    ((nxt_pc & (PAGE_SIZE - 1)) > PAGE_SIZE - 4 &&
                     block_v1[nxt_idx].len == 4);
            }

            a.mov(check_new_page_flag,
                  asmjit::Imm(next_check_new_page ? 1 : 0));
            a.mov(check_cross_page_flag,
                  asmjit::Imm(next_check_cross_page ? 1 : 0));

            a.mov(asmjit::x86::r11, asmjit::Imm(nxt_pc));
            a.cmp(asmjit::x86::r14, asmjit::x86::r11);
            a.je(labels[nxt_idx]);

            a.jmp(lb_exit);

        } else if (js.nxt_size == 2) {
            auto [nxt_pc0, nxt_idx0] = js.nxt[0];
            auto [nxt_pc1, nxt_idx1] = js.nxt[1];

            asmjit::Label path0 = a.new_label();
            asmjit::Label path1 = a.new_label();

            a.mov(asmjit::x86::r11, asmjit::Imm(nxt_pc0));
            a.cmp(asmjit::x86::r14, asmjit::x86::r11);
            a.je(path0);
            a.mov(asmjit::x86::r11, asmjit::Imm(nxt_pc1));
            a.cmp(asmjit::x86::r14, asmjit::x86::r11);
            a.je(path1);

            a.jmp(lb_exit);

            a.bind(path0);
            {
                bool next_check_new_page = !ON_SAME_PAGE(js.pc, nxt_pc0);
                bool next_check_cross_page = false;
                if (nxt_idx0 < block_v1.size()) {
                    next_check_cross_page =
                        ((nxt_pc0 & (PAGE_SIZE - 1)) > PAGE_SIZE - 4 &&
                         block_v1[nxt_idx0].len == 4);
                }
                a.mov(check_new_page_flag,
                      asmjit::Imm(next_check_new_page ? 1 : 0));
                a.mov(check_cross_page_flag,
                      asmjit::Imm(next_check_cross_page ? 1 : 0));
                a.jmp(labels[nxt_idx0]);
            }

            a.bind(path1);
            {
                bool next_check_new_page = !ON_SAME_PAGE(js.pc, nxt_pc1);
                bool next_check_cross_page = false;
                if (nxt_idx1 < block_v1.size()) {
                    next_check_cross_page =
                        ((nxt_pc1 & (PAGE_SIZE - 1)) > PAGE_SIZE - 4 &&
                         block_v1[nxt_idx1].len == 4);
                }
                a.mov(check_new_page_flag,
                      asmjit::Imm(next_check_new_page ? 1 : 0));
                a.mov(check_cross_page_flag,
                      asmjit::Imm(next_check_cross_page ? 1 : 0));
                a.jmp(labels[nxt_idx1]);
            }
        }
    }

    // invalidate
    a.bind(lb_invalidate);
    a.mov(asmjit::x86::byte_ptr(asmjit::x86::r12), asmjit::Imm(1));

    // exit
    a.bind(lb_exit);
    a.mov(asmjit::x86::rax,
          asmjit::x86::qword_ptr(asmjit::x86::rbx, offsetof(riscv_t, MCYCLE)));
    a.sub(asmjit::x86::rax, asmjit::x86::r13);

    a.add(asmjit::x86::rsp, asmjit::Imm(static_cast<int>(total_sz)));
    a.pop(asmjit::x86::r15);
    a.pop(asmjit::x86::r14);
    a.pop(asmjit::x86::r13);
    a.pop(asmjit::x86::r12);
    a.pop(asmjit::x86::r11);
    a.pop(asmjit::x86::rbx);
    a.pop(asmjit::x86::rbp);
    a.ret();

    jit_v2_func jf;
    asmjit::Error err = _jrt.add(&jf, &code);
    if (err != asmjit::Error::kOk) {
        log_warn("JIT v2 compilation failed");
        delete jb;
        return nullptr;
    }

    jb->set(jf);
    _jcache.put({block_v1.front().pc, rv.SATP}, jb);

    return jb;
}
