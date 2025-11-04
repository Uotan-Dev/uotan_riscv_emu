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

#include "core/mem.h"
#include "core/cpu/csr.h"
#include "device/bus.h"

mmu_result_t vaddr_translate(uint64_t va, uint64_t *pa, mmu_access_t type,
                             bool offline) {
    // TODO: Try TLB first

    uint64_t satp = cpu_read_csr(CSR_SATP);
    uint64_t satp_mode = GET_SATP_MODE(satp);

    // SATP Mode is bare
    if (satp_mode == SATP_MODE_BARE) {
        *pa = va;
        return TRANSLATE_OK;
    }

    uint64_t priv = (uint64_t)rv.privilege;
    uint64_t mstatus = cpu_read_csr(CSR_MSTATUS);

    // Checking mstatus is meaningless for offline translation?
    if (!offline) {
        if (type != ACCESS_INSN && (mstatus & MSTATUS_MPRV))
            priv = (mstatus & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT;
        if (priv == (uint64_t)PRIV_M) {
            *pa = va;
            return TRANSLATE_OK;
        }
    }

    // See include/core/cpu.h for satp write restrictions
    assert(satp_mode == SATP_MODE_SV39);

    uint64_t pt_base = GET_SATP_PPN(satp) * PAGE_SIZE;
    uint64_t pte, pte_addr;
    register int i = SV39_LEVELS - 1;

    for (;; i--) {
        uint64_t vpn_part =
            (va >> (PAGE_SHIFT + i * VPN_BITS)) & ((1ULL << VPN_BITS) - 1);
        pte_addr = pt_base + vpn_part * PTE_SIZE;
        extern uint64_t dram_read(uint64_t addr, size_t n);
        // dram_read() performs no check
        if (likely(paddr_in_pmem(pte_addr)))
            pte = dram_read(pte_addr, 8);
        else
            goto access_fault;

        // Check if the PTE is valid
        if (!(pte & PTE_V) || (!(pte & PTE_R) && (pte & PTE_W)))
            goto page_fault;

        if ((pte & PTE_R) || (pte & PTE_X)) {
            // Got a leaf PTE
            break;
        } else {
            pt_base = ((pte & PTE_PPN_MASK) >> PTE_PPN_SHIFT) * PAGE_SIZE;
            if (i == 0)
                goto page_fault;
        }
    }

    // Check superpage
    uint64_t pte_ppn = (pte & PTE_PPN_MASK) >> PTE_PPN_SHIFT;
    if (i > 0) {
        uint64_t mask = (1ULL << (i * VPN_BITS)) - 1;
        if (pte_ppn & mask)
            goto page_fault;
    }

    // Check U bit
    if (priv == PRIV_U && !(pte & PTE_U))
        goto page_fault;
    if (priv == PRIV_S && (pte & PTE_U) && (mstatus & MSTATUS_SUM) == 0)
        goto page_fault;

    bool readable = (pte & PTE_R);
    bool writable = (pte & PTE_W);
    bool executable = (pte & PTE_X);

    // Make executable readable
    if (executable && (mstatus & MSTATUS_MXR))
        readable = true;

    switch (type) {
        case ACCESS_INSN:
            if (!executable)
                goto page_fault;
            break;
        case ACCESS_LOAD:
            if (!readable)
                goto page_fault;
            break;
        case ACCESS_STORE:
            if (!writable)
                goto page_fault;
            break;
    }

    // Only enable Svade / Svadu extension for online translation
    if (!offline) {
        if (rv.MENVCFG & MENVCFG_ADUE) {
            // When ADUE=1, hardware updating of PTE A/D
            // bits is enabled during S-mode address translation, and the
            // implementation behaves as though the Svade extension were not
            // implemented for S-mode address translation.
            uint64_t new_pte = pte | PTE_A;
            if (type == ACCESS_STORE)
                new_pte |= PTE_D;
            if (new_pte != pte) {
                extern void dram_write(uint64_t addr, uint64_t value, size_t n);
                // dram_write() performs no check
                if (likely(paddr_in_pmem(pte_addr)))
                    dram_write(pte_addr, new_pte, 8);
                else
                    goto access_fault;
            }
        } else {
            // The Svade extension: when a virtual page is accessed and the A
            // bit is clear, or is written and the D bit is clear, a page -
            // fault exception is raised.
            if (unlikely(!(pte & PTE_A) ||
                         (type == ACCESS_STORE && !(pte & PTE_D))))
                goto page_fault;
        }
    }

    uint64_t page_offset = va & (PAGE_SIZE - 1);
    uint64_t pa_ppn_base = pte_ppn;
    if (i > 0) {
        // Superpage
        uint64_t mask = (1ULL << i * VPN_BITS) - 1;
        pa_ppn_base = (pa_ppn_base & ~mask) | ((va >> PAGE_SHIFT) & mask);
    }
    *pa = (pa_ppn_base * PAGE_SIZE) | page_offset;

    return TRANSLATE_OK;

page_fault:
    switch (type) {
        case ACCESS_INSN: return TRANSLATE_FETCH_PAGE_FAULT;
        case ACCESS_LOAD: return TRANSLATE_LOAD_PAGE_FAULT;
        case ACCESS_STORE: return TRANSLATE_STORE_PAGE_FAULT;
    }

    __UNREACHABLE;

access_fault:
    switch (type) {
        case ACCESS_INSN: return TRANSLATE_FETCH_ACCESS_FAULT;
        case ACCESS_LOAD: return TRANSLATE_LOAD_ACCESS_FAULT;
        case ACCESS_STORE: return TRANSLATE_STORE_ACCESS_FAULT;
    }

    __UNREACHABLE;
}

void vaddr_raise_exception(mmu_result_t r, uint64_t addr) {
    switch (r) {
        case TRANSLATE_FETCH_PAGE_FAULT:
            cpu_raise_exception(CAUSE_INSN_PAGEFAULT, addr);
            break;
        case TRANSLATE_LOAD_PAGE_FAULT:
            cpu_raise_exception(CAUSE_LOAD_PAGEFAULT, addr);
            break;
        case TRANSLATE_STORE_PAGE_FAULT:
            cpu_raise_exception(CAUSE_STORE_PAGEFAULT, addr);
            break;
        case TRANSLATE_FETCH_ACCESS_FAULT:
            cpu_raise_exception(CAUSE_FETCH_ACCESS, addr);
            break;
        case TRANSLATE_LOAD_ACCESS_FAULT:
            cpu_raise_exception(CAUSE_LOAD_ACCESS, addr);
            break;
        case TRANSLATE_STORE_ACCESS_FAULT:
            cpu_raise_exception(CAUSE_STORE_ACCESS, addr);
            break;
        default: break;
    }
}

#define VADDR_READ_IMPL(size, type, n)                                         \
    type vaddr_read_##size(uint64_t addr) {                                    \
        if (unlikely((addr & ((n) - 1)) != 0)) {                               \
            cpu_raise_exception(CAUSE_MISALIGNED_LOAD, addr);                  \
            return 0;                                                          \
        }                                                                      \
        uint64_t paddr;                                                        \
        mmu_result_t r = vaddr_translate(addr, &paddr, ACCESS_LOAD, false);    \
        if (r != TRANSLATE_OK) {                                               \
            vaddr_raise_exception(r, addr);                                    \
            return 0;                                                          \
        }                                                                      \
        return bus_read(paddr, n);                                             \
    }

VADDR_READ_IMPL(d, uint64_t, 8)
VADDR_READ_IMPL(w, uint32_t, 4)
VADDR_READ_IMPL(s, uint16_t, 2)
VADDR_READ_IMPL(b, uint8_t, 1)

#define VADDR_WRITE_IMPL(size, type, n)                                        \
    void vaddr_write_##size(uint64_t addr, type data) {                        \
        if (unlikely((addr & ((n) - 1)) != 0)) {                               \
            cpu_raise_exception(CAUSE_MISALIGNED_STORE, addr);                 \
            return;                                                            \
        }                                                                      \
        uint64_t paddr;                                                        \
        mmu_result_t r = vaddr_translate(addr, &paddr, ACCESS_STORE, false);   \
        if (r != TRANSLATE_OK) {                                               \
            vaddr_raise_exception(r, addr);                                    \
            return;                                                            \
        }                                                                      \
        rv.dirty_vm = addr; /* not precise, but placing here anyway */         \
        bus_write(paddr, data, n);                                             \
    }

VADDR_WRITE_IMPL(d, uint64_t, 8)
VADDR_WRITE_IMPL(w, uint32_t, 4)
VADDR_WRITE_IMPL(s, uint16_t, 2)
VADDR_WRITE_IMPL(b, uint8_t, 1)

uint32_t vaddr_ifetch(uint64_t addr, size_t *len) {
    if (unlikely((addr & 0x1) != 0)) {
        cpu_raise_exception(CAUSE_MISALIGNED_FETCH, addr);
        return 0;
    }

    uint64_t paddr;
    mmu_result_t r = vaddr_translate(addr, &paddr, ACCESS_INSN, false);

    if (unlikely(r != TRANSLATE_OK)) {
        vaddr_raise_exception(r, addr);
        return 0;
    }

    uint32_t inst = bus_ifetch(paddr);
    if ((inst & 0x3) < 3) {
        *len = 2;
        return inst & 0xffff;
    }

    *len = 4;
    if (likely((paddr & (PAGE_SIZE - 1)) <= PAGE_SIZE - 4))
        return inst;

    uint32_t inst_lo = inst & 0xffff;

    r = vaddr_translate(addr + 2, &paddr, ACCESS_INSN, false);
    if (unlikely(r != TRANSLATE_OK)) {
        vaddr_raise_exception(r, addr + 2);
        return 0;
    }
    uint32_t inst_hi = bus_ifetch(paddr) & 0xffff;

    return inst_lo | (inst_hi << 16);
}

uint32_t vaddr_ifetch_offline(uint64_t addr, uint64_t *pa, size_t *len,
                              bool *success) {
    *pa = *len = 0;
    *success = true;

    if (unlikely((addr & 0x1) != 0))
        goto fail;

    uint64_t paddr;
    mmu_result_t r = vaddr_translate(addr, &paddr, ACCESS_INSN, true);

    if (unlikely(r != TRANSLATE_OK))
        goto fail;

    *pa = paddr;

    if (!paddr_in_pmem(paddr))
        goto fail;

    extern uint64_t dram_read(uint64_t addr, size_t n);

    uint32_t inst = dram_read(paddr, 4);
    if ((inst & 0x3) < 3) {
        *len = 2;
        return inst & 0xffff;
    }

    *len = 4;
    if (likely((paddr & (PAGE_SIZE - 1)) <= PAGE_SIZE - 4))
        return inst;

    uint32_t inst_lo = inst & 0xffff;

    r = vaddr_translate(addr + 2, &paddr, ACCESS_INSN, true);
    if (unlikely(r != TRANSLATE_OK))
        goto fail;

    uint32_t inst_hi = dram_read(paddr, 2);

    return inst_lo | (inst_hi << 16);

fail:
    *success = false;
    return 0;
}
