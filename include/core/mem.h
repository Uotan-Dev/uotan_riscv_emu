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
#include <stddef.h>
#include <stdint.h>

#include "riscv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Host memory operations*/

#define GUEST_TO_HOST(paddr) ((void *)(rv.memory + ((uint64_t)(paddr) - MBASE)))
#define HOST_TO_GUEST(haddr)                                                   \
    ((uint64_t)((void *)(haddr) - (void *)rv.memory + MBASE))

/* Physical address operations */

FORCE_INLINE bool addr_in_range(uint64_t addr, uint64_t base, size_t n) {
    return addr >= base && addr < base + n;
}

FORCE_INLINE bool paddr_in_pmem(uint64_t addr) {
    return addr_in_range(addr, MBASE, MSIZE);
}

/* Virtual address operations */

uint64_t vaddr_read_d(uint64_t addr);
uint32_t vaddr_read_w(uint64_t addr);
uint16_t vaddr_read_s(uint64_t addr);
uint8_t vaddr_read_b(uint64_t addr);

void vaddr_write_d(uint64_t addr, uint64_t data);
void vaddr_write_w(uint64_t addr, uint32_t data);
void vaddr_write_s(uint64_t addr, uint16_t data);
void vaddr_write_b(uint64_t addr, uint8_t data);

uint32_t vaddr_ifetch(uint64_t addr);

/* Paging */

#define SATP_MODE_BARE 0ULL
#define SATP_MODE_SV39 8ULL

#define PAGE_SHIFT 12ULL
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PTE_SIZE 8ULL
#define VPN_BITS 9ULL
#define SV39_LEVELS 3
#define SV39_VA_BITS 39
#define SV39_VA_MASK ((1ULL << SV39_VA_BITS) - 1)
#define SV39_SEXT_MASK (~SV39_VA_MASK)

// PTE fields
#define PTE_V (1ULL << 0)
#define PTE_R (1ULL << 1)
#define PTE_W (1ULL << 2)
#define PTE_X (1ULL << 3)
#define PTE_U (1ULL << 4)
#define PTE_G (1ULL << 5)
#define PTE_A (1ULL << 6)
#define PTE_D (1ULL << 7)
#define PTE_PPN_SHIFT 10
#define PTE_PPN_BITS 44ULL
#define PTE_PPN_MASK (((1ULL << PTE_PPN_BITS) - 1ULL) << PTE_PPN_SHIFT)

// VA fields
#define VA_VPN2_SHIFT 30
#define VA_VPN1_SHIFT 21
#define VA_VPN0_SHIFT 12
#define VA_OFFSET_SHIFT 0
#define VA_VPN_MASK ((1ULL << VPN_BITS) - 1)
#define VA_OFFSET_MASK ((1ULL << PAGE_SHIFT) - 1)

// Memory access type
typedef enum {
    ACCESS_INSN = 0,
    ACCESS_LOAD = 1,
    ACCESS_STORE = 2
} mmu_access_t;

// MMU translate result
typedef enum {
    TRANSLATE_OK = 0,
    TRANSLATE_FETCH_PAGE_FAULT = 1,
    TRANSLATE_LOAD_PAGE_FAULT = 2,
    TRANSLATE_STORE_PAGE_FAULT = 3,
    TRANSLATE_ACCESS_FAULT = 4
} mmu_result_t;

#ifdef __cplusplus
}
#endif
