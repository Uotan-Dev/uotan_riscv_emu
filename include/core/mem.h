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

#define PAGE_SHIFT 12ULL
#define PAGE_SIZE (1ULL << PAGE_SHIFT)

#define GUEST_TO_HOST(paddr) ((void *)(rv.memory + ((uint64_t)(paddr) - MBASE)))
#define HOST_TO_GUEST(haddr)                                                   \
    ((uint64_t)((void *)(haddr) - (void *)rv.memory + MBASE))

/**
 * @brief Checks whether a physical address falls within a given range.
 *
 * @param addr  The physical address to check.
 * @param base  The base address of the range.
 * @param n     The size (in bytes) of the range.
 * @return true if addr is within [base, base + n), false otherwise.
 */
FORCE_INLINE bool addr_in_range(uint64_t addr, uint64_t base, size_t n) {
    return addr >= base && addr < base + n;
}

/**
 * @brief Determines whether a physical address belongs to main memory (PMEM).
 *
 * @param addr  The physical address to test.
 * @return true if the address lies within the physical memory region
 *         [MBASE, MBASE + MSIZE), false otherwise.
 */
FORCE_INLINE bool paddr_in_pmem(uint64_t addr) {
    return addr_in_range(addr, MBASE, MSIZE);
}

/**
 * @brief Calculates the page number in DRAM for a physical address.
 *
 * @param pa  The physical address to calculate.
 * @return DRAM page number of the physical address
 */
FORCE_INLINE size_t paddr_get_pmem_pg_id(uint64_t pa) {
    assert(paddr_in_pmem(pa));
    return (pa - MBASE) >> PAGE_SHIFT;
}

/**
 * @brief Reads a 64-bit doubleword from the specified virtual address.
 *
 * Performs address translation under SV39 and returns the value
 * read from the corresponding physical memory.
 *
 * @param addr  The virtual address to read from.
 * @return The 64-bit value loaded from memory.
 */
uint64_t vaddr_read_d(uint64_t addr);

/**
 * @brief Reads a 32-bit word from the specified virtual address.
 *
 * @param addr  The virtual address to read from.
 * @return The 32-bit value loaded from memory.
 */
uint32_t vaddr_read_w(uint64_t addr);

/**
 * @brief Reads a 16-bit halfword from the specified virtual address.
 *
 * @param addr  The virtual address to read from.
 * @return The 16-bit value loaded from memory.
 */
uint16_t vaddr_read_s(uint64_t addr);

/**
 * @brief Reads an 8-bit byte from the specified virtual address.
 *
 * @param addr  The virtual address to read from.
 * @return The 8-bit value loaded from memory.
 */
uint8_t vaddr_read_b(uint64_t addr);

/**
 * @brief Writes a 64-bit doubleword to the specified virtual address.
 *
 * @param addr  The virtual address to write to.
 * @param data  The 64-bit value to store.
 */
void vaddr_write_d(uint64_t addr, uint64_t data);

/**
 * @brief Writes a 32-bit word to the specified virtual address.
 *
 * @param addr  The virtual address to write to.
 * @param data  The 32-bit value to store.
 */
void vaddr_write_w(uint64_t addr, uint32_t data);

/**
 * @brief Writes a 16-bit halfword to the specified virtual address.
 *
 * @param addr  The virtual address to write to.
 * @param data  The 16-bit value to store.
 */
void vaddr_write_s(uint64_t addr, uint16_t data);

/**
 * @brief Writes an 8-bit byte to the specified virtual address.
 *
 * @param addr  The virtual address to write to.
 * @param data  The 8-bit value to store.
 */
void vaddr_write_b(uint64_t addr, uint8_t data);

/**
 * @brief Fetches a instruction from the specified virtual address.
 *
 * Performs instruction fetch translation under SV39 and returns the
 * instruction word from the corresponding physical memory.
 *
 * @param addr  The virtual address of the instruction to fetch.
 * @param len  The pointer where it outputs real instruction size.
 * @return The 32-bit instruction word.
 */
uint32_t vaddr_ifetch(uint64_t addr, size_t *len);

// SATP Mode
#define SATP_MODE_BARE 0ULL
#define SATP_MODE_SV39 8ULL

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
    TRANSLATE_FETCH_PAGE_FAULT,
    TRANSLATE_LOAD_PAGE_FAULT,
    TRANSLATE_STORE_PAGE_FAULT,
    TRANSLATE_FETCH_ACCESS_FAULT,
    TRANSLATE_LOAD_ACCESS_FAULT,
    TRANSLATE_STORE_ACCESS_FAULT,
} mmu_result_t;

#ifdef __cplusplus
}
#endif
