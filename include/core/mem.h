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

#include "common.h"
#include "riscv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Host memory operations*/

FORCE_INLINE uint64_t host_read(void *addr, size_t len) {
    // clang-format off
    switch (len) {
        case 1: return *(uint8_t *)addr;
        case 2: return *(uint16_t *)addr;
        case 4: return *(uint32_t *)addr;
        case 8: return *(uint64_t *)addr;
        default: __UNREACHABLE;
    }
    // clang-format on
}

FORCE_INLINE void host_write(void *addr, size_t len, uint64_t data) {
    // clang-format off
    switch (len) {
        case 1: *(uint8_t *)addr = data; return;
        case 2: *(uint16_t *)addr = data; return;
        case 4: *(uint32_t *)addr = data; return;
        case 8: *(uint64_t *)addr = data; return;
        default: __UNREACHABLE;
    }
    // clang-format on
}

#define GUEST_TO_HOST(paddr) ((void *)(rv.memory + ((uint64_t)(paddr) - MBASE)))
#define HOST_TO_GUEST(haddr)                                                   \
    ((uint64_t)((void *)(haddr) - (void *)rv.memory + MBASE))

/* Physical address operations */

FORCE_INLINE bool paddr_in_pmem(uint64_t addr) {
    return addr >= MBASE && addr < (uint64_t)MBASE + MSIZE;
}

#define PADDR_READ_IMPL(size, type, len)                                       \
    FORCE_INLINE type paddr_read_##size(uint64_t addr) {                       \
        assert(paddr_in_pmem(addr));                                           \
        return *(type *)GUEST_TO_HOST(addr);                                   \
    }

PADDR_READ_IMPL(d, uint64_t, 8)
PADDR_READ_IMPL(w, uint32_t, 4)
PADDR_READ_IMPL(s, uint16_t, 2)
PADDR_READ_IMPL(b, uint8_t, 1)

#undef PADDR_READ_IMPL

#define PADDR_WRITE_IMPL(size, type, len)                                      \
    FORCE_INLINE void paddr_write_##size(uint64_t addr, type data) {           \
        assert(paddr_in_pmem(addr));                                           \
        *(type *)GUEST_TO_HOST(addr) = data;                                   \
    }

PADDR_WRITE_IMPL(d, uint64_t, 8)
PADDR_WRITE_IMPL(w, uint32_t, 4)
PADDR_WRITE_IMPL(s, uint16_t, 2)
PADDR_WRITE_IMPL(b, uint8_t, 1)

#undef PADDR_WRITE_IMPL

/* Virtual address operations */

uint64_t vaddr_read_d(uint64_t addr);
uint32_t vaddr_read_w(uint64_t addr);
uint16_t vaddr_read_s(uint64_t addr);
uint8_t vaddr_read_b(uint64_t addr);

void vaddr_write_d(uint64_t addr, uint64_t data);
void vaddr_write_w(uint64_t addr, uint32_t data);
void vaddr_write_s(uint64_t addr, uint16_t data);
void vaddr_write_b(uint64_t addr, uint8_t data);

uint64_t vaddr_ifetch(uint64_t addr);

#ifdef __cplusplus
}
#endif
