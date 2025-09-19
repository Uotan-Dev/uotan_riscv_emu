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

/* Virtual address operations */

#define VADDR_READ_IMPL(size, type)                                            \
    type vaddr_read_##size(uint64_t addr) { return paddr_read_##size(addr); }

VADDR_READ_IMPL(d, uint64_t)
VADDR_READ_IMPL(w, uint32_t)
VADDR_READ_IMPL(s, uint16_t)
VADDR_READ_IMPL(b, uint8_t)

#define VADDR_WRITE_IMPL(size, type)                                           \
    void vaddr_write_##size(uint64_t addr, type data) {                        \
        paddr_write_##size(addr, data);                                        \
    }

VADDR_WRITE_IMPL(d, uint64_t)
VADDR_WRITE_IMPL(w, uint32_t)
VADDR_WRITE_IMPL(s, uint16_t)
VADDR_WRITE_IMPL(b, uint8_t)

uint64_t vaddr_ifetch(uint64_t addr) { return paddr_read_w(addr); }
