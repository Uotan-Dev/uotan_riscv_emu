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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/mem.h"
#include "core/riscv.h"

static uint64_t dram_read(uint64_t addr, size_t n) {
    void *host_addr = GUEST_TO_HOST(addr);
    switch (n) {
        case 1: return *(uint8_t *)host_addr;
        case 2: return *(uint16_t *)host_addr;
        case 4: return *(uint32_t *)host_addr;
        case 8: return *(uint64_t *)host_addr;
        default: __UNREACHABLE;
    }
}

static void dram_write(uint64_t addr, uint64_t value, size_t n) {
    void *host_addr = GUEST_TO_HOST(addr);
    switch (n) {
        case 1: *(uint8_t *)host_addr = value; return;
        case 2: *(uint16_t *)host_addr = value; return;
        case 4: *(uint32_t *)host_addr = value; return;
        case 8: *(uint64_t *)host_addr = value; return;
        default: __UNREACHABLE;
    }
}

void dram_init() {
    // Fill the memory with random junk
    srand(time(NULL));
    memset(rv.memory, rand(), sizeof(rv.memory));

    rv_add_device((device_t){
        .name = "DRAM",
        .start = MBASE,
        .end = MBASE + MSIZE - 1ULL,
        .read = dram_read,
        .write = dram_write,
    });
}
