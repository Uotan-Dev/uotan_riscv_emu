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

#include <string.h>

#include "core/cpu.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "device/clint.h"
#include "utils/misc.h"
#include "utils/timer.h"

typedef struct {
    uint32_t msip;
    uint64_t mtimecmp;
    uint64_t mtime;
} clint_t;

static clint_t clint;

static uint64_t clint_read(uint64_t addr, size_t n) {
    const uint64_t mask = make_mask_bytes(n);

    uint64_t offset = 0;
    uint64_t reg_val = 0;

    if (addr_in_range(addr, CLINT_MSIP_ADDR, sizeof(clint.msip))) {
        reg_val = clint.msip;
        offset = addr - CLINT_MSIP_ADDR;
    } else if (addr_in_range(addr, CLINT_MTIMECMP_ADDR,
                             sizeof(clint.mtimecmp))) {
        reg_val = clint.mtimecmp;
        offset = addr - CLINT_MTIMECMP_ADDR;
    } else if (addr_in_range(addr, CLINT_MTIME_ADDR, sizeof(clint.mtime))) {
        reg_val = clint.mtime;
        offset = addr - CLINT_MTIME_ADDR;
    } else {
        return 0;
    }

    return (reg_val >> (offset * 8)) & mask;
}

static void clint_write(uint64_t addr, uint64_t value, size_t n) {
    const uint64_t mask = make_mask_bytes(n);

    uint64_t offset = 0;

    if (addr_in_range(addr, CLINT_MSIP_ADDR, sizeof(clint.msip))) {
        offset = addr - CLINT_MSIP_ADDR;
        if (n == 4 && offset == 0) {
            clint.msip = (uint32_t)(value & 0xFFFFFFFF);
        } else {
            uint64_t reg_value = clint.msip;
            reg_value &= ~(mask << (offset * 8));
            reg_value |= (value & mask) << (offset * 8);
            clint.msip = (uint32_t)(reg_value & 0xFFFFFFFF);
        }
    } else if (addr_in_range(addr, CLINT_MTIMECMP_ADDR,
                             sizeof(clint.mtimecmp))) {
        offset = addr - CLINT_MTIMECMP_ADDR;
        if (n >= 8 && offset == 0) {
            clint.mtimecmp = value;
        } else {
            uint64_t reg_value = clint.mtimecmp;
            reg_value &= ~(mask << (offset * 8));
            reg_value |= (value & mask) << (offset * 8);
            clint.mtimecmp = reg_value;
        }
    }
    // CLINT_MTIME_ADDR is read-only by convention
}

void clint_init() {
    memset(&clint, 0, sizeof(clint_t));

    clint.mtimecmp = UINT64_MAX;
    rv_add_device((device_t){
        .name = "CLINT",
        .start = CLINT_BASE,
        .end = CLINT_BASE + CLINT_SIZE - 1ULL,
        .read = clint_read,
        .write = clint_write,
    });
}

void clint_tick() {
    rv.MTIME = clint.mtime = timer_get_milliseconds() * 1000;

    // A machine timer interrupt becomes pending whenever mtime contains a value
    // greater than or equal to mtimecmp
    if (clint.mtime >= clint.mtimecmp)
        cpu_write_csr(CSR_MIP, cpu_read_csr(CSR_MIP) | MIP_MTIP);
    else
        cpu_write_csr(CSR_MIP, cpu_read_csr(CSR_MIP) & ~MIP_MTIP);

    if (clint.msip & 1)
        cpu_write_csr(CSR_MIP, cpu_read_csr(CSR_MIP) | MIP_MSIP);
    else
        cpu_write_csr(CSR_MIP, cpu_read_csr(CSR_MIP) & ~MIP_MSIP);
}
