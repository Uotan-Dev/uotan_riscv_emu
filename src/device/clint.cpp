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

#include <atomic>
#include <cstring>

#include "core/cpu.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "device/clint.h"
#include "utils/misc.h"
#include "utils/slowtimer.h"

typedef struct {
    std::atomic_uint_fast32_t msip;
    std::atomic_uint_fast64_t mtimecmp;
    std::atomic_uint_fast64_t mtime;
} clint_t;

static uint64_t clint_start;
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
    clint.msip = 0;
    clint.mtime = 0;
    clint.mtimecmp = UINT64_MAX;
    clint_start = slowtimer_get_microseconds();

    rv_add_device((device_t){
        .name = "CLINT",
        .start = CLINT_BASE,
        .end = CLINT_BASE + CLINT_SIZE - 1ULL,
        .read = clint_read,
        .write = clint_write,
    });
}

void clint_tick() {
    rv.MTIME = clint.mtime = slowtimer_get_microseconds() - clint_start;

    // A machine timer interrupt becomes pending whenever mtime contains a value
    // greater than or equal to mtimecmp
    if (clint.mtime >= clint.mtimecmp)
        cpu_raise_intr(MIP_MTIP, PRIV_M);
    else
        cpu_clear_intr(MIP_MTIP, PRIV_M);

    if (clint.msip & 1)
        cpu_raise_intr(MIP_MSIP, PRIV_M);
    else
        cpu_clear_intr(MIP_MSIP, PRIV_M);
}
