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

#include <assert.h>

#include "core/cpu.h"
#include "device/bus.h"

void bus_init() { rv.bus.num_devices = 0; }

void bus_add_device(device_t dev) {
    bus_t *bus = &rv.bus;
    if (unlikely(bus->num_devices >= MAX_DEVICES)) {
        Error("Too many devices!");
        return;
    }
    bus->devices[bus->num_devices++] = dev;
}

#define BUS_DRAM_IDX 0
#define BUS_IDX_INVALID SIZE_MAX

// Get idx for non-DRAM devices
static inline size_t bus_get_idx(uint64_t addr) {
    for (size_t i = BUS_DRAM_IDX + 1; i < rv.bus.num_devices; i++) {
        device_t *dev = &rv.bus.devices[i];
        if (addr >= dev->start && addr <= dev->end)
            return i;
    }
    return BUS_IDX_INVALID;
}

uint64_t bus_read(uint64_t addr, size_t n) {
    // DRAM is always at idx 0
    // See src/core/riscv.c
    if (likely(paddr_in_pmem(addr)))
        return rv.bus.devices[BUS_DRAM_IDX].read(addr, n);
    size_t i = bus_get_idx(addr);
    if (unlikely(i == BUS_IDX_INVALID)) {
        fprintf(stderr, "bus_read() error, addr 0x%08" PRIx64 "\n", addr);
        cpu_raise_exception(CAUSE_LOAD_ACCESS, addr);
        return 0;
    }
    assert(rv.bus.devices[i].read);
    return rv.bus.devices[i].read(addr, n);
}

uint32_t bus_ifetch(uint64_t addr) {
    if (likely(paddr_in_pmem(addr)))
        return rv.bus.devices[BUS_DRAM_IDX].read(addr, 4);
    fprintf(stderr, "bus_ifetch() error, addr 0x%08" PRIx64 "\n", addr);
    cpu_raise_exception(CAUSE_FETCH_ACCESS, addr);
    return 0;
}

void bus_write(uint64_t addr, uint64_t value, size_t n) {
    if (likely(paddr_in_pmem(addr))) {
        rv.bus.devices[0].write(addr, value, n);
        return;
    }
    size_t i = bus_get_idx(addr);
    if (unlikely(i == BUS_IDX_INVALID)) {
        fprintf(stderr, "bus_write() error, addr 0x%08" PRIx64 "\n", addr);
        cpu_raise_exception(CAUSE_STORE_ACCESS, addr);
        return;
    }
    assert(rv.bus.devices[i].write);
    rv.bus.devices[i].write(addr, value, n);
}
