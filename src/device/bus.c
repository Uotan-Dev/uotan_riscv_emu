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

uint64_t bus_read(uint64_t addr, size_t n) {
    size_t i = bus_check_addr(addr);
    if (i >= rv.bus.num_devices) {
        Warn("bus_read() error, addr 0x%08" PRIu64 "", addr);
        cpu_raise_exception(CAUSE_LOAD_ACCESS, addr);
        return 0;
    }
    device_t *dev = &rv.bus.devices[i];
    return dev->read(addr, n);
}

void bus_write(uint64_t addr, uint64_t value, size_t n) {
    size_t i = bus_check_addr(addr);
    if (i >= rv.bus.num_devices) {
        Warn("bus_write() error, addr 0x%08" PRIu64 "", addr);
        cpu_raise_exception(CAUSE_STORE_ACCESS, addr);
        return;
    }
    device_t *dev = &rv.bus.devices[i];
    dev->write(addr, value, n);
}

size_t bus_check_addr(uint64_t addr) {
    bus_t *bus = &rv.bus;
    for (size_t i = 0; i < bus->num_devices; i++) {
        device_t *dev = &bus->devices[i];
        if (addr >= dev->start && addr <= dev->end)
            return i;
    }
    return (size_t)-1;
}
