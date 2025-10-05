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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct __bus bus_t;

// Read / Write function for a device
typedef uint64_t (*read_func_t)(uint64_t addr, size_t n);
typedef void (*write_func_t)(uint64_t addr, uint64_t value, size_t n);

typedef struct {
    const char *name;
    uint64_t start;
    uint64_t end;
    // void *data;
    read_func_t read;
    write_func_t write;
} device_t;

#define MAX_DEVICES 32

struct __bus {
    device_t devices[MAX_DEVICES];
    size_t num_devices;
};

/**
 * @brief Initializes the system bus.
 *
 * This function sets up the bus and internal device mappings.
 * It should be called once during machine initialization before
 * any device access or memory transaction occurs.
 */
void bus_init();

/**
 * @brief Registers a new device on the system bus.
 *
 * This function adds a memory-mapped device to the global bus device table.
 * Each device is typically defined by its address range and read/write
 * callbacks.
 *
 * @param dev  The device descriptor to register, defined by device_t.
 */
void bus_add_device(device_t dev);

/**
 * @brief Reads data from the bus at a given physical address.
 *
 * Performs a memory-mapped I/O or memory access of @p n bytes
 * starting at @p addr. The corresponding device’s read handler
 * will be invoked if the address falls within its mapped range.
 *
 * @param addr  The physical address to read from.
 * @param n     The number of bytes to read (1, 2, 4, or 8).
 * @return The value read from the bus, right-aligned within 64 bits.
 */
uint64_t bus_read(uint64_t addr, size_t n);

/**
 * @brief Writes data to the bus at a given physical address.
 *
 * Performs a memory-mapped I/O or memory write of @p n bytes
 * to @p addr. The corresponding device’s write handler
 * will be invoked if the address falls within its mapped range.
 *
 * @param addr   The physical address to write to.
 * @param value  The data value to write (lower @p n bytes are used).
 * @param n      The number of bytes to write (1, 2, 4, or 8).
 */
void bus_write(uint64_t addr, uint64_t value, size_t n);

/**
 * @brief Fetches a 32-bit instruction from the bus.
 *
 * This function is used for instruction fetches.
 * It reads a 32-bit word from the specified physical address,
 * typically corresponding to main memory or an instruction ROM.
 *
 * @param addr  The physical address of the instruction.
 * @return The 32-bit instruction word.
 */
uint32_t bus_ifetch(uint64_t addr);

#ifdef __cplusplus
}
#endif
