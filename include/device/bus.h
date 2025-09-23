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

void bus_init();
void bus_add_device(device_t dev);
uint64_t bus_read(uint64_t addr, size_t n);
void bus_write(uint64_t addr, uint64_t value, size_t n);
uint32_t bus_ifetch(uint64_t addr);

#ifdef __cplusplus
}
#endif
