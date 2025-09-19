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
#include <stdint.h>

#include "common.h"

#define RESET_PC 0x80000000

typedef struct {
    // Interger registers
#define NR_GPR 32
    uint64_t X[NR_GPR];
    uint64_t PC; // Program counter

    // Memory
#define MSIZE 0x8000000
#define MBASE 0x80000000
    uint8_t memory[MSIZE] __attribute((aligned(4096)));

    // Some status
    bool image_loaded; // whether we have loaded the image
    bool halt;         // whether the machine has halted
} riscv_t;

extern riscv_t rv __attribute((aligned(4096)));

// Initialize the machine
void rv_init();

// Load a image
void rv_load_image(const char *path);
void rv_load_default_image();

// Halt the machine
FORCE_INLINE void rv_halt() { rv.halt = true; }
