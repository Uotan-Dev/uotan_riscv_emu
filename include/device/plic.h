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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLIC_BASE 0x0C000000
#define PLIC_SIZE 0x04000000

// clang-format off
// Interrupt source priority registers
#define PLIC_PRIORITY_BASE      0x0C000000
#define PLIC_PRIORITY_SIZE      0x00001000

// Interrupt pending bits
#define PLIC_PENDING_BASE       0x0C001000
#define PLIC_PENDING_SIZE       0x00000080

// Interrupt enable bits
#define PLIC_ENABLE_BASE        0x0C002000
#define PLIC_ENABLE_SIZE        0x001FE000
#define PLIC_ENABLE_CONTEXT_SIZE 0x00000080

// Context configuration
#define PLIC_CONTEXT_BASE       0x0C200000
#define PLIC_CONTEXT_SIZE       0x00200000
#define PLIC_CONTEXT_STRIDE     0x00001000

#define PLIC_CONTEXT_M_MODE     0
#define PLIC_CONTEXT_S_MODE     1

#define PLIC_THRESHOLD_OFFSET   0x00000000
#define PLIC_CLAIM_OFFSET       0x00000004

#define PLIC_M_THRESHOLD_ADDR   (PLIC_CONTEXT_BASE + PLIC_CONTEXT_M_MODE * PLIC_CONTEXT_STRIDE + PLIC_THRESHOLD_OFFSET)
#define PLIC_M_CLAIM_ADDR       (PLIC_CONTEXT_BASE + PLIC_CONTEXT_M_MODE * PLIC_CONTEXT_STRIDE + PLIC_CLAIM_OFFSET)
#define PLIC_S_THRESHOLD_ADDR   (PLIC_CONTEXT_BASE + PLIC_CONTEXT_S_MODE * PLIC_CONTEXT_STRIDE + PLIC_THRESHOLD_OFFSET)
#define PLIC_S_CLAIM_ADDR       (PLIC_CONTEXT_BASE + PLIC_CONTEXT_S_MODE * PLIC_CONTEXT_STRIDE + PLIC_CLAIM_OFFSET)

#define PLIC_M_ENABLE_ADDR      (PLIC_ENABLE_BASE + PLIC_CONTEXT_M_MODE * PLIC_ENABLE_CONTEXT_SIZE)
#define PLIC_S_ENABLE_ADDR      (PLIC_ENABLE_BASE + PLIC_CONTEXT_S_MODE * PLIC_ENABLE_CONTEXT_SIZE)
// clang-format on

#define PLIC_MAX_SOURCES 1024
#define PLIC_MAX_CONTEXTS 2

void plic_init();
void plic_destroy();
void plic_set_irq(uint32_t source, int level);

#ifdef __cplusplus
}
#endif
