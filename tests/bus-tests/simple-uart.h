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

#define SIMPLE_UART_BASE_ADDR 0x1000

uint64_t simple_uart_read(const void *data, uint64_t addr, size_t n);
void simple_uart_write(void *data, uint64_t addr, uint64_t value, size_t n);

#ifdef __cplusplus
}
#endif
