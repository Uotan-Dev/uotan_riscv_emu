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
#include <stdio.h>

#include "simple-uart.h"

uint64_t simple_uart_read(const void *data, uint64_t addr, size_t n) {
    uint64_t off = addr - SIMPLE_UART_BASE_ADDR;
    assert(off == 0);
    return -1;
}

void simple_uart_write(void *data, uint64_t addr, uint64_t value, size_t n) {
    uint64_t off = addr - SIMPLE_UART_BASE_ADDR;
    assert(off == 0 && n == 4);
    putchar((int)value);
}
