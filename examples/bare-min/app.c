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

#include <stdbool.h>
#include <stdint.h>

#define trap(code) asm volatile("mv a0, %0; ebreak" : :"r"(code))

int main() {
    volatile uint32_t a = 1, b = 2, c = 3;
    volatile uint32_t s = a + b;
    volatile uint32_t p = a * b;
    volatile uint32_t v = s / p;
    volatile uint32_t x = s % p;
    trap(0);
    while (true)
        ;
    return 0;
}
