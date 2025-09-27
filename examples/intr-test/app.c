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

#define CLINT_BASE 0x02000000UL
#define CLINT_MTIME (CLINT_BASE + 0xBFF8ULL)
#define CLINT_MTIMECMP (CLINT_BASE + 0x4000ULL)

typedef void (*user_trap_handler_t)(void);

static volatile uint64_t success_flag = 0;

extern void trap(void);

#define POWER_OFF_ADDR 0x100000
#define shutdown(code)                                                         \
    do {                                                                       \
        volatile uint32_t *const power_off_reg = (uint32_t *)POWER_OFF_ADDR;   \
        *power_off_reg = ((uint32_t)(code) << 16) | 0x5555;                    \
    } while (0)

void __cust_trap_handler() {
    // set success_flag here
    success_flag = 1;

    volatile uint64_t *mtimecmp = (volatile uint64_t *)CLINT_MTIMECMP;
    *mtimecmp = 0xFFFFFFFFFFFFFFFFULL;
}

int main(void) {
    success_flag = 0;

    // set mtvec
    asm volatile("csrw mtvec, %0" ::"r"(trap));

    // enable machine-timer interrupt
    const uint64_t MIE_MTIE = (1UL << 7);
    asm volatile("csrs mie, %0" ::"r"(MIE_MTIE));

    // enable global machine interrupts
    const uint64_t MSTATUS_MIE = (1UL << 3);
    asm volatile("csrs mstatus, %0" ::"r"(MSTATUS_MIE));

    // program CLINT
    volatile uint64_t *mtime = (volatile uint64_t *)CLINT_MTIME;
    volatile uint64_t *mtimecmp = (volatile uint64_t *)CLINT_MTIMECMP;
    uint64_t now = *mtime;
    const uint64_t DELAY = 1000000;
    *mtimecmp = now + DELAY;

    // wait for interrupt
    for (volatile uint64_t i = 0; i < 100000000ULL; i++) {
        if (success_flag)
            break;
        asm volatile("wfi");
    }

    uint32_t code = success_flag == 1 ? 0 : (uint32_t)-1;
    shutdown(code);
    // asm volatile("mv a0, %0; ebreak" : : "r"(code));

    while (true)
        asm volatile("wfi");
    return 0;
}
