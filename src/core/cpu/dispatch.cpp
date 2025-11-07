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

#include <absl/container/flat_hash_map.h>
#include <asmjit/x86.h>
#include <cinttypes>
#include <pthread.h>
#include <unistd.h>

#include "core/cpu/csr.h"
#include "core/cpu/dispatch.h"
#include "core/cpu/interpreter.h"
#include "core/cpu/jit_v1.hpp"
#include "core/cpu/jit_v2.hpp"
#include "core/cpu/system.h"
#include "core/riscv.h"
#include "device/clint.h"
#include "device/goldfish_battery.h"
#include "device/goldfish_rtc.h"
#include "device/uart16550.h"
#include "ui/ui.h"
#include "utils/alarm.h"
#include "utils/logger.h"
#include "utils/slowtimer.h"

static pthread_t cpu_thread;
static pthread_mutex_t cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cpu_cond = PTHREAD_COND_INITIALIZER;
static bool cpu_thread_running = false;

/* Child CPU thread */
static void *cpu_thread_func(void *arg) {
    // Notify the main thread that the child thread has started
    pthread_mutex_lock(&cpu_mutex);
    cpu_thread_running = true;
    pthread_cond_broadcast(&cpu_cond);
    pthread_mutex_unlock(&cpu_mutex);

    jit_v1 cpu_jit_v1;
    jit_v2 cpu_jit_v2(cpu_jit_v1);

    uint64_t start = slowtimer_get_microseconds();

    while (true) {
        if (unlikely(rv.shutdown))
            break;

        if (cpu_jit_v2.try_run(rv.PC) == 0 && cpu_jit_v1.try_run(rv.PC) == 0)
            cpu_interp_block();
    }

    uint64_t end = slowtimer_get_microseconds();
    double delta = (double)(end - start) / 1000000.0;
    log_info("Simulation time: %f seconds (%" PRIu64 " microseconds)", delta,
             end - start);
    log_info("Simulation speed: %f insts per second", rv.MCYCLE / delta);

    sleep(1);

    // Notify the main thread again
    pthread_mutex_lock(&cpu_mutex);
    cpu_thread_running = false;
    pthread_cond_broadcast(&cpu_cond);
    pthread_mutex_unlock(&cpu_mutex);

    return nullptr;
}

static inline void cpu_thread_start() {
    pthread_mutex_lock(&cpu_mutex);
    if (cpu_thread_running) {
        log_warn("CPU thread already running");
        pthread_mutex_unlock(&cpu_mutex);
        return;
    }

    if (pthread_create(&cpu_thread, nullptr, cpu_thread_func, nullptr) != 0) {
        pthread_mutex_unlock(&cpu_mutex);
        log_error("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    while (!cpu_thread_running)
        pthread_cond_wait(&cpu_cond, &cpu_mutex);
    pthread_mutex_unlock(&cpu_mutex);
}

void cpu_start() {
    alarm_turn(true);

    pthread_cond_init(&cpu_cond, nullptr);
    pthread_mutex_init(&cpu_mutex, nullptr);

    cpu_thread_start();

    while (true) {
        pthread_mutex_lock(&cpu_mutex);
        bool running = cpu_thread_running;
        pthread_mutex_unlock(&cpu_mutex);

        if (!running)
            break;

        // Update UI and framebuffer
        ui_update();

        // Update clint
        clint_tick();
        // Update UART
        uart_tick();
        // Update RTC
        rtc_tick();
        // Update battery
        battery_update();

        // Update stip
        pthread_mutex_lock(&rv.csr_lock);
        bool trigger = rv.MTIME >= rv.STIMECMP;
        pthread_mutex_unlock(&rv.csr_lock);
        if (trigger)
            cpu_raise_intr(SIP_STIP, PRIV_S);
        else
            cpu_clear_intr(SIP_STIP, PRIV_S);
    }

    alarm_turn(false);
    pthread_join(cpu_thread, nullptr);

    pthread_mutex_destroy(&cpu_mutex);
    pthread_cond_destroy(&cpu_cond);
}

#define CPU_EXEC_COMMON()                                                      \
    do {                                                                       \
        static rv_insn_t ir;                                                   \
        rv.last_exception = CAUSE_EXCEPTION_NONE;                              \
        interrupt_t intr = cpu_get_pending_intr();                             \
        if (unlikely(intr != CAUSE_INTERRUPT_NONE))                            \
            cpu_process_intr(intr);                                            \
        cpu_interp_step(&ir);                                                  \
    } while (0)

void cpu_step() {
    alarm_turn(true);
    if (!unlikely(rv.shutdown)) {
        clint_tick();
        uart_tick();
        CPU_EXEC_COMMON();
    }
    alarm_turn(false);
}

void cpu_start_archtest() {
    pthread_cond_init(&cpu_cond, nullptr);
    pthread_mutex_init(&cpu_mutex, nullptr);

    uint64_t start = slowtimer_get_microseconds();

    cpu_thread_start();

    while (true) {
        pthread_mutex_lock(&cpu_mutex);
        bool running = cpu_thread_running;
        pthread_mutex_unlock(&cpu_mutex);

        if (!running)
            break;

        if (slowtimer_get_microseconds() - start > 3200000)
            rv_shutdown(-1, SHUTDOWN_CAUSE_GUEST_PANIC);

        // Update clint
        clint_tick();

        // Update stip
        pthread_mutex_lock(&rv.csr_lock);
        bool trigger = rv.MTIME >= rv.STIMECMP;
        pthread_mutex_unlock(&rv.csr_lock);
        if (trigger)
            cpu_raise_intr(SIP_STIP, PRIV_S);
        else
            cpu_clear_intr(SIP_STIP, PRIV_S);
    }

    pthread_join(cpu_thread, nullptr);

    pthread_mutex_destroy(&cpu_mutex);
    pthread_cond_destroy(&cpu_cond);
}

// clang-format off
static const char *regs[] = {
    "$0", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
    "s0", "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
    "a6", "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};
// clang-format on

void cpu_print_registers() {
    for (size_t i = 0; i < NR_GPR; i++)
        printf("%s\t0x%08" PRIx64 "\n", regs[i], rv.X[i]);
    printf("%s\t0x%08" PRIx64 "\n", "pc", rv.PC);
}
