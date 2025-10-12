/*
 * Goldfish virtual platform RTC
 *
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 * Copyright (C) 2025 Nuo Shen, Nanjing University
 *
 * For more details on Google Goldfish virtual platform refer:
 * https://android.googlesource.com/platform/external/qemu/+/refs/heads/emu-2.0-release/docs/GOLDFISH-VIRTUAL-HARDWARE.TXT
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/riscv.h"
#include "device/goldfish_rtc.h"
#include "device/plic.h"
#include "utils/logger.h"

#define RTC_TIME_LOW 0x00
#define RTC_TIME_HIGH 0x04
#define RTC_ALARM_LOW 0x08
#define RTC_ALARM_HIGH 0x0c
#define RTC_IRQ_ENABLED 0x10
#define RTC_CLEAR_ALARM 0x14
#define RTC_ALARM_STATUS 0x18
#define RTC_CLEAR_INTERRUPT 0x1c

typedef struct {
    uint64_t tick_offset;   // Offset between host time and guest time
    uint64_t alarm_next;    // The time for the next alarm
    uint32_t alarm_running; // Flag indicating if an alarm is set
    uint32_t irq_pending;   // Flag indicating if an interrupt is pending
    uint32_t irq_enabled;   // Flag for the interrupt enable register
    uint32_t time_high;     // Latched high 32 bits of the current time

    // protects alarm fields and irq fields
    pthread_mutex_t m;
} rtc_t;

static rtc_t rtc;

static uint64_t get_host_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

// Helper to get the current emulated time in nanoseconds
static uint64_t rtc_get_count() { return get_host_time_ns() + rtc.tick_offset; }

// Update the IRQ line to the PLIC
static void rtc_update_irq() {
    plic_set_irq(RTC_IRQ, (rtc.irq_pending && rtc.irq_enabled) ? 1 : 0);
}

// Called when an alarm fires
static void rtc_interrupt() {
    rtc.alarm_running = 0;
    rtc.irq_pending = 1;
    rtc_update_irq();
}

static void rtc_clear_alarm() { rtc.alarm_running = 0; }

static void rtc_set_alarm() {
    uint64_t ticks = rtc_get_count();
    uint64_t event = rtc.alarm_next;

    if (event <= ticks) {
        rtc_clear_alarm();
        rtc_interrupt();
    } else {
        rtc.alarm_running = 1;
    }
}

static uint64_t rtc_read(uint64_t addr, size_t n) {
    uint64_t offset = addr - RTC_BASE;
    uint64_t r = 0;

    /*
     * From the documentation linked at the top of the file:
     *
     *   To read the value, the kernel must perform an IO_READ(TIME_LOW), which
     *   returns an unsigned 32-bit value, before an IO_READ(TIME_HIGH), which
     *   returns a signed 32-bit value, corresponding to the higher half of the
     *   full value.
     */

    switch (offset) {
        case RTC_TIME_LOW:
            r = rtc_get_count();
            rtc.time_high = r >> 32;
            r &= 0xffffffff;
            break;
        case RTC_TIME_HIGH: r = rtc.time_high; break;
        case RTC_ALARM_LOW:
            pthread_mutex_lock(&rtc.m);
            r = rtc.alarm_next & 0xffffffff;
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_ALARM_HIGH:
            pthread_mutex_lock(&rtc.m);
            r = rtc.alarm_next >> 32;
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_IRQ_ENABLED:
            pthread_mutex_lock(&rtc.m);
            r = rtc.irq_enabled;
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_ALARM_STATUS:
            pthread_mutex_lock(&rtc.m);
            r = rtc.alarm_running;
            pthread_mutex_unlock(&rtc.m);
            break;
        default: break;
    }

    return r;
}

static void rtc_write(uint64_t addr, uint64_t value, size_t n) {
    uint64_t offset = addr - RTC_BASE;
    uint64_t current_tick, new_tick;

    value &= 0xFFFFFFFF;

    switch (offset) {
        case RTC_TIME_LOW:
            current_tick = rtc_get_count();
            new_tick = (current_tick & 0xFFFFFFFF00000000) | value;
            rtc.tick_offset += new_tick - current_tick;
            break;
        case RTC_TIME_HIGH:
            current_tick = rtc_get_count();
            new_tick = (current_tick & 0x00000000FFFFFFFF) | (value << 32);
            rtc.tick_offset += new_tick - current_tick;
            break;
        case RTC_ALARM_LOW:
            pthread_mutex_lock(&rtc.m);
            rtc.alarm_next = (rtc.alarm_next & 0xFFFFFFFF00000000) | value;
            rtc_set_alarm();
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_ALARM_HIGH:
            pthread_mutex_lock(&rtc.m);
            rtc.alarm_next =
                (rtc.alarm_next & 0x00000000FFFFFFFF) | (value << 32);
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_IRQ_ENABLED:
            pthread_mutex_lock(&rtc.m);
            rtc.irq_enabled = value & 1;
            rtc_update_irq();
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_CLEAR_ALARM:
            pthread_mutex_lock(&rtc.m);
            rtc_clear_alarm();
            pthread_mutex_unlock(&rtc.m);
            break;
        case RTC_CLEAR_INTERRUPT:
            pthread_mutex_lock(&rtc.m);
            rtc.irq_pending = 0;
            rtc_update_irq();
            pthread_mutex_unlock(&rtc.m);
            break;
        default: break;
    }
}

void rtc_tick() {
    pthread_mutex_lock(&rtc.m);

    if (!rtc.alarm_running) {
        pthread_mutex_unlock(&rtc.m);
        return;
    }

    if (rtc_get_count() >= rtc.alarm_next)
        rtc_interrupt();

    pthread_mutex_unlock(&rtc.m);
}

void rtc_init() {
    memset(&rtc, 0, sizeof(rtc));
    pthread_mutex_init(&rtc.m, NULL);

    rtc.tick_offset = (uint64_t)time(NULL) * 1000000000 - get_host_time_ns();

    rv_add_device((device_t){
        .name = "Goldfish virtual platform RTC",
        .start = RTC_BASE,
        .end = RTC_BASE + RTC_SIZE - 1ULL,
        .read = rtc_read,
        .write = rtc_write,
    });
}

void rtc_destory() {
    int rc = pthread_mutex_destroy(&rtc.m);
    if (rc)
        log_warn("destroy rtc lock failed");
}
