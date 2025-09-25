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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/riscv.h"
#include "device/rtc.h"
#include "utils/timer.h"

static time_t rtc_ref_timedate() {
    struct timespec ts;
    if (likely(clock_gettime(CLOCK_REALTIME, &ts) == 0))
        return ts.tv_sec;
    else
        return time(NULL);
}

static time_t rtc_timedate_diff(struct tm *tm) {
    time_t s = mktimegm(tm);
    return s - rtc_ref_timedate();
}

static void rtc_get_timedate(struct tm *tm, time_t offset) {
    time_t ti = rtc_ref_timedate() + offset;
    gmtime_r(&ti, tm);
}

//
// ASPEED Real Time Clock
//
// Implementation inspired by QEMU's aspeed_rtc emulation (hw/rtc/aspeed_rtc.c)
// QEMU is licensed under GPL v2 or later.
//
// https://github.com/qemu/qemu/blob/master/hw/rtc/aspeed_rtc.c
//

#define COUNTER1 (0x00 / 4)
#define COUNTER2 (0x04 / 4)
#define ALARM (0x08 / 4)
#define CONTROL (0x10 / 4)
#define ALARM_STATUS (0x14 / 4)

#define RTC_UNLOCKED (1UL << 1)
#define RTC_ENABLED (1UL << 0)

typedef struct {
    uint32_t reg[0x18];
    int64_t offset;
} rtc_t;

static rtc_t rtc;

static void rtc_calc_offset() {
    struct tm tm;

    memset(&tm, 0, sizeof(tm));

    uint32_t year, cent;
    uint32_t reg1 = rtc.reg[COUNTER1];
    uint32_t reg2 = rtc.reg[COUNTER2];

    tm.tm_mday = (reg1 >> 24) & 0x1f;
    tm.tm_hour = (reg1 >> 16) & 0x1f;
    tm.tm_min = (reg1 >> 8) & 0x3f;
    tm.tm_sec = (reg1 >> 0) & 0x3f;

    cent = (reg2 >> 16) & 0x1f;
    year = (reg2 >> 8) & 0x7f;
    tm.tm_mon = ((reg2 >> 0) & 0x0f) - 1;
    tm.tm_year = year + (cent * 100) - 1900;

    rtc.offset = rtc_timedate_diff(&tm);
}

static uint32_t rtc_get_counter(int r) {
    uint32_t year, cent;
    struct tm now;

    rtc_get_timedate(&now, rtc.offset);

    switch (r) {
        case COUNTER1:
            return (now.tm_mday << 24) | (now.tm_hour << 16) |
                   (now.tm_min << 8) | now.tm_sec;
        case COUNTER2:
            cent = (now.tm_year + 1900) / 100;
            year = now.tm_year % 100;
            return ((cent & 0x1f) << 16) | ((year & 0x7f) << 8) |
                   ((now.tm_mon + 1) & 0xf);
        default: __UNREACHABLE;
    }
}

static uint64_t rtc_read(uint64_t addr, size_t n) {
    uint64_t val;
    uint32_t r = addr >> 2;

    switch (r) {
        case COUNTER1:
        case COUNTER2:
            if (rtc.reg[CONTROL] & RTC_ENABLED)
                rtc.reg[r] = rtc_get_counter(r);
            // fall through
        case CONTROL: val = rtc.reg[r]; break;
        case ALARM:
        case ALARM_STATUS:
        default:
            // Unimplemented
            return 0;
    }

    return val;
}

static void rtc_write(uint64_t addr, uint64_t value, size_t n) {
    uint32_t r = addr >> 2;

    switch (r) {
        case COUNTER1:
        case COUNTER2:
            if (!(rtc.reg[CONTROL] & RTC_UNLOCKED))
                break;
            // fall through
        case CONTROL:
            rtc.reg[r] = value;
            rtc_calc_offset();
            break;
        case ALARM:
        case ALARM_STATUS:
        default:
            // Unimplemented
            break;
    }
}

void rtc_init() {
    memset(&rtc, 0, sizeof(rtc_t));

    rtc.reg[CONTROL] = RTC_ENABLED;
    rtc.reg[COUNTER1] = rtc_get_counter(COUNTER1);
    rtc.reg[COUNTER2] = rtc_get_counter(COUNTER2);

    rv_add_device((device_t){
        .name = "ASPEED RTC",
        .start = RTC_BASE,
        .end = RTC_BASE + RTC_SIZE - 1ULL,
        .read = rtc_read,
        .write = rtc_write,
    });
}
