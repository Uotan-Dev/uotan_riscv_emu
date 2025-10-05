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

#define _GNU_SOURCE
#include <errno.h> // IWYU pragma: keep
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "utils/timer.h"

// absolute monotonic ms as sampled by background thread
static atomic_uint_fast64_t sampled_ms = 0;

// publish point for "restart" - elapsed = sampled_ms - start_ms
static atomic_uint_fast64_t start_ms = 0;

static atomic_bool sampler_running = false;
static pthread_t sampler_thread;
static uint32_t sampler_period_ms = 1;

static void *sampler_fn(void *arg);

static inline uint64_t timespec_to_ms(const struct timespec *ts) {
    return (uint64_t)ts->tv_sec * 1000ULL +
           (uint64_t)(ts->tv_nsec / 1000000ULL);
}

// Start the sampler thread. sample_period_ms must be > 0 (ms).
// Returns 0 on success, -1 on error.
int timer_start(uint32_t sample_period_ms_arg) {
    if (sample_period_ms_arg == 0)
        sample_period_ms_arg = 1;

    bool expected = false;
    if (!atomic_compare_exchange_strong(&sampler_running, &expected, true))
        return 0;

    sampler_period_ms = sample_period_ms_arg;

    // initialize sampled_ms and start_ms from current host clock
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        // restore running flag
        atomic_store(&sampler_running, false);
        return -1;
    }
    uint64_t now_ms = timespec_to_ms(&now);
    atomic_store(&sampled_ms, now_ms);
    atomic_store(&start_ms, now_ms);

    int rc = pthread_create(&sampler_thread, NULL, sampler_fn, NULL);
    if (rc != 0) {
        atomic_store(&sampler_running, false);
        return -1;
    }
    return 0;
}

// Restart/reset the "start" point so that timer_get_milliseconds() returns 0
// immediately after.
void timer_restart() {
    uint64_t cur = atomic_load_explicit(&sampled_ms, memory_order_acquire);
    atomic_store_explicit(&start_ms, cur, memory_order_release);
}

// Return elapsed milliseconds since last restart (or since timer_start() if
// never restarted). This function does NOT call clock_gettime(); it reads the
// most recently sampled value. Caller must ensure timer_start() has been called
// before using this function.
uint64_t timer_get_milliseconds() {
    uint64_t cur = atomic_load_explicit(&sampled_ms, memory_order_acquire);
    uint64_t base = atomic_load_explicit(&start_ms, memory_order_acquire);
    return cur - base;
}

// Return the last sampled absolute monotonic ms value (no clock_gettime
// inside).
uint64_t timer_get_absolute_ms() {
    return atomic_load_explicit(&sampled_ms, memory_order_acquire);
}

// Stop the sampler thread and join. Safe to call multiple times.
void timer_stop() {
    bool expected = true;
    if (!atomic_compare_exchange_strong(&sampler_running, &expected, false)) {
        // not running
        return;
    }

    // Wait for thread to exit
    pthread_join(sampler_thread, NULL);
}

// Sampler thread function: sleeps until next absolute sample point using
// CLOCK_MONOTONIC and clock_nanosleep(TIMER_ABSTIME) to reduce drift. Writes
// absolute ms into sampled_ms.
static void *sampler_fn(void *arg) {
    (void)arg;
    struct timespec next;
    if (clock_gettime(CLOCK_MONOTONIC, &next) != 0) {
        // can't sample; stop
        atomic_store(&sampler_running, false);
        return NULL;
    }

    // align next to the next sampling boundary
    unsigned p = sampler_period_ms;
    long add_sec = p / 1000;
    long add_nsec = (p % 1000) * 1000000L;

    next.tv_sec += add_sec;
    next.tv_nsec += add_nsec;
    if (next.tv_nsec >= 1000000000L) {
        next.tv_sec += 1;
        next.tv_nsec -= 1000000000L;
    }

    while (atomic_load_explicit(&sampler_running, memory_order_acquire)) {
        // sleep until next absolute time
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
        if (rc != 0 && rc != EINTR) {
            // serious error - stop
            atomic_store(&sampler_running, false);
            break;
        }

        // sample current time and publish
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            uint64_t now_ms = timespec_to_ms(&now);
            atomic_store_explicit(&sampled_ms, now_ms, memory_order_release);
        }

        // advance next by p ms (keep using integer arithmetic to avoid drift
        // accumulation)
        next.tv_sec += add_sec;
        next.tv_nsec += add_nsec;
        if (next.tv_nsec >= 1000000000L) {
            next.tv_sec += 1;
            next.tv_nsec -= 1000000000L;
        }
    }

    return NULL;
}

time_t mktimegm(struct tm *tm) {
    time_t t;
    int y = tm->tm_year + 1900, m = tm->tm_mon + 1, d = tm->tm_mday;
    if (m < 3) {
        m += 12;
        y--;
    }
    t = 86400ULL * (d + (153 * m - 457) / 5 + 365 * y + y / 4 - y / 100 +
                    y / 400 - 719469);
    t += 3600 * tm->tm_hour + 60 * tm->tm_min + tm->tm_sec;
    return t;
}
