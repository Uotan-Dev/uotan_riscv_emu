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

#include <cassert>
#include <cstring>
#include <signal.h>
#include <sys/time.h>

#include "utils/alarm.h"
#include "utils/logger.h"

#define MAX_HANDLER 16

static alarm_handler_t handlers[MAX_HANDLER];
static size_t handler_cnt;
static bool alarm_run;

void alarm_add_handle(alarm_handler_t h) {
    assert(handler_cnt < MAX_HANDLER);
    assert(h);
    for (size_t i = 0; i < handler_cnt; i++)
        if (h == handlers[i])
            return;
    handlers[handler_cnt++] = h;
    log_info("Added handler %p", h);
}

void alarm_turn(bool on) {
    log_info("New alarm state: %d", (int)on);
    alarm_run = on;
}

void alarm_init() {
    alarm_run = false;

    struct sigaction s;
    memset(&s, 0, sizeof(s));

    // Run handlers one by one
    s.sa_handler = [](int signum) -> void {
        if (!alarm_run)
            return;
        for (size_t i = 0; i < handler_cnt; i++)
            handlers[i]();
    };

    int ret = sigaction(SIGVTALRM, &s, nullptr);
    assert(ret == 0);

    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 1000000 / TIMER_HZ;
    it.it_interval = it.it_value;
    ret = setitimer(ITIMER_VIRTUAL, &it, NULL);
    assert(ret == 0);

    log_info("Alarm initialized");
}
