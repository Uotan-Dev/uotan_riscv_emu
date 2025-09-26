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

#include "core/riscv.h"
#include "device/sifive_test.h"
#include "utils/logger.h"

// SiFive Test
// See https://github.com/qemu/qemu/blob/master/hw/misc/sifive_test.c

static uint64_t sifive_test_read(uint64_t addr, size_t n) { return 0; }

static void sifive_test_write(uint64_t addr, uint64_t value, size_t n) {
    if (addr == SIFIVE_TEST_FINISHER_ADDR) {
        int status = value & 0xFFFF;
        int code = (value >> 16) & 0xFFFF;
        switch (status) {
            case SIFIVE_TEST_FINISHER_FAIL:
                rv_shutdown(code, SHUTDOWN_CAUSE_GUEST_PANIC);
                return;
            case SIFIVE_TEST_FINISHER_PASS:
                rv_shutdown(code, SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
                return;
            case SIFIVE_TEST_FINISHER_RESET:
                // FIXME: Reset is treated as Shutdown
                log_warn("sifive_test: Reset is treated as Shutdown");
                rv_shutdown(code, SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
                return;
            default: return;
        }
    }
    __UNREACHABLE;
}

void sifive_test_init() {
    rv_add_device((device_t){
        .name = "SIFIVE TEST",
        .start = SIFIVE_TEST_BASE,
        .end = SIFIVE_TEST_BASE + SIFIVE_TEST_SIZE - 1ULL,
        .read = sifive_test_read,
        .write = sifive_test_write,
    });
}
