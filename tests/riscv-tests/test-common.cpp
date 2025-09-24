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

#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

#include "../utils/test_utils.hpp"
#include "core/mem.h"
#include "core/riscv.h"
#include "test-common.hpp"

#define RISCV_TEST_TOHOST UINT64_C(0x0000000080001000)

extern "C" void __cpu_exec_once();

bool test_binary(std::string bin) {
    std::vector<char> buffer;
    load_file(bin, buffer);
    rv_init(buffer.data(), buffer.size());
    const auto time_start = std::chrono::high_resolution_clock::now();
    bool timeout = false, failed_on_exception = false;
    uint64_t a0 = -1;

    auto get_milliseconds = [&time_start]() -> uint64_t {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                                     time_start)
            .count();
    };

    while (!timeout) {
        __cpu_exec_once();
        volatile uint8_t *p =
            static_cast<volatile uint8_t *>(GUEST_TO_HOST(RISCV_TEST_TOHOST));
        assert(p);
        if (*p) [[unlikely]] {
            a0 = rv.X[10]; // Read a0 register
            break;
        }
        if (rv.last_exception != CAUSE_EXCEPTION_NONE && rv.MTVEC == 0 &&
            rv.STVEC == 0) {
            failed_on_exception = true;
            break;
        }
        timeout = get_milliseconds() > 1200;
    }

    if (a0 == 0)
        return true;

    if (timeout) {
        std::cerr << "===========================\n";
        std::cerr << bin << " Timeout" << std::endl;
    } else if (failed_on_exception) {
        std::cerr << "===========================\n";
        std::cerr << bin << " Caused unexpected exception" << std::endl;
        std::cerr << "Exception " << rv.last_exception << std::endl;
    } else {
        std::cerr << "===========================\n";
        std::cerr << bin << " Finished with non-zero a0 (a0=" << a0 << ")\n";
    }
    std::cerr << "failed at pc 0x" << std::hex << std::setw(16)
              << std::setfill('0') << static_cast<uint64_t>(rv.PC) << std::dec
              << std::setfill(' ') << std::endl;
    std::cerr << "===========================\n";

    return false;
}
