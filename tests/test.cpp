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

#include <gtest/gtest.h>
#include <string>

// include test utils
#include "utils/test_utils.hpp"

// include some emu headers
#include "core/cpu.h"
#include "core/riscv.h"

/* Sample Test Suite to try the framework */

TEST(SampleTestSuite, BasicAssertion) { EXPECT_TRUE(true); }

TEST(SampleTestSuite, MathTest) {
    EXPECT_EQ(2 + 2, 4);
    ASSERT_EQ(5 * 5, 25);
}

/* ALU Tests */

#include "alu-tests/gen-tests.hpp"

// RV64IM ALU Tests
TEST(ALUTestSuite, RV64IM_TEST) {
    // Generate the test source
    write_alu_test_file("rv_alu_test.c");

    // clang-format off
    std::string link_ld = 
    "ENTRY(_start)\n"
    "\n"
    "SECTIONS\n"
    "{\n"
    "  . = 0x80000000;\n"
    "\n"
    "  .text : {\n"
    "    KEEP(*(.text*))\n"
    "    KEEP(*(.rodata*))\n"
    "  }\n"
    "\n"
    "  .data : {\n"
    "    *(.data*)\n"
    "  }\n"

    "  .bss : {\n"
    "    __bss_start = .;\n"
    "    *(.bss*)\n"
    "    *(COMMON)\n"
    "    __bss_end = .;\n"
    "  }\n"
    "\n"
    "  PROVIDE(__stack_top = 0x80000000 + 0x8000000 - 0x1000);\n"
    "}\n";
    // clang-format on
    write_file(link_ld, "link.ld");

    // clang-format off
    std::string boot_s =
    "    .section .text\n"
    "    .align  2\n"
    "    .global _start\n"
    "    .extern main\n"
    "\n"
    "_start:\n"
    "    la   sp, __stack_top\n"
    "    li   t0, 0\n"
    "    mv   gp, t0\n"
    "    mv   tp, t0\n"
    "    call main\n"
    "\n"
    "1:  j 1b\n";
    // clang-format on
    write_file(boot_s, "boot.S");

    std::string cc = "riscv64-linux-gnu-gcc";
    // clang-format off
    std::vector<std::string> base_args = {
        cc,
        "-march=rv64im",
        "-mabi=lp64",
        "-fno-common",
        "-fno-builtin",
        "-nostdlib",
        "-ffreestanding",
        "-fno-pic",
        "-mstrict-align",
        "-O2",
        "-Wno-error",
        "-w"
    };
    // clang-format on

    {
        std::vector<std::string> args = base_args;
        args.push_back("-c");
        args.push_back("boot.S");
        args.push_back("-o");
        args.push_back("boot.o");
        int rc = run_process(args);
        ASSERT_EQ(rc, 0);
    }

    {
        std::vector<std::string> args = base_args;
        args.push_back("-c");
        args.push_back("rv_alu_test.c");
        args.push_back("-o");
        args.push_back("rv_alu_test.o");
        int rc = run_process(args);
        ASSERT_EQ(rc, 0);
    }

    {
        std::vector<std::string> args = base_args;
        args.push_back("-o");
        args.push_back("firmware.elf");
        args.push_back("boot.o");
        args.push_back("rv_alu_test.o");
        args.push_back("-T");
        args.push_back("link.ld");
        int rc = run_process(args);
        ASSERT_EQ(rc, 0);
    }

    {
        // clang-format off
        std::vector<std::string> args = {
            "riscv64-linux-gnu-objcopy",
            "-O", "binary",
            "firmware.elf", "firmware.bin"
        };
        // clang-format on
        int rc = run_process(args);
        ASSERT_EQ(rc, 0);
    }

    rv_init();
    rv_load_image("firmware.bin");
    cpu_start();

    EXPECT_EQ(rv.halt_code, 0);
}
