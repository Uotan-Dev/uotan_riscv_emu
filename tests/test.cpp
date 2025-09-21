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
#include <unistd.h>

// include test utils
#include "utils/test_utils.hpp"

// include some emu headers
#include "core/cpu.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "utils/timer.h"

/* Sample Tests */

TEST(SampleTestSuite, BasicAssertion) { EXPECT_TRUE(true); }

TEST(SampleTestSuite, MathTest) {
    EXPECT_EQ(2 + 2, 4);
    ASSERT_EQ(5 * 5, 25);
}

/* Timer Tests */
TEST(TimerTestSuite, TimerTest) {
    ASSERT_EQ(timer_start(1), 0);

    // wait a little to let sampler publish initial value
    usleep(50 * 1000);

    timer_restart();    // set base to now
    usleep(500 * 1000); // sleep 500 ms
    uint64_t t = timer_get_milliseconds();
    EXPECT_TRUE(t >= 450 && t <= 550);

    // test longer interval
    timer_restart();
    usleep(1500 * 1000); // 1.5s
    t = timer_get_milliseconds();
    EXPECT_TRUE(t >= 1450 && t <= 1550);

    timer_stop();
}

/* M mode Tests */

#include "m_mode-tests/trap_tests.hpp"

TEST(M_modeTestSuite, TRAP_TEST) {
    // Disassembly of section .text:

    // 0000000080000000 <_start>:
    //     80000000:   00000297                auipc   t0,0x0
    //     80000004:   01c28293                addi    t0,t0,28 # 8000001c
    //     <trap_handler> 80000008:   30529073                csrw    mtvec,t0
    //     8000000c:   00a00513                li      a0,10
    //     80000010:   00000073                ecall

    // 0000000080000014 <done>:
    //     80000014:   00100073                ebreak
    //     80000018:   ffdff06f                j       80000014 <done>

    // 000000008000001c <trap_handler>:
    //     8000001c:   02a50513                addi    a0,a0,42
    //     80000020:   34102373                csrr    t1,mepc
    //     80000024:   00430313                addi    t1,t1,4
    //     80000028:   34131073                csrw    mepc,t1
    //     8000002c:   30200073                mret

    rv_init();
    memcpy(GUEST_TO_HOST(RESET_PC), trap_test_firmware_bin,
           sizeof(trap_test_firmware_bin));
    rv.image_loaded = true;
    cpu_step(8);
    ASSERT_EQ(*cpu_get_csr(CSR_MEPC), 0x80000010);
    ASSERT_EQ(*cpu_get_csr(CSR_MCAUSE), CAUSE_MACHINE_ECALL);
    cpu_start();
    ASSERT_EQ(rv.X[10], 52);
}

/* Bus Tests */

#include "bus-tests/simple-uart.h"

TEST(BusTestSuite, BUS_TEST) {
    device_t uart;
    uart.data = NULL;
    uart.start = SIMPLE_UART_BASE_ADDR;
    uart.end = SIMPLE_UART_BASE_ADDR + 8;
    uart.name = "simple_uart";
    uart.read = simple_uart_read;
    uart.write = simple_uart_write;

    rv_add_device(uart);
    uint32_t v = paddr_read_w(SIMPLE_UART_BASE_ADDR);
    ASSERT_EQ(v, static_cast<uint32_t>(-1));
    for (char c : "fuck\n") {
        // Should output "fuck"
        paddr_write_w(SIMPLE_UART_BASE_ADDR, c);
    }
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

    ASSERT_EQ(rv.halt_code, 0);
}
