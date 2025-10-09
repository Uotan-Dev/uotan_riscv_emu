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
#include <inttypes.h>
#include <string>
#include <unistd.h>

// include some emu headers
#include "core/cpu.h"
#include "core/riscv.h"

/* Sample Tests */

TEST(SampleTestSuite, BasicAssertion) { EXPECT_TRUE(true); }

TEST(SampleTestSuite, MathTest) {
    EXPECT_EQ(2 + 2, 4);
    ASSERT_EQ(5 * 5, 25);
}

/* M mode Tests */

#include "m_mode-tests/trap_tests.hpp"

TEST(M_modeTestSuite, TRAP_TEST) {
    // clang-format off

    // Disassembly of section .text:
    //
    // 0000000080000000 <_start>:
    //     80000000:   00000297                auipc   t0,0x0
    //     80000004:   03028293                addi    t0,t0,48 # 80000030 <trap_handler>
    //     80000008:   30529073                csrw    mtvec,t0
    //     8000000c:   00a00513                li      a0,10
    //     80000010:   00000073                ecall
    //
    // 0000000080000014 <done>:
    //     80000014:   001002b7                lui     t0,0x100
    //     80000018:   00005337                lui     t1,0x5
    //     8000001c:   5553031b                addiw   t1,t1,1365 # 5555 <_start-0x7fffaaab>
    //     80000020:   01051513                slli    a0,a0,0x10
    //     80000024:   00656533                or      a0,a0,t1
    //     80000028:   00a2a023                sw      a0,0(t0) # 100000 <_start-0x7ff00000>
    //
    // 000000008000002c <loop>:
    //     8000002c:   0000006f                j       8000002c <loop>
    //
    // 0000000080000030 <trap_handler>:
    //     80000030:   02a50513                addi    a0,a0,42
    //     80000034:   34102373                csrr    t1,mepc
    //     80000038:   00430313                addi    t1,t1,4
    //     8000003c:   34131073                csrw    mepc,t1
    //     80000040:   30200073                mret

    // clang-format on
    rv_init();
    rv_load(trap_test_firmware_bin, sizeof(trap_test_firmware_bin));
    cpu_start();
    ASSERT_EQ(rv.shutdown_code, 52);
    ASSERT_EQ(rv.shutdown_cause, SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
}

/* Bus Tests */

#include "bus-tests/simple-uart.h"

TEST(BusTestSuite, BUS_TEST) {
    device_t uart;
    uart.start = SIMPLE_UART_BASE_ADDR;
    uart.end = SIMPLE_UART_BASE_ADDR + 8;
    uart.name = "simple_uart";
    uart.read = simple_uart_read;
    uart.write = simple_uart_write;

    auto dummy = new uint8_t[8];
    assert(dummy);
    rv_init();
    rv_load(dummy, 8);
    delete[] dummy;
    rv_add_device(uart);
    uint32_t v = bus_read(SIMPLE_UART_BASE_ADDR, 4);
    ASSERT_EQ(v, static_cast<uint32_t>(-1));
    for (char c : "fuck\n") {
        // Should output "fuck"
        bus_write(SIMPLE_UART_BASE_ADDR, c, 4);
    }
}

/* https://github.com/riscv-software-src/riscv-tests */

#include "riscv-tests/test-common.hpp"

static inline void test_files(const std::vector<std::string> &files) {
    std::vector<std::string> failed_files;

    for (const auto &f : files) {
        std::cout << "Testing: " << f << std::endl;
        bool r = test_binary(f);
        std::cout << (r ? "Passed " : "Failed ") << f << std::endl;
        if (!r)
            failed_files.emplace_back(f);
        EXPECT_TRUE(r);
    }

    std::cerr << "Failed tests" << std::endl;
    for (const auto &f : failed_files)
        std::cerr << f << std::endl;
}

TEST(RISVTestSuite, RV64MI_TEST) {
    // TODO: Bring back pmpaddr test after we have implemented it

    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64mi/bin/breakpoint.bin",
        "testbins/rv64mi/bin/csr.bin",
        "testbins/rv64mi/bin/instret_overflow.bin",
        "testbins/rv64mi/bin/ld-misaligned.bin",
        "testbins/rv64mi/bin/lh-misaligned.bin",
        "testbins/rv64mi/bin/lw-misaligned.bin",
        "testbins/rv64mi/bin/ma_addr.bin",
        "testbins/rv64mi/bin/ma_fetch.bin",
        "testbins/rv64mi/bin/mcsr.bin",
        // "testbins/rv64mi/bin/pmpaddr.bin",
        "testbins/rv64mi/bin/sbreak.bin",
        "testbins/rv64mi/bin/scall.bin",
        "testbins/rv64mi/bin/sd-misaligned.bin",
        "testbins/rv64mi/bin/sh-misaligned.bin",
        "testbins/rv64mi/bin/sw-misaligned.bin",
        "testbins/rv64mi/bin/zicntr.bin"
    };
    // clang-format on

    test_files(files);
}

TEST(RISVTestSuite, RV64SI_TEST) {
    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64si/bin/csr.bin",
        "testbins/rv64si/bin/dirty.bin",
        "testbins/rv64si/bin/icache-alias.bin",
        "testbins/rv64si/bin/ma_fetch.bin",
        "testbins/rv64si/bin/sbreak.bin",
        "testbins/rv64si/bin/scall.bin",
        "testbins/rv64si/bin/wfi.bin",
    };
    // clang-format on

    test_files(files);
}

TEST(RISVTestSuite, RV64UI_TEST) {
    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64ui/bin/add.bin",
        "testbins/rv64ui/bin/addi.bin",
        "testbins/rv64ui/bin/addiw.bin",
        "testbins/rv64ui/bin/addw.bin",
        "testbins/rv64ui/bin/and.bin",
        "testbins/rv64ui/bin/andi.bin",
        "testbins/rv64ui/bin/auipc.bin",
        "testbins/rv64ui/bin/beq.bin",
        "testbins/rv64ui/bin/bge.bin",
        "testbins/rv64ui/bin/bgeu.bin",
        "testbins/rv64ui/bin/blt.bin",
        "testbins/rv64ui/bin/bltu.bin",
        "testbins/rv64ui/bin/bne.bin",
        "testbins/rv64ui/bin/fence_i.bin",
        "testbins/rv64ui/bin/jal.bin",
        "testbins/rv64ui/bin/jalr.bin",
        "testbins/rv64ui/bin/lb.bin",
        "testbins/rv64ui/bin/lbu.bin",
        "testbins/rv64ui/bin/ld.bin",
        "testbins/rv64ui/bin/ld_st.bin",
        "testbins/rv64ui/bin/lh.bin",
        "testbins/rv64ui/bin/lhu.bin",
        "testbins/rv64ui/bin/lui.bin",
        "testbins/rv64ui/bin/lw.bin",
        "testbins/rv64ui/bin/lwu.bin",
        "testbins/rv64ui/bin/ma_data.bin",
        "testbins/rv64ui/bin/or.bin",
        "testbins/rv64ui/bin/ori.bin",
        "testbins/rv64ui/bin/sb.bin",
        "testbins/rv64ui/bin/sd.bin",
        "testbins/rv64ui/bin/sh.bin",
        "testbins/rv64ui/bin/simple.bin",
        "testbins/rv64ui/bin/sll.bin",
        "testbins/rv64ui/bin/slli.bin",
        "testbins/rv64ui/bin/slliw.bin",
        "testbins/rv64ui/bin/sllw.bin",
        "testbins/rv64ui/bin/slt.bin",
        "testbins/rv64ui/bin/slti.bin",
        "testbins/rv64ui/bin/sltiu.bin",
        "testbins/rv64ui/bin/sltu.bin",
        "testbins/rv64ui/bin/sra.bin",
        "testbins/rv64ui/bin/srai.bin",
        "testbins/rv64ui/bin/sraiw.bin",
        "testbins/rv64ui/bin/sraw.bin",
        "testbins/rv64ui/bin/srl.bin",
        "testbins/rv64ui/bin/srli.bin",
        "testbins/rv64ui/bin/srliw.bin",
        "testbins/rv64ui/bin/srlw.bin",
        "testbins/rv64ui/bin/st_ld.bin",
        "testbins/rv64ui/bin/sub.bin",
        "testbins/rv64ui/bin/subw.bin",
        "testbins/rv64ui/bin/sw.bin",
        "testbins/rv64ui/bin/xor.bin",
        "testbins/rv64ui/bin/xori.bin",
    };
    // clang-format on

    test_files(files);
}

TEST(RISVTestSuite, RV64UM_TEST) {
    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64um/bin/div.bin",
        "testbins/rv64um/bin/divu.bin",
        "testbins/rv64um/bin/divuw.bin",
        "testbins/rv64um/bin/divw.bin",
        "testbins/rv64um/bin/mul.bin",
        "testbins/rv64um/bin/mulh.bin",
        "testbins/rv64um/bin/mulhsu.bin",
        "testbins/rv64um/bin/mulhu.bin",
        "testbins/rv64um/bin/mulw.bin",
        "testbins/rv64um/bin/rem.bin",
        "testbins/rv64um/bin/remu.bin",
        "testbins/rv64um/bin/remuw.bin",
        "testbins/rv64um/bin/remw.bin",
    };
    // clang-format on

    test_files(files);
}

TEST(RISVTestSuite, RV64UA_TEST) {
    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64ua/bin/amoadd_d.bin",
        "testbins/rv64ua/bin/amoadd_w.bin",
        "testbins/rv64ua/bin/amoand_d.bin",
        "testbins/rv64ua/bin/amoand_w.bin",
        "testbins/rv64ua/bin/amomax_d.bin",
        "testbins/rv64ua/bin/amomaxu_d.bin",
        "testbins/rv64ua/bin/amomaxu_w.bin",
        "testbins/rv64ua/bin/amomax_w.bin",
        "testbins/rv64ua/bin/amomin_d.bin",
        "testbins/rv64ua/bin/amominu_d.bin",
        "testbins/rv64ua/bin/amominu_w.bin",
        "testbins/rv64ua/bin/amomin_w.bin",
        "testbins/rv64ua/bin/amoor_d.bin",
        "testbins/rv64ua/bin/amoor_w.bin",
        "testbins/rv64ua/bin/amoswap_d.bin",
        "testbins/rv64ua/bin/amoswap_w.bin",
        "testbins/rv64ua/bin/amoxor_d.bin",
        "testbins/rv64ua/bin/amoxor_w.bin",
        "testbins/rv64ua/bin/lrsc.bin",
    };
    // clang-format on

    test_files(files);
}
