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
#include <gtest/gtest.h>
#include <inttypes.h>
#include <string>
#include <unistd.h>

// include some emu headers
#include "core/cpu/dispatch.h"
#include "core/riscv.h"
#include "utils/lru_cache.hpp"

/* Sample Tests */

TEST(SampleTestSuite, BasicAssertion) { EXPECT_TRUE(true); }

TEST(SampleTestSuite, MathTest) {
    EXPECT_EQ(2 + 2, 4);
    ASSERT_EQ(5 * 5, 25);
}

/* Bare Min test */
#include "test-programs/bare-min.hpp"

TEST(BareMinTestSuite, BareMin_TEST) {
    rv_init();
    rv_load(bare_min_bin, sizeof(bare_min_bin));
    cpu_start();
    ASSERT_EQ(rv.shutdown_code, 0);
    ASSERT_EQ(rv.shutdown_cause, SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    rv_destroy();
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
    rv_destroy();
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
    rv_destroy();
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

TEST(RISVTestSuite, RV64UF_TEST) {
    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64uf/bin/fadd.bin",
        "testbins/rv64uf/bin/fclass.bin",
        "testbins/rv64uf/bin/fcmp.bin",
        "testbins/rv64uf/bin/fcvt.bin",
        "testbins/rv64uf/bin/fcvt_w.bin",
        "testbins/rv64uf/bin/fdiv.bin",
        "testbins/rv64uf/bin/fmadd.bin",
        "testbins/rv64uf/bin/fmin.bin",
        "testbins/rv64uf/bin/ldst.bin",
        "testbins/rv64uf/bin/move.bin",
        "testbins/rv64uf/bin/recoding.bin",
    };
    // clang-format on

    test_files(files);
}

TEST(RISVTestSuite, RV64UD_TEST) {
    // clang-format off
    std::vector<std::string> files = {
        "testbins/rv64ud/bin/fadd.bin",
        "testbins/rv64ud/bin/fclass.bin",
        "testbins/rv64ud/bin/fcmp.bin",
        "testbins/rv64ud/bin/fcvt.bin",
        "testbins/rv64ud/bin/fcvt_w.bin",
        "testbins/rv64ud/bin/fdiv.bin",
        "testbins/rv64ud/bin/fmadd.bin",
        "testbins/rv64ud/bin/fmin.bin",
        "testbins/rv64ud/bin/ldst.bin",
        "testbins/rv64ud/bin/move.bin",
        "testbins/rv64ud/bin/recoding.bin",
        "testbins/rv64ud/bin/structural.bin",
    };
    // clang-format on

    test_files(files);
}

TEST(RISVTestSuite, RV64UC_TEST) {
    // clang-format off
    std::vector<std::string> files = {
    "testbins/rv64uc/bin/rvc.bin",
    };
    // clang-format on

    test_files(files);
}

/* Util Tests */

// Test data structure
struct TestData {
    int value;
    std::string name;

    TestData(int v, const std::string &n) : value(v), name(n) {}
};

// Helper macro to test both map types
#define TEST_BOTH_MAPS(test_name, test_body)                                   \
    TEST(UtilTestSuite, LRUTest_UnorderedMap_##test_name) {                    \
        using CacheType = LruCache<int, TestData *>;                           \
        test_body                                                              \
    }                                                                          \
    TEST(UtilTestSuite, LRUTest_Map_##test_name) {                             \
        using CacheType = LruCache<int, TestData *, std::map>;                 \
        test_body                                                              \
    }                                                                          \
    TEST(UtilTestSuite, LRUTest_FlatHashMap_##test_name) {                     \
        using CacheType = LruCache<int, TestData *, absl::flat_hash_map>;      \
        test_body                                                              \
    }

// Test 1: Basic put and get
TEST_BOTH_MAPS(BasicPutGet, {
    CacheType cache(3);

    cache.put(1, new TestData(100, "first"));
    cache.put(2, new TestData(200, "second"));

    TestData *data1 = cache.get(1);
    ASSERT_NE(data1, nullptr);
    EXPECT_EQ(data1->value, 100);
    EXPECT_EQ(data1->name, "first");

    TestData *data2 = cache.get(2);
    ASSERT_NE(data2, nullptr);
    EXPECT_EQ(data2->value, 200);

    TestData *data3 = cache.get(999);
    EXPECT_EQ(data3, nullptr);
})

// Test 2: LRU eviction
TEST_BOTH_MAPS(LRUEviction, {
    CacheType cache(3);

    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));
    cache.put(3, new TestData(3, "three"));

    EXPECT_EQ(cache.size(), 3);

    // Insert 4th element, should evict key 1 (least recently used)
    cache.put(4, new TestData(4, "four"));

    EXPECT_EQ(cache.size(), 3);
    EXPECT_EQ(cache.get(1), nullptr); // Evicted
    EXPECT_NE(cache.get(2), nullptr); // Still exists
    EXPECT_NE(cache.get(3), nullptr);
    EXPECT_NE(cache.get(4), nullptr);
})

// Test 3: Access updates LRU order
TEST_BOTH_MAPS(AccessUpdatesOrder, {
    CacheType cache(3);

    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));
    cache.put(3, new TestData(3, "three"));

    // Access key 1, making it most recently used
    cache.get(1);

    // Insert 4th element, should evict key 2 (now LRU)
    cache.put(4, new TestData(4, "four"));

    EXPECT_NE(cache.get(1), nullptr); // Still exists (was accessed)
    EXPECT_EQ(cache.get(2), nullptr); // Evicted (was LRU)
    EXPECT_NE(cache.get(3), nullptr);
    EXPECT_NE(cache.get(4), nullptr);
})

// Test 4: Update existing key
TEST_BOTH_MAPS(UpdateExisting, {
    CacheType cache(3);

    cache.put(1, new TestData(100, "old"));

    TestData *old_data = cache.get(1);
    EXPECT_EQ(old_data->name, "old");

    // Update with new data (old pointer should be deleted automatically)
    cache.put(1, new TestData(999, "new"));

    TestData *new_data = cache.get(1);
    EXPECT_EQ(new_data->value, 999);
    EXPECT_EQ(new_data->name, "new");
    EXPECT_EQ(cache.size(), 1);
})

// Test 5: Remove element
TEST_BOTH_MAPS(RemoveElement, {
    CacheType cache(3);

    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));
    cache.put(3, new TestData(3, "three"));

    EXPECT_TRUE(cache.remove(2));
    EXPECT_EQ(cache.size(), 2);
    EXPECT_EQ(cache.get(2), nullptr);

    EXPECT_FALSE(cache.remove(999)); // Non-existent key
    EXPECT_EQ(cache.size(), 2);
})

// Test 6: Contains check
TEST_BOTH_MAPS(ContainsCheck, {
    CacheType cache(3);

    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));

    EXPECT_TRUE(cache.contains(1));
    EXPECT_TRUE(cache.contains(2));
    EXPECT_FALSE(cache.contains(999));

    cache.remove(1);
    EXPECT_FALSE(cache.contains(1));
})

// Test 7: Clear cache
TEST_BOTH_MAPS(ClearCache, {
    CacheType cache(3);

    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));
    cache.put(3, new TestData(3, "three"));

    EXPECT_EQ(cache.size(), 3);

    cache.clear();

    EXPECT_EQ(cache.size(), 0);
    EXPECT_TRUE(cache.empty());
    EXPECT_EQ(cache.get(1), nullptr);
    EXPECT_EQ(cache.get(2), nullptr);
    EXPECT_EQ(cache.get(3), nullptr);
})

// Test 8: Empty cache operations
TEST_BOTH_MAPS(EmptyCache, {
    CacheType cache(3);

    EXPECT_TRUE(cache.empty());
    EXPECT_EQ(cache.size(), 0);
    EXPECT_EQ(cache.capacity(), 3);

    EXPECT_EQ(cache.get(1), nullptr);
    EXPECT_FALSE(cache.contains(1));
    EXPECT_FALSE(cache.remove(1));
})

// Test 9: Single element cache
TEST_BOTH_MAPS(SingleElementCache, {
    CacheType cache(1);

    cache.put(1, new TestData(1, "one"));
    EXPECT_EQ(cache.size(), 1);

    // Adding second element should evict first
    cache.put(2, new TestData(2, "two"));
    EXPECT_EQ(cache.size(), 1);
    EXPECT_EQ(cache.get(1), nullptr);
    EXPECT_NE(cache.get(2), nullptr);
})

// Test 10: Complex LRU scenario
TEST_BOTH_MAPS(ComplexLRUScenario, {
    CacheType cache(3);

    // Initial state: [1, 2, 3]
    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));
    cache.put(3, new TestData(3, "three"));

    // Access 1, order becomes: [1, 3, 2]
    cache.get(1);

    // Access 2, order becomes: [2, 1, 3]
    cache.get(2);

    // Insert 4, evicts 3 (LRU), order becomes: [4, 2, 1]
    cache.put(4, new TestData(4, "four"));

    EXPECT_NE(cache.get(1), nullptr);
    EXPECT_NE(cache.get(2), nullptr);
    EXPECT_EQ(cache.get(3), nullptr); // Evicted
    EXPECT_NE(cache.get(4), nullptr);
})

// Test 11: std::map with tuple key (only for std::map)
TEST(UtilTestSuite, LRUTest_Map_TupleKey) {
    using Key = std::tuple<int, int>;
    LruCache<Key, TestData *, std::map> cache(3);

    cache.put({1, 2}, new TestData(12, "one-two"));
    cache.put({3, 4}, new TestData(34, "three-four"));
    cache.put({5, 6}, new TestData(56, "five-six"));

    TestData *data = cache.get({1, 2});
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->value, 12);
    EXPECT_EQ(data->name, "one-two");

    // Test eviction with tuple key
    cache.put({7, 8}, new TestData(78, "seven-eight"));
    EXPECT_EQ(cache.get({3, 4}), nullptr); // Evicted
    EXPECT_NE(cache.get({1, 2}), nullptr); // Still exists (was accessed)
}

// Test 12: std::map with pair key (only for std::map)
TEST(UtilTestSuite, LRUTest_Map_PairKey) {
    using Key = std::pair<std::string, int>;
    LruCache<Key, TestData *, std::map> cache(2);

    cache.put({"alpha", 1}, new TestData(100, "test1"));
    cache.put({"beta", 2}, new TestData(200, "test2"));

    TestData *data = cache.get({"alpha", 1});
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->value, 100);

    cache.put({"gamma", 3}, new TestData(300, "test3"));

    // "beta" should be evicted
    EXPECT_EQ(cache.get({"beta", 2}), nullptr);
    EXPECT_NE(cache.get({"alpha", 1}), nullptr);
    EXPECT_NE(cache.get({"gamma", 3}), nullptr);
}

// Test 13: Stress test - many operations
TEST_BOTH_MAPS(StressTest, {
    CacheType cache(100);

    // Insert 200 elements (will evict 100)
    for (int i = 0; i < 200; i++) {
        cache.put(i, new TestData(i, "data_" + std::to_string(i)));
    }

    EXPECT_EQ(cache.size(), 100);

    // First 100 should be evicted
    for (int i = 0; i < 100; i++) {
        EXPECT_EQ(cache.get(i), nullptr);
    }

    // Last 100 should exist
    for (int i = 100; i < 200; i++) {
        EXPECT_NE(cache.get(i), nullptr);
    }
})

// Test 14: Interleaved operations
TEST_BOTH_MAPS(InterleavedOps, {
    CacheType cache(5);

    cache.put(1, new TestData(1, "one"));
    cache.put(2, new TestData(2, "two"));
    EXPECT_TRUE(cache.contains(1));

    cache.put(3, new TestData(3, "three"));
    cache.remove(2);
    EXPECT_FALSE(cache.contains(2));

    cache.put(4, new TestData(4, "four"));
    cache.put(5, new TestData(5, "five"));
    EXPECT_EQ(cache.size(), 4);

    cache.get(1); // Access 1
    cache.put(6, new TestData(6, "six"));
    cache.put(7, new TestData(7, "seven"));

    // 1 should still exist (was recently accessed)
    EXPECT_NE(cache.get(1), nullptr);
})
