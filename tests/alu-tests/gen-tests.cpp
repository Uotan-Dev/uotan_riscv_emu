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

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "gen-tests.hpp"

using namespace std;

// Test value sets for different integer types
static const int64_t v64[] = {
    static_cast<int64_t>(0x8000000000000000ULL), // INT64_MIN
    static_cast<int64_t>(0x8000000000000001ULL), // INT64_MIN + 1
    -2,
    -1,
    0,
    1,
    2,
    0x7FFFFFFFFFFFFFFELL, // INT64_MAX - 1
    0x7FFFFFFFFFFFFFFFLL  // INT64_MAX
};

static const int32_t v32[] = {
    static_cast<int32_t>(0x80000000U), // INT32_MIN
    static_cast<int32_t>(0x80000001U), // INT32_MIN + 1
    -2,
    -1,
    0,
    1,
    2,
    0x7FFFFFFE, // INT32_MAX - 1
    0x7FFFFFFF  // INT32_MAX
};

static const int16_t v16[] = {
    static_cast<int16_t>(0x8000), // INT16_MIN
    static_cast<int16_t>(0x8001), // INT16_MIN + 1
    -2,
    -1,
    0,
    1,
    2,
    0x7FFE, // INT16_MAX - 1
    0x7FFF  // INT16_MAX
};

static const int8_t v8[] = {
    static_cast<int8_t>(0x80), // INT8_MIN
    static_cast<int8_t>(0x81), // INT8_MIN + 1
    -2,
    -1,
    0,
    1,
    2,
    0x7E, // INT8_MAX - 1
    0x7F  // INT8_MAX
};

static const uint64_t uv64[] = {0x8000000000000000ULL,
                                0x8000000000000001ULL,
                                static_cast<uint64_t>(-2),
                                static_cast<uint64_t>(-1),
                                0,
                                1,
                                2,
                                0x7FFFFFFFFFFFFFFEULL,
                                0x7FFFFFFFFFFFFFFFULL};

static const uint32_t uv32[] = {0x80000000U,
                                0x80000001U,
                                static_cast<uint32_t>(-2),
                                static_cast<uint32_t>(-1),
                                0,
                                1,
                                2,
                                0x7FFFFFFEU,
                                0x7FFFFFFFU};

static const uint16_t uv16[] = {0x8000,
                                0x8001,
                                static_cast<uint16_t>(-2),
                                static_cast<uint16_t>(-1),
                                0,
                                1,
                                2,
                                0x7FFE,
                                0x7FFF};

static const uint8_t uv8[] = {
    0x80, 0x81, static_cast<uint8_t>(-2), static_cast<uint8_t>(-1), 0, 1, 2,
    0x7E, 0x7F};

// Check if operation should be excluded to avoid undefined behavior
template <typename T> bool shouldExclude(const string &op, T x, T y) {
    if (op == "/" || op == "%") {
        if (y == 0)
            return true;
        // Avoid signed integer overflow in division
        if (std::is_signed<T>::value) {
            if (y == -1 && x == (T(1) << (sizeof(T) * 8 - 1))) {
                return true;
            }
        }
    } else if (op == "<<" || op == ">>") {
        // Avoid undefined shift behavior
        int shift_bits = sizeof(T) * 8;
        if (y >= shift_bits || y < 0)
            return true;
    }
    return false;
}

// Generate test cases for a specific type and operation
template <typename T>
void generateTests(ostream &out, const string &typeName, const T *values,
                   size_t count, const string &op) {
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < count; j++) {
            if (shouldExclude(op, values[i], values[j]))
                continue;

            out << "  {\n";
            out << "    volatile " << typeName << " x = ";
            if (std::is_signed<T>::value) {
                out << static_cast<int64_t>(values[i]);
            } else {
                out << static_cast<uint64_t>(values[i]) << "ULL";
            }
            out << ";\n";

            out << "    volatile " << typeName << " y = ";
            if (std::is_signed<T>::value) {
                out << static_cast<int64_t>(values[j]);
            } else {
                out << static_cast<uint64_t>(values[j]) << "ULL";
            }
            out << ";\n";

            // Calculate expected result
            T expected;
            if (op == "+")
                expected = values[i] + values[j];
            else if (op == "-")
                expected = values[i] - values[j];
            else if (op == "*")
                expected = values[i] * values[j];
            else if (op == "/")
                expected = values[i] / values[j];
            else if (op == "%")
                expected = values[i] % values[j];
            else if (op == "&")
                expected = values[i] & values[j];
            else if (op == "|")
                expected = values[i] | values[j];
            else if (op == "^")
                expected = values[i] ^ values[j];
            else if (op == "<<")
                expected = values[i] << values[j];
            else if (op == ">>")
                expected = values[i] >> values[j];
            else if (op == "==")
                expected = (values[i] == values[j]) ? 1 : 0;
            else if (op == "!=")
                expected = (values[i] != values[j]) ? 1 : 0;
            else if (op == "<")
                expected = (values[i] < values[j]) ? 1 : 0;
            else if (op == "<=")
                expected = (values[i] <= values[j]) ? 1 : 0;
            else if (op == ">")
                expected = (values[i] > values[j]) ? 1 : 0;
            else if (op == ">=")
                expected = (values[i] >= values[j]) ? 1 : 0;

            out << "    " << typeName << " result = x " << op << " y;\n";
            out << "    " << typeName << " expected = ";
            if (std::is_signed<T>::value) {
                out << static_cast<int64_t>(expected);
            } else {
                out << static_cast<uint64_t>(expected) << "ULL";
            }
            out << ";\n";
            out << "    if (result != expected) trap(-1);\n";
            out << "  }\n\n";
        }
    }
}

// Generate all tests for a specific type
template <typename T>
void generateAllTests(ostream &out, const string &typeName, const T *values,
                      size_t count) {
    vector<string> ops = {"+",  "-",  "*",  "/",  "%", "&",  "|", "^",
                          "<<", ">>", "==", "!=", "<", "<=", ">", ">="};

    for (const auto &op : ops) {
        generateTests(out, typeName, values, count, op);
    }
}

void write_alu_test_file(const string &path) {
    ofstream file(path);
    if (!file.is_open()) {
        cerr << "Error: Cannot open file " << path << " for writing" << endl;
        return;
    }

    file << "// RISC-V64 Arithmetic and Logic Operations Test\n";
    file << "// Auto-generated test cases for bare-metal environment\n\n";

    file << "#include <stdint.h>\n\n";

    file << "#define trap(code) asm volatile(\"mv a0, %0; ebreak\" : "
            ":\"r\"(code))\n\n";

    file << "int main(void) {\n\n";

    // Generate tests for all integer types
    file << "  // Testing int8_t operations\n";
    generateAllTests(file, "int8_t", v8, sizeof(v8) / sizeof(v8[0]));

    file << "  // Testing uint8_t operations\n";
    generateAllTests(file, "uint8_t", uv8, sizeof(uv8) / sizeof(uv8[0]));

    file << "  // Testing int16_t operations\n";
    generateAllTests(file, "int16_t", v16, sizeof(v16) / sizeof(v16[0]));

    file << "  // Testing uint16_t operations\n";
    generateAllTests(file, "uint16_t", uv16, sizeof(uv16) / sizeof(uv16[0]));

    file << "  // Testing int32_t operations\n";
    generateAllTests(file, "int32_t", v32, sizeof(v32) / sizeof(v32[0]));

    file << "  // Testing uint32_t operations\n";
    generateAllTests(file, "uint32_t", uv32, sizeof(uv32) / sizeof(uv32[0]));

    file << "  // Testing int64_t operations\n";
    generateAllTests(file, "int64_t", v64, sizeof(v64) / sizeof(v64[0]));

    file << "  // Testing uint64_t operations\n";
    generateAllTests(file, "uint64_t", uv64, sizeof(uv64) / sizeof(uv64[0]));

    file << "  // All tests passed\n";
    file << "  trap(0);\n";
    file << "  return 0;\n";
    file << "}\n";

    file.close();
}
