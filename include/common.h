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

#pragma once

#if defined(__GNUC__) || defined(__clang__)
#define UNUSED __attribute__((unused))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define FORCE_INLINE static inline __attribute__((always_inline))
#else
#define UNUSED
#define likely(x) (x)
#define unlikely(x) (x)
#if defined(_MSC_VER)
#define FORCE_INLINE static inline __forceinline
#else
#define FORCE_INLINE static inline
#endif
#endif

// macro stringizing
#define str_temp(x) #x
#define str(x) str_temp(x)

// strlen() for string constant
#define STRLEN(CONST_STR) (sizeof(CONST_STR) - 1)

// macro concatenation
#define concat_temp(x, y) x##y
#define concat(x, y) concat_temp(x, y)
#define concat3(x, y, z) concat(concat(x, y), z)
#define concat4(x, y, z, w) concat3(concat(x, y), z, w)
#define concat5(x, y, z, v, w) concat4(concat(x, y), z, v, w)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/* The purpose of __builtin_unreachable() is to assist the compiler in:
 * - Eliminating dead code that the programmer knows will never be executed.
 * - Linearizing the code by indicating to the compiler that the path is 'cold'
 *   (a similar effect can be achieved by calling a noreturn function).
 */
#if defined(__GNUC__) || defined(__clang__)
#define __UNREACHABLE __builtin_unreachable()
#elif defined(_MSC_VER)
#define __UNREACHABLE __assume(false)
#else /* unspported compilers */
/* clang-format off */
#define __UNREACHABLE do { /* nop */ } while (0)
/* clang-format on */
#endif

#define BITMASK(bits) ((1ull << (bits)) - 1)
#define BITS(x, hi, lo)                                                        \
    (((x) >> (lo)) & BITMASK((hi) - (lo) + 1)) // similar to x[hi:lo] in verilog
#define SEXT(x, len)                                                           \
    ({                                                                         \
        struct {                                                               \
            int64_t n : len;                                                   \
        } __x = {.n = x};                                                      \
        (uint64_t)__x.n;                                                       \
    })

#define ROUNDUP(a, sz) ((((uintptr_t)a) + (sz) - 1) & ~((sz) - 1))
#define ROUNDDOWN(a, sz) ((((uintptr_t)a)) & ~((sz) - 1))

#include <inttypes.h> // IWYU pragma: keep
#include <stdio.h>    // IWYU pragma: keep

#define Log(format, ...)                                                       \
    printf("\33[1;97m[%s,%d,%s] " format "\33[0m\n", __FILE__, __LINE__,       \
           __func__, ##__VA_ARGS__)
#define Info(format, ...)                                                      \
    printf("\33[1;32m[INFO %s:%d %s] " format "\33[0m\n", __FILE__, __LINE__,  \
           __func__, ##__VA_ARGS__)
#define Warn(format, ...)                                                      \
    printf("\33[1;33m[WARN %s:%d %s] " format "\33[0m\n", __FILE__, __LINE__,  \
           __func__, ##__VA_ARGS__)
#define Error(format, ...)                                                     \
    printf("\33[1;31m[ERROR %s:%d %s] " format "\33[0m\n", __FILE__, __LINE__, \
           __func__, ##__VA_ARGS__)
