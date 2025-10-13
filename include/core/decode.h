/*
 * Copyright 2025 Nuo Shen, Nanjing University
 *
 * This file is part of the UEMU project.
 *
 * The majority of this file is developed by Nuo Shen under the Apache License,
 * Version 2.0. However, certain portions of this file are adapted from the NEMU
 * project (Copyright (c) 2014-2024 Zihao Yu, Nanjing University), which is
 * licensed under the Mulan PSL v2.
 *
 * Therefore, this file as a whole is distributed under both licenses:
 *   - Apache License 2.0 for the original portions by Nuo Shen
 *   - Mulan PSL v2 for the adapted portions from NEMU
 *
 * You may obtain copies of both licenses at:
 *   - Apache License 2.0: http://www.apache.org/licenses/LICENSE-2.0
 *   - Mulan PSL v2:      http://license.coscl.org.cn/MulanPSL2
 *
 * When redistributing this file or a derived work, you must comply with
 * both licenses accordingly.
 */

#pragma once

#include <stdint.h>

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t pc;
    uint64_t npc;  // next PC
    uint32_t inst; // instruction
} Decode;

/**
 * The decoding algorithm is taken from NJU emulator
 * Keeping the original license here
 */

/***************************************************************************************
 * Copyright (c) 2014-2024 Zihao Yu, Nanjing University
 *
 * NEMU is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 *PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 * See the Mulan PSL v2 for more details.
 ***************************************************************************************/

// --- pattern matching mechanism ---
FORCE_INLINE void pattern_decode(const char *str, int len, uint64_t *key,
                                 uint64_t *mask, uint64_t *shift) {
    uint64_t __key = 0, __mask = 0, __shift = 0;
#define macro(i)                                                               \
    if ((i) >= len)                                                            \
        goto finish;                                                           \
    else {                                                                     \
        char c = str[i];                                                       \
        if (c != ' ') {                                                        \
            __key = (__key << 1) | (c == '1' ? 1 : 0);                         \
            __mask = (__mask << 1) | (c == '?' ? 0 : 1);                       \
            __shift = (c == '?' ? __shift + 1 : 0);                            \
        }                                                                      \
    }

    // clang-format off
#define macro2(i)  macro(i);   macro((i) + 1)
#define macro4(i)  macro2(i);  macro2((i) + 2)
#define macro8(i)  macro4(i);  macro4((i) + 4)
#define macro16(i) macro8(i);  macro8((i) + 8)
#define macro32(i) macro16(i); macro16((i) + 16)
#define macro64(i) macro32(i); macro32((i) + 32)
    // clang-format on
    macro64(0);
#undef macro

finish:
    *key = __key >> __shift;
    *mask = __mask >> __shift;
    *shift = __shift;
}

FORCE_INLINE void pattern_decode_hex(const char *str, int len, uint64_t *key,
                                     uint64_t *mask, uint64_t *shift) {
    uint64_t __key = 0, __mask = 0, __shift = 0;
#define macro(i)                                                               \
    if ((i) >= len)                                                            \
        goto finish;                                                           \
    else {                                                                     \
        char c = str[i];                                                       \
        if (c != ' ') {                                                        \
            __key = (__key << 4) | (c == '?'                 ? 0               \
                                    : (c >= '0' && c <= '9') ? c - '0'         \
                                                             : c - 'a' + 10);  \
            __mask = (__mask << 4) | (c == '?' ? 0 : 0xf);                     \
            __shift = (c == '?' ? __shift + 4 : 0);                            \
        }                                                                      \
    }

    macro16(0);
#undef macro
finish:
    *key = __key >> __shift;
    *mask = __mask >> __shift;
    *shift = __shift;
}

// --- pattern matching wrappers for decode ---
#define INSTPAT(pattern, ...)                                                  \
    do {                                                                       \
        uint64_t key, mask, shift;                                             \
        pattern_decode(pattern, STRLEN(pattern), &key, &mask, &shift);         \
        if ((((uint64_t)INSTPAT_INST(s) >> shift) & mask) == key) {            \
            INSTPAT_MATCH(s, ##__VA_ARGS__);                                   \
            goto *(__instpat_end);                                             \
        }                                                                      \
    } while (0)

#define INSTPAT_START(name)                                                    \
    {                                                                          \
        const void *__instpat_end = &&concat(__instpat_end_, name);
#define INSTPAT_END(name)                                                      \
    concat(__instpat_end_, name) :;                                            \
    }

#ifdef __cplusplus
}
#endif
