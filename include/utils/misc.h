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

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t make_mask_bytes(size_t bytes) {
    if (bytes >= 8)
        return UINT64_MAX;
    return (1ULL << (bytes * 8)) - 1ULL;
}

void enable_stdin_raw_mode();
void disable_stdin_raw_mode();

#ifdef __cplusplus
}
#endif
