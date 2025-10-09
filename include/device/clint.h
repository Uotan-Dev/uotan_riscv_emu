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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLINT_BASE 0x2000000
#define CLINT_SIZE 0x10000

// clang-format off
#define CLINT_MSIP_ADDR     0x02000000
#define CLINT_MTIMECMP_ADDR 0x02004000
#define CLINT_MTIME_ADDR    0x0200BFF8
// clang-format on

void clint_init();
void clint_destroy();
void clint_tick();

#ifdef __cplusplus
}
#endif
