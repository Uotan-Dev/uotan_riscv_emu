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

#define SIFIVE_TEST_BASE 0x100000
#define SIFIVE_TEST_SIZE 0x1000

#define SIFIVE_TEST_FINISHER_ADDR 0x00100000

#define SIFIVE_TEST_FINISHER_RESET 0x3333
#define SIFIVE_TEST_FINISHER_PASS 0x5555
#define SIFIVE_TEST_FINISHER_FAIL 0x7777

void sifive_test_init();
