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

#ifdef __cplusplus
extern "C" {
#endif

#include <elf.h> // Use the system's elf.h for definitions
#include <stdbool.h>
#include <stdint.h>

bool is_elf(const char *file_path);
uint64_t elf_load(const char *file_path);
void dump_signature(const char *elf_file_path, const char *sig_file_path);

#ifdef __cplusplus
}
#endif
