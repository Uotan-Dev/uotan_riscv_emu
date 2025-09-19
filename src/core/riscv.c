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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "core/mem.h"
#include "core/riscv.h"

riscv_t rv;

void rv_init() {
    // set integer registers
    memset(rv.X, 0, sizeof(rv.X));

    // set the reset address
    rv.PC = RESET_PC;

    // set the memory
    srand(time(NULL));
    memset(rv.memory, rand(), sizeof(rv.memory));

    // set some status
    rv.image_loaded = false;
    rv.halt = false;

    Log("RV initialized!");
}

void rv_load_image(const char *path) {
    if (path == NULL || *path == '\0')
        goto fail;

    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        goto fail;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size == 0)
        goto fail;
    Log("Loading image %s of size %ld...", path, size);
    fseek(fp, 0, SEEK_SET);
    unsigned long res = fread(GUEST_TO_HOST(RESET_PC), size, 1, fp);
    assert(res == 1);

    fclose(fp);
    rv.image_loaded = true;
    return;

fail:
    Error("Loading image failed");
}

void rv_load_default_image() {
    // clang-format off
    static const uint32_t builtin_img[] = {
        0x00000297, // auipc t0,0
        0x00028823, // sb  zero,16(t0)
        0x0102c503, // lbu a0,16(t0)
        0x00100073, // ebreak
        0x00000000,
    };
    // clang-format on

    memcpy(GUEST_TO_HOST(RESET_PC), builtin_img, sizeof(builtin_img));
    rv.image_loaded = true;
}
