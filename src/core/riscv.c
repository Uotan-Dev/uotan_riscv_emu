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
    // clear the whole struct
    memset(&rv, 0, sizeof(rv));

    // set the reset address
    rv.PC = RESET_PC;

    // set the control and status registers
    rv.MISA = MISA_I | MISA_M; // RV64IM, Machine Mode only
    rv.MVENDORID = MVENDORID_DEFAULT;
    rv.MARCHID = MARCHID_DEFAULT;
    rv.MIMPID = MIMPID_DEFAULT;
    // keep other CSRs zero

    // set the privilege level
    rv.privilege = PRIV_M; // boot in M mode

    // set the memory with random junk
    srand(time(NULL));
    memset(rv.memory, rand(), sizeof(rv.memory));

    // set debugger
    rv.has_debugger = true;

    // set some status
    rv.image_loaded = false;

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

// wrong
void rv_exception(uint64_t cause, uint64_t tval, uint64_t *pc) {
    // We only support M mode
    assert(rv.privilege == PRIV_M);

    // Handle BP
    if ((unlikely(cause == CAUSE_BREAKPOINT && rv.has_debugger))) {
        rv.halt = true;
        rv.halt_code = rv.X[10];
        rv.halt_pc = *pc;
        return;
    }

    rv.MEPC = *pc & ~1ULL; // The low bit of mepc (mepc[0]) is always zero
    rv.MCAUSE = cause;
    rv.MTVAL = tval;

    uint64_t mstatus = rv.MSTATUS;

    // Save current MIE to MPIE
    if (mstatus & MSTATUS_MIE)
        mstatus |= MSTATUS_MPIE;
    else
        mstatus &= ~MSTATUS_MPIE;

    // Save PRIV level to MPP
    mstatus &= ~MSTATUS_MPP;
    mstatus |= ((uint64_t)rv.privilege << MSTATUS_MPP_SHIFT);

    // Disable M mode interrupt
    mstatus &= ~MSTATUS_MIE;

    rv.MSTATUS = mstatus;
    rv.privilege = PRIV_M;

    uint64_t mtvec = rv.MTVEC;
    if ((mtvec & 0b11) == 0) {
        // Direct Mode
        *pc = mtvec & ~3ULL;
    } else {
        if (cause & INTERRUPT_FLAG) {
            // Vectored Mode, Asynchronous interrupts set pc to BASE+4×cause
            *pc = (mtvec & ~3ULL) + 4ULL * (cause & 0x3F);
        } else {
            *pc = mtvec & ~3ULL;
        }
    }
}

bool rv_check_interrupts() {
    // TODO
    return false;
}
