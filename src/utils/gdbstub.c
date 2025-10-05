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

#include <errno.h> // IWYU pragma: keep
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/cpu.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "utils/gdbstub.h" // IWYU pragma: keep
#include "utils/logger.h"

// Software breakpoints
typedef struct {
    uint64_t addr;
    uint32_t orig_insn; // original 32-bit insts
    bool used;
} breakpoint_t;

#define MAX_BP 256

static breakpoint_t breakpoints[MAX_BP];

// Forward declarations
static gdb_action_t uemu_cont(void *args);
static gdb_action_t uemu_stepi(void *args);
static size_t uemu_get_reg_byte(int regno);
static int uemu_read_reg(void *args, int regno, void *value);
static int uemu_write_reg(void *args, int regno, void *value);
static int uemu_read_mem(void *args, size_t addr, size_t len, void *val);
static int uemu_write_mem(void *args, size_t addr, size_t len, void *val);
static bool uemu_set_bp(void *args, size_t addr, bp_type_t type);
static bool uemu_del_bp(void *args, size_t addr, bp_type_t type);
static void uemu_on_interrupt(void *args);
static void uemu_set_cpu(void *args, int cpuid);
static int uemu_get_cpu(void *args);

static struct target_ops uemu_ops = {
    .cont = uemu_cont,
    .stepi = uemu_stepi,
    .get_reg_bytes = uemu_get_reg_byte,
    .read_reg = uemu_read_reg,
    .write_reg = uemu_write_reg,
    .read_mem = uemu_read_mem,
    .write_mem = uemu_write_mem,
    .set_bp = uemu_set_bp,
    .del_bp = uemu_del_bp,
    .on_interrupt = uemu_on_interrupt,
    .set_cpu = uemu_set_cpu,
    .get_cpu = uemu_get_cpu,
};

static const arch_info_t uemu_arch = {
    .target_desc = TARGET_RV64,
    .smp = 1,
    .reg_num = NR_GPR + 1, // GPRs + PC
};

static inline bool uemu_is_interrupt() {
    return __atomic_load_n(&rv.is_interrupted_gdb, __ATOMIC_RELAXED);
}

static inline breakpoint_t *uemu_find_breakpoint(uint64_t addr) {
    for (size_t i = 0; i < MAX_BP; i++)
        if (breakpoints[i].used && breakpoints[i].addr == addr)
            return &breakpoints[i];
    return NULL;
}

// run emulator until it stops (breakpoint/exception) or shutdown
static gdb_action_t uemu_cont(void *args) {
    log_info("gdbstub: cont()");

    while (!unlikely(rv.shutdown) && !uemu_is_interrupt()) {
        if (uemu_find_breakpoint(rv.PC))
            break;
        cpu_step();
    }

    __atomic_store_n(&rv.is_interrupted_gdb, false, __ATOMIC_RELAXED);

    return rv.shutdown ? ACT_SHUTDOWN : ACT_RESUME;
}

static gdb_action_t uemu_stepi(void *args) {
    log_info("gdbstub: stepi()");
    if (!unlikely(rv.shutdown))
        cpu_step();
    return rv.shutdown ? ACT_SHUTDOWN : ACT_RESUME;
}

static size_t uemu_get_reg_byte(int regno) { return sizeof(uint64_t); }

static int uemu_read_reg(void *args, int regno, void *value) {
    if (unlikely(regno > NR_GPR || regno < 0))
        return EFAULT;

    if (regno == NR_GPR)
        *(uint64_t *)value = rv.PC;
    else
        *(uint64_t *)value = rv.X[regno];

    return 0;
}

static int uemu_write_reg(void *args, int regno, void *value) {
    if (unlikely(regno > NR_GPR || regno < 0))
        return EFAULT;

    if (regno == NR_GPR)
        rv.PC = *(uint64_t *)value;
    else
        rv.X[regno] = *(uint64_t *)value;

    return 0;
}

static int uemu_read_mem(void *args, size_t addr, size_t len, void *val) {
    if (likely(paddr_in_pmem(addr))) {
        uint8_t *haddr = GUEST_TO_HOST(addr);
        for (size_t i = 0; i < len; i++)
            ((uint8_t *)val)[i] = haddr[i];
        return 0;
    }
    return EFAULT;
}

static int uemu_write_mem(void *args, size_t addr, size_t len, void *val) {
    if (likely(paddr_in_pmem(addr))) {
        uint8_t *haddr = GUEST_TO_HOST(addr);
        for (size_t i = 0; i < len; i++)
            haddr[i] = ((uint8_t *)val)[i];
        return 0;
    }
    return EFAULT;
}

static bool uemu_set_bp(void *args, size_t addr, bp_type_t type) {
    if (type != BP_SOFTWARE)
        return false;

    if (uemu_find_breakpoint(addr))
        return true;

    for (size_t i = 0; i < MAX_BP; i++) {
        if (!breakpoints[i].used) {
            breakpoints[i].used = true;
            breakpoints[i].addr = addr;
            log_info("Breakpoint set");
            return true;
        }
    }

    log_error("Too many breakpoints set");
    return false;
}

static bool uemu_del_bp(void *args, size_t addr, bp_type_t type) {
    if (type != BP_SOFTWARE)
        return false;

    breakpoint_t *bp = uemu_find_breakpoint(addr);
    if (bp)
        bp->used = false;

    return true;
}

static void uemu_on_interrupt(void *args) {
    __atomic_store_n(&rv.is_interrupted_gdb, true, __ATOMIC_RELAXED);
}

static void uemu_set_cpu(void *args, int cpuid) {
    if (cpuid != 0)
        log_warn("We have only one CPU");
}

static int uemu_get_cpu(void *args) { return 0; }

static gdbstub_t gdbstub;

void gdbstub_emu_start() {
    log_info("Starting gdbstub, target_desc: %s", uemu_arch.target_desc);

    if (!gdbstub_init(&gdbstub, &uemu_ops, uemu_arch, "127.0.0.1:1234")) {
        log_error("gdbstub_init() failed");
        exit(EXIT_FAILURE);
    }

    if (!gdbstub_run(&gdbstub, NULL)) {
        log_error("gdbstub_run() failed");
        exit(EXIT_FAILURE);
    }

    log_info("gdbstub has started!");

    gdbstub_close(&gdbstub);
    log_info("gdbstub has closed!");
}
