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
#include <dlfcn.h>
#include <inttypes.h>
#include <string.h>

#include "core/cpu.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "utils/difftest-defs.h"
#include "utils/difftest.h"
#include "utils/logger.h"

static void (*ref_difftest_memcpy)(uint64_t addr, void *buf, size_t n,
                                   bool direction) = NULL;
static void (*ref_difftest_regcpy)(void *dut, bool direction) = NULL;
static void (*ref_difftest_exec)(uint64_t n) = NULL;
static void (*ref_difftest_raise_intr)(uint64_t NO) = NULL;

static void difftest_prepare_ctx(struct diff_context_t *ctx) {
    memcpy(ctx->gpr, rv.X, sizeof(rv.X));
    ctx->pc = rv.PC;
}

void difftest_init(const char *ref_so_file) {
    assert(ref_so_file);

    log_info("Initializing difftest with %s", ref_so_file);

    void *handle = dlopen(ref_so_file, RTLD_LAZY);
    if (!handle)
        log_warn("You may have to use absolute path here");
    assert(handle);

    ref_difftest_memcpy = dlsym(handle, "difftest_memcpy");
    ref_difftest_regcpy = dlsym(handle, "difftest_regcpy");
    ref_difftest_exec = dlsym(handle, "difftest_exec");
    ref_difftest_raise_intr = dlsym(handle, "difftest_raise_intr");
    void (*ref_difftest_init)(int) = dlsym(handle, "difftest_init");
    assert(ref_difftest_memcpy && ref_difftest_regcpy && ref_difftest_exec &&
           ref_difftest_init);

    ref_difftest_init(0); // Port is not used

    ref_difftest_memcpy(MBASE, GUEST_TO_HOST(MBASE), MSIZE, DIFFTEST_TO_REF);

    struct diff_context_t ctx;
    difftest_prepare_ctx(&ctx);
    ref_difftest_regcpy(&ctx, DIFFTEST_TO_REF);
}

void difftest_dut_step() {
    assert(ref_difftest_exec);
    ref_difftest_exec(1);
}

void difftest_chk_reg() {
    struct diff_context_t ctx;
    ref_difftest_regcpy(&ctx, DIFFTEST_TO_DUT);
    bool good = true;
    if (ctx.pc != rv.PC) {
        log_error("Bad PC. DUT: 0x%08" PRIx64 " REF: 0x%08" PRIx64 "", rv.PC,
                  ctx.pc);
        good = false;
    }
    for (size_t i = 0; i < NR_GPR; i++) {
        if (ctx.gpr[i] != rv.X[i]) {
            log_error("Bad %s. DUT: 0x%08" PRIx64 " REF: 0x%08" PRIx64 "",
                      regs[i], rv.X[i], ctx.gpr[i]);
            good = false;
        }
    }
    if (!good) {
        log_error("Shutdown at DUT PC 0x%08" PRIx64 "", rv.decode.pc);
        rv_shutdown(-1, SHUTDOWN_CAUSE_GUEST_PANIC);
    }
}
