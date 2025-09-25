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
#include "core/cpu.h"
#include "core/mem.h"
#include "core/riscv.h"
#include "device/bus.h"
#include "device/clint.h"
#include "device/dram.h"
#include "device/plic.h"
#include "device/sifive_test.h"
#include "device/uart.h"
#include "utils/timer.h"

riscv_t rv;

void rv_init(const void *buf, size_t buf_size) {
    // clear the whole struct
    memset(&rv, 0, sizeof(rv));

    // set the reset address
    rv.PC = RESET_PC;

    // set the control and status registers
    rv.MISA |= MISA_XLEN_64;    // XLEN is 64
    rv.MISA |= MISA_I | MISA_M; // I_EXT, M_EXT
    rv.MISA |= MISA_SUPER;      // Support supervisor mode
    rv.MVENDORID = MVENDORID_DEFAULT;
    rv.MARCHID = MARCHID_DEFAULT;
    rv.MIMPID = MIMPID_DEFAULT;
    // keep other CSRs zero

    // set the privilege level
    rv.privilege = PRIV_M; // boot in M mode

    // Reset the timer
    timer_restart();

    // init BUS
    bus_init();
    // setup DRAM
    dram_init();
    // setup CLINT
    clint_init();
    // setup PLIC
    plic_init();
    // setup SiFive Test
    sifive_test_init();
    // setup NS16550A UART
    uart_init();

    // We always put DRAM as the first device
    if (unlikely(strcmp(rv.bus.devices[0].name, "DRAM"))) {
        Error("DRAM is not the first device");
        exit(EXIT_FAILURE);
    }

    // reset last exception
    rv.last_exception = CAUSE_EXCEPTION_NONE;

    // Load kernel
    assert(buf && buf_size && buf_size <= MSIZE);
    memcpy(GUEST_TO_HOST(RESET_PC), buf, buf_size);

    // Misc
    rv.shutdown = false;

    Log("RV initialized!");
}

void rv_add_device(device_t dev) {
    assert(dev.name && dev.read && dev.write);
    Info("Added device %s at [0x%08" PRIx64 ", 0x%08" PRIx64 "]", dev.name,
         dev.start, dev.end);
    bus_add_device(dev);
}

interrupt_t rv_get_pending_interrupt() {
    // TODO: Receive intr from devices first

    uint64_t m_pending = cpu_read_csr(CSR_MIE) & cpu_read_csr(CSR_MIP) &
                         ~cpu_read_csr(CSR_MIDELEG);
    uint64_t s_pending = cpu_read_csr(CSR_SIE) & cpu_read_csr(CSR_SIP);
    uint64_t pending = 0;
    switch (rv.privilege) {
        case PRIV_M:
            if (cpu_read_csr(CSR_MSTATUS) & MSTATUS_MIE)
                pending = m_pending;
            break;
        case PRIV_S:
            if (cpu_read_csr(CSR_MSTATUS) & MSTATUS_MIE)
                pending = m_pending;
            else if (cpu_read_csr(CSR_SSTATUS) & SSTATUS_SIE)
                pending = s_pending;
            break;
        case PRIV_U: break;
    }

    if (pending == 0)
        return CAUSE_INTERRUPT_NONE;

    // External
    if (pending & MIP_MEIP)
        return CAUSE_MACHINE_EXTERNAL;
    if (pending & SIP_SEIP)
        return CAUSE_SUPERVISOR_EXTERNAL;

    // Software
    if (pending & MIP_MSIP)
        return CAUSE_MACHINE_SOFTWARE;
    if (pending & SIP_SSIP)
        return CAUSE_SUPERVISOR_SOFTWARE;

    // Timer
    if (pending & MIP_MTIP)
        return CAUSE_MACHINE_TIMER;
    if (pending & SIP_STIP)
        return CAUSE_SUPERVISOR_TIMER;

    return CAUSE_INTERRUPT_NONE;
}

void rv_shutdown(int code, shutdown_cause_t cause) {
    rv.shutdown = true;
    rv.shutdown_code = code;
    rv.shutdown_cause = cause;
    printf("shutdown with code %d and cause %d\n", code, (int)cause);
}
