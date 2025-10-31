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

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "../device/bus.h"
#include "cpu/decode.h"
#include "cpu/fpu.h"
#include "cpu/system.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESET_PC 0x80000000

typedef enum : int {
    SHUTDOWN_CAUSE_GUEST_PANIC,
    SHUTDOWN_CAUSE_GUEST_SHUTDOWN
} shutdown_cause_t;

typedef struct {
    // Interger registers
#define NR_GPR 32
    uint64_t X[NR_GPR];

    // Program counter
    uint64_t PC;

    // FPRs
#define NR_FPR 32
    fpr_t F[NR_FPR];

    // Control and Status registers
    // Instruction implementations should not write these fields directly, see
    // include/core/cpu.h for a set of valid functions
#define NR_CSR 4096

    uint64_t MVENDORID;  // Vendor ID
    uint64_t MARCHID;    // Architecture ID
    uint64_t MIMPID;     // Implementation ID
    uint64_t MHARTID;    // Hardware thread ID
    uint64_t MSTATUS;    // Machine status register
    uint64_t MISA;       // ISA and extensions
    uint64_t MEDELEG;    // Machine exception delegate register
    uint64_t MIDELEG;    // Machine interrupt delegate register
    uint64_t MIE;        // Machine interrupt-enable register
    uint64_t MTVEC;      // Machine trap-handler base address
    uint32_t MCOUNTEREN; // Machine counter enable
    uint64_t MSCRATCH;   // Scratch register for machine trap handlers
    uint64_t MEPC;       // Machine exception program counter
    uint64_t MCAUSE;     // Machine trap cause
    uint64_t MTVAL;      // Machine bad address or instruction
    uint64_t MIP;        // Machine interrupt pending
    uint64_t MCYCLE;     // Machine cycle counter
    uint64_t MINSTRET;   // Machine instructions-retired counter
    uint64_t MENVCFG;    // Machine environment configuration register
    uint64_t MSECCFG;    // Machine security configuration register

    // SSTATUS, SIE, SIP are not here because they will be inferred
    // from M-mode CSRs

    uint64_t STVEC;      // Supervisor trap-handler base address
    uint32_t SCOUNTEREN; // Supervisor counter enable
    uint64_t SSCRATCH;   // Supervisor register for machine trap handlers
    uint64_t SEPC;       // Supervisor exception program counter
    uint64_t SCAUSE;     // Supervisor trap cause
    uint64_t STVAL;      // Supervisor bad address or instruction
    uint64_t SATP;       // Supervisor address translation and protection
    uint64_t STIMECMP;   // Supervisor timer compare.

    uint64_t MTIME; // Mirrored from clint

    // Floating-point control and status register
    fcsr_t FCSR;

    // Lock for CSRs that are accessed in multiple threads.
    // Currently for MIP and SIP.
    pthread_mutex_t csr_lock;

    // The value written to instret will be the value read by the following
    // instruction (i.e. the increment is suppressed)
    bool suppress_minstret_increase;

    // Privilege level
    privilege_level_t privilege;

    // For LR/SC implementation
    uint64_t reservation_address;
    bool reservation_valid;

    // Last exception
    exception_t last_exception;

    // Seed CSR related
    bool seed_written;
    uint32_t seed_state;

    // Memory
#define MSIZE 0x20000000
#define MBASE 0x80000000
    uint8_t memory[MSIZE] __attribute((aligned(4096)));

    // Decoder status
    Decode decode;

    // Bus status
    bus_t bus;

    // Misc
    bool shutdown;
    int shutdown_code;
    shutdown_cause_t shutdown_cause;
    bool is_interrupted_gdb; // for gdbstub
} riscv_t;

extern riscv_t rv __attribute((aligned(4096)));

/**
 * @brief Initializes the RISC-V machine.
 *
 * This function is reponsible for initializeing core components like CPU, DRAM
 * and bus.
 */
void rv_init();

/**
 * @brief Copys some data into the machine memory.
 *
 * This function can only be called after rv_init().
 *
 * @param buf A pointer to the buffer.
 * @param n   Bytes to copy.
 */
void rv_load(const void *buf, size_t n);

/**
 * @brief Connects a device to the machine.
 *
 * This function calls bus_add_device() in the background to add a device to the
 * bus.
 *
 * @param dev A struct that contains device information.
 */
void rv_add_device(device_t dev);

/**
 * @brief Powers off the simulated RISC-V machine.
 *
 * This function terminates CPU execution and performs system shutdown
 * with the specified exit code and cause. It is typically invoked by
 * the SiFive test device or when an unrecoverable exception occurs.
 *
 * @param code   Exit code returned to the host environment (e.g., test result).
 * @param cause  The reason for shutdown, defined by shutdown_cause_t.
 */
void rv_shutdown(int code, shutdown_cause_t cause);

/**
 * @brief Recycle resources before exiting.
 */
void rv_destroy();

#ifdef __cplusplus
}
#endif
