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

#include <SDL2/SDL_main.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cpu.h"
#include "core/riscv.h"
#include "ui/ui.h"
#include "utils/alarm.h"
#include "utils/elf.h"
#include "utils/gdbstub.h"
#include "utils/logger.h"
#include "utils/timer.h"

static const char *bin_file = NULL;
static const char *signature_out_file = NULL;
static bool opt_gdb = false;

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] IMAGE\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help        Show this help message and exit\n");
    printf("      --gdb         Enable gdbstub support\n");
    printf("\nExamples:\n");
    printf("  %s hello.bin\n", progname);
    printf("  %s --gdb hello.bin\n", progname);
    printf("  %s --help\n", progname);
}

static void parse_args(int argc, char *argv[]) {
    int i = 1;
    while (i < argc) {
        if (argv[i][0] == '+') {
            if (strncmp(argv[i], "+signature=", 11) == 0)
                signature_out_file = argv[i] + 11;
            i++;
            continue;
        }
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--gdb") == 0) {
                opt_gdb = true;
            } else if (strcmp(argv[i], "-h") == 0 ||
                       strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            }
            // We ignore arguments like --isa
            i++;
            continue;
        }
        if (bin_file == NULL)
            bin_file = argv[i];
        i++;
    }

    if (bin_file == NULL) {
        log_error("No image file specified.");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    log_set_output(stdout);

    parse_args(argc, argv);
    log_info("uEmu - A simple RISC-V emulator");

    // Start the alarm
    alarm_init();

    // Initialize the machine
    rv_init();

    // Parse and load the binary file
    uint64_t entry_point = 0;
    if (is_elf(bin_file)) {
        log_info("Loading ELF file %s", bin_file);
        entry_point = elf_load(bin_file);
        if (!paddr_in_pmem(entry_point)) {
            log_error("Entry point not in pmem");
            exit(EXIT_FAILURE);
        }
    } else {
        if (signature_out_file) {
            log_error("signature out file cannot be used with bins");
            exit(EXIT_FAILURE);
        }
        log_info("Loading BIN file %s", bin_file);
        FILE *fp = fopen(bin_file, "rb");
        if (!fp) {
            log_error("fopen failed");
            exit(EXIT_FAILURE);
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        assert(size);
        fseek(fp, 0, SEEK_SET);
        unsigned long res = fread(GUEST_TO_HOST(MBASE), size, 1, fp);
        assert(res == 1);
        fclose(fp);
        entry_point = MBASE;
    }

    // Update start PC
    if (entry_point != MBASE) {
        log_warn("Setting PC to non-default 0x%08" PRIx64 "", entry_point);
        rv.PC = entry_point;
    }

    // Setup timer
    if (timer_start(1) != 0) {
        log_error("timer_start() failed!\n");
        exit(EXIT_FAILURE);
    }
    atexit(timer_stop);

    // Start CPU
    if (opt_gdb) {
        gdbstub_emu_start();
    } else if (signature_out_file) {
        cpu_start_archtest();
        dump_signature(bin_file, signature_out_file);
    } else {
        // Start the UI
        ui_init();
        cpu_start();
    }

    ui_close();

    return EXIT_SUCCESS;
}
