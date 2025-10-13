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

#include "core/cpu.h"
#include "core/riscv.h"
#include "ui/ui.h"
#include "utils/alarm.h"
#include "utils/elf.h"
#include "utils/gdbstub.h"
#include "utils/logger.h"

extern char *disk_file;

static const char *bin_file = NULL;
static const char *signature_out_file = NULL;
static bool opt_gdb = false;

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] IMAGE\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help                Show this help message and exit\n");
    printf("      --gdb                 Enable gdbstub support\n");
    printf("      --disk FILE           Specify disk file\n");
    printf("      --signature FILE      Write signature output to FILE\n");
    printf("\nExamples:\n");
    printf("  %s hello.bin\n", progname);
    printf("  %s --gdb hello.bin\n", progname);
    printf("  %s --disk disk.img hello.bin\n", progname);
    printf("  %s --help\n", progname);
}

static void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"gdb", no_argument, NULL, 'g'},
        {"disk", required_argument, NULL, 'd'},
        {"signature", required_argument, NULL, 's'},
        {NULL, 0, NULL, 0}};

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "hg", long_options, &option_index)) !=
           -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'g': opt_gdb = true; break;
            case 'd': disk_file = optarg; break;
            case 's': signature_out_file = optarg; break;
            case '?':
                /* getopt_long already printed error message */
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
                break;
            default:
                fprintf(stderr, "Unexpected option\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
                break;
        }
    }

    /* Get positional argument (IMAGE) */
    if (optind < argc) {
        bin_file = argv[optind];
    }

    if (bin_file == NULL) {
        fprintf(stderr, "No image file specified.");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    puts("uemu - tiny RISC-V system emulator");
    puts("Built on " __DATE__ " " __TIME__ "");
    puts("Copyright 2025 Nuo Shen, Nanjing University");
    puts("Licensed under the Apache License 2.0");
    puts("See https://www.apache.org/licenses/LICENSE-2.0");
    putchar('\n');

    parse_args(argc, argv);

    log_set_output(stderr);
    log_info("Logger started at stderr.");

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
        ui_close();
    }

    rv_destroy();

    return EXIT_SUCCESS;
}
