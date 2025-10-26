/*
 * Copyright 2025 Nuo Shen, Nanjing University
 * Copyright 2025 UOTAN
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

extern char *disk_file;

static const char *bin_file = NULL;
static const char *signature_out_file = NULL;
static bool opt_gdb = false;

// Structure to hold load file information
typedef struct {
    char *filename;
    uint64_t address;
} load_file_t;

#define MAX_LOAD_FILES 16
static load_file_t load_files[MAX_LOAD_FILES];
static int load_file_count = 0;

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] IMAGE\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help                Show this help message and exit\n");
    printf("      --gdb                 Enable gdbstub support\n");
    printf("      --disk FILE           Specify disk file\n");
    printf("      --signature FILE      Write signature output to FILE\n");
    printf("      --load FILE@0xADDR    Load binary FILE to address 0xADDR\n");
    printf("                            Can be specified multiple times\n");
    printf("\nExamples:\n");
    printf("  %s hello.bin\n", progname);
    printf("  %s --gdb hello.bin\n", progname);
    printf("  %s --disk disk.img hello.bin\n", progname);
    printf("  %s --load data.bin@0x80100000 hello.bin\n", progname);
    printf("  %s --load data1.bin@0x80100000 --load data2.bin@0x80200000 "
           "hello.bin\n",
           progname);
    printf("  %s --help\n", progname);
}

static bool parse_load_option(const char *optarg) {
    if (load_file_count >= MAX_LOAD_FILES) {
        log_error("Too many --load options (max %d)", MAX_LOAD_FILES);
        return false;
    }

    // Find the '@' separator
    char *at_sign = strchr(optarg, '@');
    if (!at_sign) {
        log_error("Invalid --load format. Expected: FILE@0xADDRESS");
        return false;
    }

    // Extract filename
    size_t filename_len = at_sign - optarg;
    char *filename = malloc(filename_len + 1);
    if (!filename) {
        log_error("Memory allocation failed");
        return false;
    }
    strncpy(filename, optarg, filename_len);
    filename[filename_len] = '\0';

    // Parse address
    char *addr_str = at_sign + 1;
    char *endptr;
    uint64_t address = strtoull(addr_str, &endptr, 0);
    if (*endptr != '\0') {
        log_error("Invalid address format: %s", addr_str);
        free(filename);
        return false;
    }

    // Store the load file info
    load_files[load_file_count].filename = filename;
    load_files[load_file_count].address = address;
    load_file_count++;

    return true;
}

static void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"gdb", no_argument, NULL, 'g'},
        {"disk", required_argument, NULL, 'd'},
        {"signature", required_argument, NULL, 's'},
        {"load", required_argument, NULL, 'l'},
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
            case 'l':
                if (!parse_load_option(optarg)) {
                    print_usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
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

static bool load_binary_file(const char *filename, uint64_t address) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        log_error("Failed to open file: %s", filename);
        return false;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size <= 0) {
        log_error("Invalid file size: %s", filename);
        fclose(fp);
        return false;
    }
    fseek(fp, 0, SEEK_SET);

    // Check if address is in valid memory range
    if (!paddr_in_pmem(address) || !paddr_in_pmem(address + size - 1)) {
        log_error("Load address 0x%08" PRIx64 " or range is not in pmem",
                  address);
        fclose(fp);
        return false;
    }

    // Load file into memory
    log_info("Loading %s to 0x%08" PRIx64 " (size: %ld bytes)", filename,
             address, size);
    unsigned long res = fread(GUEST_TO_HOST(address), size, 1, fp);
    if (res != 1) {
        log_error("Failed to read file: %s", filename);
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

static void cleanup_load_files(void) {
    for (int i = 0; i < load_file_count; i++) {
        free(load_files[i].filename);
    }
}

int main(int argc, char *argv[]) {
    puts("uemu - tiny RISC-V system emulator");
    puts("Built on " __DATE__ " " __TIME__ "");
    puts("Copyright 2025 Nuo Shen, Nanjing University");
    puts("Copyright 2025 UOTAN");
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
            cleanup_load_files();
            exit(EXIT_FAILURE);
        }
    } else {
        if (signature_out_file) {
            log_error("signature out file cannot be used with bins");
            cleanup_load_files();
            exit(EXIT_FAILURE);
        }
        if (!load_binary_file(bin_file, MBASE)) {
            cleanup_load_files();
            exit(EXIT_FAILURE);
        }
        entry_point = MBASE;
    }

    // Load additional binary files
    for (int i = 0; i < load_file_count; i++) {
        if (!load_binary_file(load_files[i].filename, load_files[i].address)) {
            cleanup_load_files();
            exit(EXIT_FAILURE);
        }
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
    cleanup_load_files();

    return EXIT_SUCCESS;
}
