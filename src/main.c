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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cpu.h"
#include "core/riscv.h"
#include "utils/logger.h"
#include "utils/timer.h"

static const char *bin_file = NULL;

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] IMAGE\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help        Show this help message and exit\n");
    printf("\nExamples:\n");
    printf("  %s hello.bin\n", progname);
    printf("  %s --help\n", progname);
}

static void parse_args(int argc, char *argv[]) {
    // clang-format off
    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    // clang-format on

    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case '?': // getopt_long already prints an error
            default: print_usage(argv[0]); exit(EXIT_FAILURE);
        }
    }

    if (optind < argc)
        bin_file = argv[optind];
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    // Initialize the logger
    log_set_output(stderr);
    log_info("Logger started");

    if (timer_start(1) != 0) {
        log_error("timer_start() failed!\n");
        exit(EXIT_FAILURE);
    }
    atexit(timer_stop);

    // Load the bin_file
    void *buf = NULL;
    size_t buf_size = 0;
    if (unlikely(!bin_file || bin_file[0] == '\0')) {
        extern const uint8_t bare_min_firmware_bin[];
        extern size_t bare_min_firmware_bin_len;
        buf_size = bare_min_firmware_bin_len;
        buf = malloc(buf_size);
        assert(buf);
        memcpy(buf, bare_min_firmware_bin, buf_size);
        log_info("Loaded builtin_img from %p", bare_min_firmware_bin);
    } else {
        FILE *fp = fopen(bin_file, "rb");
        if (fp == NULL) {
            fprintf(stderr, "fopen failed\n");
            exit(EXIT_FAILURE);
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        if (size == 0) {
            fprintf(stderr, "file size is 0\n");
            exit(EXIT_FAILURE);
        }
        buf_size = size;
        buf = malloc(buf_size);
        assert(buf);
        fseek(fp, 0, SEEK_SET);
        unsigned long res = fread(buf, size, 1, fp);
        assert(res == 1);
        fclose(fp);
        log_info("Loaded image %s of size %ld...", bin_file, size);
    }

    // Initialize our RISC-V machine
    rv_init(buf, buf_size);
    free(buf);

    // Start CPU
    cpu_start();

    return EXIT_SUCCESS;
}
