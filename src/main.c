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
#include <stdlib.h>
#include <string.h>

#include "core/cpu.h"
#include "core/riscv.h"
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
    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != 1) {
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

    if (timer_start(1) != 0) {
        fprintf(stderr, "timer_start() failed!\n");
        exit(EXIT_FAILURE);
    }
    atexit(timer_stop);

    // Load the bin_file
    void *buf = NULL;
    size_t buf_size = 0;
    if (unlikely(!bin_file && bin_file[0] == '\0')) {
        static const uint32_t builtin_img[] = {
            0x00000297, // auipc t0,0
            0x00028823, // sb  zero,16(t0)
            0x0102c503, // lbu a0,16(t0)
            0x0000006f, // j 0
        };
        buf_size = sizeof(builtin_img);
        buf = malloc(buf_size);
        assert(buf);
        memcpy(buf, builtin_img, sizeof(builtin_img));
        Log("Loaded builtin_img from %p", builtin_img);
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
        Log("Loaded image %s of size %ld...", bin_file, size);
    }

    // Initialize our RISC-V machine
    rv_init(buf, buf_size);
    free(buf);

    // Start CPU
    cpu_start();

    return EXIT_SUCCESS;
}
