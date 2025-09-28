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

#include "utils/arg_handler.h"

#define MAX_EXTRA_FILES 16

typedef struct {
    char *file_path;
    uint64_t load_addr;
} file_spec_t;

static bool opt_gdb = false;
static char *bin_file = NULL;
static file_spec_t file_specs[MAX_EXTRA_FILES];
static int file_spec_count = 0;
static rv_load_t load_buffers[MAX_EXTRA_FILES + 1];
static int load_buffer_count = 0;

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] IMAGE\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help                    Show this help message and exit\n");
    printf("      --gdb                     Enable gdbstub support\n");
    printf("  -l, --load FILE@ADDR          Load additional file to specified "
           "address\n");
    printf("\nAddress format:\n");
    printf(
        "  Addresses can be specified in decimal or hexadecimal (0x prefix)\n");
    printf("  Examples: 0x80200000, 2148532224, 0x82200000\n");
    printf("\nExamples:\n");
    printf("  %s fw_jump.bin\n", progname);
    printf("  %s --gdb fw_payload.bin\n", progname);
    printf("  %s fw_jump.bin -l Image@0x80200000 -l system.dtb@0x82200000\n",
           progname);
    printf("  %s fw_jump.bin -l bbl@0x80000000 -l Image@0x80200000\n",
           progname);
    printf("  %s opensbi.bin -l vmlinux@0x80200000 -l qemu.dtb@0x82200000 -l "
           "initramfs.cpio@0x84000000\n",
           progname);
}

static uint64_t parse_address(const char *addr_str) {
    char *endptr;
    uint64_t addr;

    if (strncmp(addr_str, "0x", 2) == 0 || strncmp(addr_str, "0X", 2) == 0) {
        addr = strtoull(addr_str, &endptr, 16);
    } else {
        addr = strtoull(addr_str, &endptr, 10);
    }

    if (*endptr != '\0') {
        fprintf(stderr, "Error: Invalid address format: %s\n", addr_str);
        exit(EXIT_FAILURE);
    }

    return addr;
}

static void add_file_spec(const char *file_path, uint64_t load_addr) {
    if (file_spec_count >= MAX_EXTRA_FILES) {
        fprintf(stderr, "Error: Too many extra files (maximum %d)\n",
                MAX_EXTRA_FILES);
        exit(EXIT_FAILURE);
    }

    file_specs[file_spec_count].file_path = strdup(file_path);
    file_specs[file_spec_count].load_addr = load_addr;
    file_spec_count++;

    printf("Added file to load: %s @ 0x%016lx\n", file_path, load_addr);
}

// Parse --load FILE@ADDR format
static void parse_load_option(const char *load_spec) {
    char *spec_copy = strdup(load_spec);
    char *at_pos = strchr(spec_copy, '@');

    if (!at_pos) {
        fprintf(stderr,
                "Error: Invalid load format. Expected FILE@ADDR, got: %s\n",
                load_spec);
        fprintf(stderr, "Example: Image@0x80200000\n");
        exit(EXIT_FAILURE);
    }

    *at_pos = '\0';
    char *file_path = spec_copy;
    char *addr_str = at_pos + 1;

    uint64_t load_addr = parse_address(addr_str);
    add_file_spec(file_path, load_addr);

    free(spec_copy);
}

// Load file to memory buffer
static void *load_file_to_buffer(const char *file_path, size_t *file_size) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", file_path);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory
    void *buffer = malloc(*file_size);
    if (!buffer) {
        fprintf(stderr,
                "Error: Cannot allocate memory for file %s (%zu bytes)\n",
                file_path, *file_size);
        fclose(file);
        return NULL;
    }

    // Read file content
    size_t bytes_read = fread(buffer, 1, *file_size, file);
    if (bytes_read != *file_size) {
        fprintf(stderr, "Error: Failed to read file %s completely\n",
                file_path);
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    printf("Loaded file %s: %zu bytes\n", file_path, *file_size);
    return buffer;
}

// Create load buffer array
static int create_load_buffers() {
    load_buffer_count = 0;

    if (bin_file) {
        size_t file_size;
        void *buffer = load_file_to_buffer(bin_file, &file_size);
        if (!buffer) {
            fprintf(stderr, "Error: Failed to load main binary file: %s\n",
                    bin_file);
            return -1;
        }

        load_buffers[load_buffer_count].buf = buffer;
        load_buffers[load_buffer_count].n = file_size;
        load_buffers[load_buffer_count].addr = 0x80000000;
        load_buffer_count++;

        printf("Main binary: %s @ 0x%016lx (%zu bytes)\n", bin_file,
               load_buffers[0].addr, file_size);
    }

    for (int i = 0; i < file_spec_count; i++) {
        size_t file_size;
        void *buffer = load_file_to_buffer(file_specs[i].file_path, &file_size);
        if (!buffer) {
            fprintf(stderr, "Error: Failed to load file: %s\n",
                    file_specs[i].file_path);
            for (int j = 0; j < load_buffer_count; j++)
                free(load_buffers[j].buf);
            return -1;
        }

        load_buffers[load_buffer_count].buf = buffer;
        load_buffers[load_buffer_count].n = file_size;
        load_buffers[load_buffer_count].addr = file_specs[i].load_addr;

        printf("Extra file: %s @ 0x%016lx (%zu bytes)\n",
               file_specs[i].file_path, file_specs[i].load_addr, file_size);

        load_buffer_count++;
    }

    return load_buffer_count;
}

void parse_args(int argc, char *argv[]) {
    // clang-format off
    const struct option long_options[] = {
        {"help",    no_argument,       NULL, 'h'},
        {"gdb",     no_argument,       NULL,  1},
        {"load",    required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };
    // clang-format on

    int opt;
    while ((opt = getopt_long(argc, argv, "hl:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h': print_usage(argv[0]); exit(EXIT_SUCCESS);

            case 1: // --gdb
                opt_gdb = true;
                break;

            case 'l': // --load FILE@ADDR
                parse_load_option(optarg);
                break;

            case '?':
            default: print_usage(argv[0]); exit(EXIT_FAILURE);
        }
    }

    // Get the main binary file
    if (optind < argc) {
        bin_file = argv[optind];
    } else {
        fprintf(stderr, "Error: No image file specified\n\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Display load plan
    printf("\nLoad plan:\n");
    printf("  Main image: %s @ 0x80000000\n", bin_file);
    for (int i = 0; i < file_spec_count; i++) {
        printf("  Extra file: %s @ 0x%016lx\n", file_specs[i].file_path,
               file_specs[i].load_addr);
    }
    putchar('\n');
}

// Check if GDB is enabled
bool is_gdb_enabled() { return opt_gdb; }

// Create and return load buffer array
rv_load_t *get_load_buffers(int *count) {
    if (load_buffer_count == 0) {
        if (create_load_buffers() < 0) {
            *count = 0;
            return NULL;
        }
    }

    *count = load_buffer_count;
    return load_buffers;
}

// Clean up all allocated resources
void cleanup_load_buffers() {
    // Free file path strings
    for (int i = 0; i < file_spec_count; i++)
        free(file_specs[i].file_path);
    file_spec_count = 0;

    // Free load buffers
    for (int i = 0; i < load_buffer_count; i++) {
        if (load_buffers[i].buf) {
            free(load_buffers[i].buf);
            load_buffers[i].buf = NULL;
        }
    }
    load_buffer_count = 0;
}
