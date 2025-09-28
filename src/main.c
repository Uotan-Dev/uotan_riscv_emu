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
#include "utils/arg_handler.h"
#include "utils/gdbstub.h"
#include "utils/logger.h"
#include "utils/timer.h"

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

    atexit(cleanup_load_buffers);

    int buffer_count;
    rv_load_t *loads = get_load_buffers(&buffer_count);
    if (loads == NULL) {
        log_error("create_load_buffer() failed");
        exit(EXIT_FAILURE);
    }

    log_info("Start with %d buffers", buffer_count);
    rv_init(loads, (size_t)buffer_count);

    if (is_gdb_enabled())
        gdbstub_emu_start();
    else
        cpu_start();

    return EXIT_SUCCESS;
}
