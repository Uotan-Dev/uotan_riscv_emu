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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/history.h>
#include <readline/readline.h>

#include "common.h"
#include "core/cpu.h"
#include "utils/misc.h"

typedef struct {
    const char *name;
    const char *desc;
    void (*handler)(char *);
} cmd_t;

// Forward declarations of cmds
static void cmd_clear(char *args);
static void cmd_info(char *args);
static void cmd_help(char *args);
static void cmd_quit(char *args);

// clang-format off
static const cmd_t cmd_table[] = {
    {"clear", "Clear the screen", cmd_clear},
    {"quit", "Quit the emulator", cmd_quit},
    {"info", "Print some info", cmd_info},
    {"help", "Print the help msg", cmd_help},
};
// clang-format on

static void cmd_clear(char *args) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

static void cmd_info(char *args) { cpu_print_registers(); }

static void cmd_help(char *args) {
    for (size_t i = 0; i < ARRAY_SIZE(cmd_table); i++)
        printf("%-6s %-10s\n", cmd_table[i].name, cmd_table[i].desc);
}

static void cmd_quit(char *args) { exit(EXIT_SUCCESS); }

static char *input = NULL;

static void ui_handle_input() {
    if (input == NULL || *input == '\0')
        return;

    add_history(input);

    char *cmd = strtok(input, " ");
    if (cmd == NULL)
        return;
    char *args = strtok(NULL, " ");

    size_t i = 0;
    for (; i < ARRAY_SIZE(cmd_table); i++) {
        if (!strcmp(cmd_table[i].name, cmd)) {
            cmd_table[i].handler(args); // Run cmd
            return;
        }
    }
    if (i >= ARRAY_SIZE(cmd_table)) {
        printf("Invalid command: %s\n", cmd);
        puts("Type \"help\" for a list of valid commands");
    }
}

void ui_start() {
    set_stdin_blocking();

    using_history();

    while (true) {
        if (input) {
            free(input); // Free previous input
            input = NULL;
        }
        input = readline("(uemu) ");

        // Handle user input
        ui_handle_input();
    }
}
