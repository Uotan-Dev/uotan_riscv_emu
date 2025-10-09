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

#include <stdbool.h>
#include <sys/select.h>
#include <termios.h>

#include "utils/misc.h"

static struct termios g_orig_tio;
static bool g_term_raw = false;

void enable_stdin_raw_mode() {
    if (g_term_raw)
        return;
    struct termios tio;
    if (tcgetattr(STDIN_FILENO, &tio) == -1)
        return;
    g_orig_tio = tio;
    tio.c_lflag &= ~(ECHO | ICANON | IEXTEN |
                     ISIG);         // no echo, non-canonical, disable signals
    tio.c_iflag &= ~(IXON | ICRNL); // disable software flow ctrl, CR->NL
    // tio.c_oflag &= ~(OPOST);
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &tio);
    g_term_raw = true;

    setvbuf(stderr, NULL, _IONBF, 0);
}

void disable_stdin_raw_mode() {
    if (!g_term_raw)
        return;
    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_tio);
    g_term_raw = false;
}
