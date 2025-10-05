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

#include <cstdarg>
#include <cstdio>

#include "common.h"
#include "utils/logger.h"

#define COLOR_RESET "\033[0m"
#define COLOR_INFO "\033[32m"
#define COLOR_WARN "\033[33m"
#define COLOR_ERROR "\033[31m"

static FILE *stream_output = nullptr;

static void log_print(const char *level, const char *color, const char *fmt,
                      va_list args) {
    fprintf(stream_output, "%s[%s] ", color, level);
    vfprintf(stream_output, fmt, args);
    fprintf(stream_output, "%s\n", COLOR_RESET);
}

void log_set_output(FILE *__restrict stream) { stream_output = stream; }

void log_info(const char *fmt, ...) {
    if (unlikely(!stream_output))
        return;
    va_list args;
    va_start(args, fmt);
    log_print("INFO", COLOR_INFO, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    if (unlikely(!stream_output))
        return;
    va_list args;
    va_start(args, fmt);
    log_print("WARN", COLOR_WARN, fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    if (unlikely(!stream_output))
        return;
    va_list args;
    va_start(args, fmt);
    log_print("ERROR", COLOR_ERROR, fmt, args);
    va_end(args);
}
