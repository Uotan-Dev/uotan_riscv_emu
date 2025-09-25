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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../common.h"

// TODO: support dynamic size
#define FIFO_SIZE 16

typedef struct {
    uint8_t buffer[FIFO_SIZE];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
} fifo_t;

FORCE_INLINE void fifo_init(fifo_t *f) { memset(f, 0, sizeof(fifo_t)); }

FORCE_INLINE bool fifo_is_full(const fifo_t *f) {
    return f->count == FIFO_SIZE;
}

FORCE_INLINE bool fifo_is_empty(const fifo_t *f) { return f->count == 0; }

FORCE_INLINE void fifo_push(fifo_t *f, uint8_t val) {
    if (fifo_is_full(f))
        return;
    f->buffer[f->head] = val;
    f->head = (f->head + 1) % FIFO_SIZE;
    f->count++;
}

FORCE_INLINE uint8_t fifo_pop(fifo_t *f) {
    if (fifo_is_empty(f))
        return 0;
    uint8_t val = f->buffer[f->tail];
    f->tail = (f->tail + 1) % FIFO_SIZE;
    f->count--;
    return val;
}

#ifdef __cplusplus
}
#endif
