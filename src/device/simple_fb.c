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

#include <SDL3/SDL.h>
#include <assert.h>
#include <stdlib.h>

#include "core/riscv.h"
#include "device/simple_fb.h"
#include "ui/ui.h"
#include "utils/logger.h"

simple_fb_t simple_fb;

static size_t fb_size;

static uint64_t simple_fb_read(uint64_t addr, size_t n) {
    assert(n <= 8);
    uint64_t offset = addr - SIMPLEFB_BASE;
    if (offset >= fb_size)
        return 0;
    uint64_t v = 0;
    pthread_mutex_lock(&simple_fb.m);
    memcpy(&v, simple_fb.vram + offset, n);
    pthread_mutex_unlock(&simple_fb.m);
    return v;
}

static void simple_fb_write(uint64_t addr, uint64_t value, size_t n) {
    uint64_t offset = addr - SIMPLEFB_BASE;
    if (offset > fb_size)
        return;
    pthread_mutex_lock(&simple_fb.m);
    memcpy(simple_fb.vram + offset, &value, n);
    simple_fb.dirty = true;
    pthread_mutex_unlock(&simple_fb.m);
}

bool simple_fb_tick(struct SDL_Texture *texture) {
    if (!ui_initialized())
        return false;
    if (!simple_fb.dirty)
        return false;
    pthread_mutex_lock(&simple_fb.m);
    SDL_UpdateTexture(texture, NULL, simple_fb.vram, ui_width * FB_BPP);
    simple_fb.dirty = false;
    pthread_mutex_unlock(&simple_fb.m);
    return true;
}

void simple_fb_init() {
    memset(&simple_fb, 0, sizeof(simple_fb));

    pthread_mutex_init(&simple_fb.m, NULL);

    fb_size = ui_width * ui_height * FB_BPP;
    simple_fb.vram = (uint8_t *)calloc(fb_size, sizeof(uint8_t));
    assert(simple_fb.vram);

    rv_add_device((device_t){
        .name = "simple-framebuffer",
        .start = SIMPLEFB_BASE,
        .end = SIMPLEFB_BASE + fb_size - 1ULL,
        .read = simple_fb_read,
        .write = simple_fb_write,
    });
}

void simple_fb_destroy() {
    int rc = pthread_mutex_destroy(&simple_fb.m);
    if (rc)
        log_warn("destroy simple_fb lock failed");

    if (simple_fb.vram) {
        free(simple_fb.vram);
        simple_fb.vram = NULL;
    }
}
