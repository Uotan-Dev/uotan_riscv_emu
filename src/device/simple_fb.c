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

#include <SDL2/SDL.h>
#include <assert.h>

#include "core/riscv.h"
#include "device/simple_fb.h"
#include "ui/ui.h"

simple_fb_t simple_fb;

static uint64_t simple_fb_read(uint64_t addr, size_t n) {
    assert(n <= 8);
    uint64_t offset = addr - SIMPLEFB_BASE;
    if (offset >= SIMPLEFB_BASE)
        return 0;
    uint64_t v = 0;
    pthread_mutex_lock(&simple_fb.m);
    memcpy(&v, simple_fb.vram + offset, n);
    pthread_mutex_unlock(&simple_fb.m);
    return v;
}

static void simple_fb_write(uint64_t addr, uint64_t value, size_t n) {
    uint64_t offset = addr - SIMPLEFB_BASE;
    if (offset > SIMPLEFB_BASE)
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
    SDL_UpdateTexture(texture, NULL, simple_fb.vram, FB_WIDTH * FB_BPP);
    simple_fb.dirty = false;
    pthread_mutex_unlock(&simple_fb.m);
    return true;
}

void simple_fb_init() {
    memset(&simple_fb, 0, sizeof(simple_fb));

    rv_add_device((device_t){
        .name = "simple-framebuffer",
        .start = SIMPLEFB_BASE,
        .end = SIMPLEFB_BASE + SIMPLEFB_SIZE - 1ULL,
        .read = simple_fb_read,
        .write = simple_fb_write,
    });
}
