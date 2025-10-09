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

#include <SDL2/SDL.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FB_WIDTH 1024
#define FB_HEIGHT 768
#define FB_BPP 4 // Bytes per pixel (32-bit color)
#define FB_SIZE (FB_WIDTH * FB_HEIGHT * FB_BPP)

#define SIMPLEFB_BASE 0x50000000
#define SIMPLEFB_SIZE FB_SIZE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t vram[FB_SIZE];
    bool dirty; // Whether vram has been written
    pthread_mutex_t m;
} simple_fb_t;

extern simple_fb_t simple_fb;

void simple_fb_init();
void simple_fb_destory();
bool simple_fb_tick(struct SDL_Texture *texture);

#ifdef __cplusplus
}
#endif
