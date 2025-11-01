/*
 * Copyright 2025 Nuo Shen, Nanjing University
 * Copyright 2025 UOTAN
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
#include <signal.h>
#include <stdlib.h>

#include <linux/input-event-codes.h>

#include "common.h"
#include "core/riscv.h"
#include "device/goldfish_events.h"
#include "device/simple_fb.h"
#include "ui/ui.h"
#include "utils/alarm.h"
#include "utils/logger.h"

#include "uotan_bmp.hpp"

bool ui_small_screen = false;
size_t ui_height = UI_HEIGHT_DEFAULT;
size_t ui_width = UI_WIDTH_DEFAULT;

static SDL_Window *window;
static SDL_Renderer *renderer;
static SDL_Texture *texture;
static SDL_Surface *icon;
static const char *title = "Uotan RISC-V Emulator";

static bool initialized;

static sig_atomic_t ui_update_requested;

static void ui_set_window_icon() {
    SDL_IOStream *rw = SDL_IOFromConstMem(uotan_bmp, uotan_bmp_len);
    if (!rw) {
        log_warn("Failed to create RWops for embedded icon: %s",
                 SDL_GetError());
        return;
    }

    // Load BMP from memory
    icon = SDL_LoadBMP_IO(rw, 1);
    if (!icon) {
        log_warn("Failed to load embedded icon: %s", SDL_GetError());
        return;
    }

    SDL_SetWindowIcon(window, icon);
    // SDL_DestroySurface(icon);
}

static void ui_startup_screen() {
    if (!icon) {
        log_warn("Icon not loaded, skipping startup screen");
        return;
    }

    pthread_mutex_lock(&simple_fb.m);

    const size_t fb_size = ui_width * ui_height * FB_BPP;
    uint8_t *buf = new uint8_t[fb_size];
    memset(buf, 0, fb_size);

    int x_offset = (ui_width - 96) >> 1;
    int y_offset = (ui_height - 96) >> 1;

    for (int y = 0; y < 96; y++) {
        uint8_t *src = (uint8_t *)icon->pixels + y * icon->pitch;
        uint8_t *dst = buf + ((y_offset + y) * ui_width + x_offset) * FB_BPP;
        memcpy(dst, src, 96 * FB_BPP);
    }

    simple_fb.dirty = true;
    pthread_mutex_unlock(&simple_fb.m);

    SDL_UpdateTexture(texture, nullptr, buf, ui_width * FB_BPP);
    SDL_RenderClear(renderer);
    SDL_RenderTexture(renderer, texture, nullptr, nullptr);
    SDL_RenderPresent(renderer);

    // delay 1.6s
    SDL_Delay(1600);

    delete[] buf;
}

void ui_set_small() {
    ui_small_screen = true;
    ui_height = UI_HEIGHT_SMALL;
    ui_width = UI_WIDTH_SMALL;
}

void ui_init() {
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS))
        goto ui_fail;

    // Create the window
    if (ui_small_screen)
        window = SDL_CreateWindow(title, ui_width * 3, ui_height * 3, 0);
    else
        window = SDL_CreateWindow(title, ui_width, ui_height, 0);

    if (!window)
        goto ui_fail;

    // Set window icon
    ui_set_window_icon();

    // Create the renderer
    renderer = SDL_CreateRenderer(window, nullptr);
    if (!renderer)
        goto ui_fail;

    // Create the texture
    texture =
        SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888,
                          SDL_TEXTUREACCESS_STREAMING, ui_width, ui_height);
    if (!texture)
        goto ui_fail;
    /* For SDL3.
     * ARGB8888 includes an alpha byte; if alpha is 0 pixels may be treated as
     * transparent. Disable SDL blending so the renderer does not use the
     * texture alpha for blending.
     */
    SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_NONE);

    // Start splash screen
    ui_startup_screen();

    // Make global update periodic
    ui_update_requested = 0;
    alarm_add_handle([]() -> void { ui_update_requested = 1; });

    initialized = true;

    return;

ui_fail:
    log_error("UI initialization failed. Last SDL error: %s", SDL_GetError());
    exit(EXIT_FAILURE);
}

void ui_close() {
    initialized = false;
    if (texture) {
        SDL_DestroyTexture(texture);
        texture = nullptr;
    }
    if (renderer) {
        SDL_DestroyRenderer(renderer);
        renderer = nullptr;
    }
    if (window) {
        SDL_DestroyWindow(window);
        window = nullptr;
    }
    if (icon) {
        SDL_DestroySurface(icon);
        icon = nullptr;
    }
    SDL_Quit();
}

bool ui_initialized() { return initialized; }

void ui_update() {
    if (!initialized)
        return;

#define macro(key)                                                             \
    case SDL_SCANCODE_##key: return KEY_##key;

    auto sdl_to_linux_keycode = [](SDL_Scancode scancode) -> uint32_t {
        switch (scancode) {
            GOLDFISH_KEYS(macro)
            default: return 0;
        }
        __UNREACHABLE;
    };

#undef macro

    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_EVENT_QUIT:
                log_info("SDL Quit");
                rv_shutdown(0, SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
                rv_destroy();
                exit(EXIT_SUCCESS);
            case SDL_EVENT_KEY_DOWN: /* fallthrough */
            case SDL_EVENT_KEY_UP: {
                uint32_t kc = sdl_to_linux_keycode(event.key.scancode);
                if (kc) {
                    if (event.type == SDL_EVENT_KEY_DOWN)
                        kc |= 0x200;
                    events_put_keycode(kc);
                }
                break;
            }
        }
    }

    if (!ui_update_requested)
        return;

    if (simple_fb_tick(texture)) {
        SDL_RenderClear(renderer);
        SDL_RenderTexture(renderer, texture, nullptr, nullptr);
        SDL_RenderPresent(renderer);
    }

    ui_update_requested = 0;
}
