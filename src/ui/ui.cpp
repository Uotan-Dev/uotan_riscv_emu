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

static struct SDL_Window *window;
static struct SDL_Renderer *renderer;
static struct SDL_Texture *texture;

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
    SDL_Surface *icon = SDL_LoadBMP_IO(rw, 1);
    if (!icon) {
        log_warn("Failed to load embedded icon: %s", SDL_GetError());
        return;
    }

    SDL_SetWindowIcon(window, icon);
    SDL_DestroySurface(icon);
}

void ui_init() {
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS))
        goto ui_fail;

    // Create the window
    window = SDL_CreateWindow("Uotan RISC-V Emulator", FB_WIDTH, FB_HEIGHT, 0);
    if (!window)
        goto ui_fail;

    // Set window icon
    ui_set_window_icon();

    // Create the renderer
    renderer = SDL_CreateRenderer(window, NULL);
    if (!renderer)
        goto ui_fail;

    // Create the texture
    texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888,
                                SDL_TEXTUREACCESS_STATIC, FB_WIDTH, FB_HEIGHT);
    if (!texture)
        goto ui_fail;
    /* For SDL3.
     * ARGB8888 includes an alpha byte; if alpha is 0 pixels may be treated as
     * transparent. Disable SDL blending so the renderer does not use the
     * texture alpha for blending.
     */
    SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_NONE);

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
        texture = NULL;
    }
    if (renderer) {
        SDL_DestroyRenderer(renderer);
        renderer = NULL;
    }
    if (window) {
        SDL_DestroyWindow(window);
        window = NULL;
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
        SDL_RenderTexture(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }

    ui_update_requested = 0;
}
