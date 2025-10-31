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
#include <stddef.h>

extern bool ui_small_screen;
extern size_t ui_height, ui_width;

#define UI_WIDTH_DEFAULT 1024
#define UI_HEIGHT_DEFAULT 768

#define UI_WIDTH_SMALL 400
#define UI_HEIGHT_SMALL 300

void ui_set_small();
void ui_init();
void ui_close();
bool ui_initialized();
void ui_request_global_update();
void ui_request_display_update(const void *buf);
void ui_update();

#ifdef __cplusplus
}
#endif
