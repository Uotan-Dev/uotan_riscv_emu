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

#define TIMER_HZ 60

typedef void (*alarm_handler_t)();

/**
 * @brief Initializes the alarm.
 */
void alarm_init();

/**
 * @brief Turns on/off the alarm.
 *
 * @param on  New status of the alarm.
 */
void alarm_turn(bool on);

/**
 * @brief Adds a handler to the alarm.
 *
 * This function adds a handler to the alarm. Added handlers will be called with
 * TIMER_HZ.
 *
 * @param h  A function pointer to the handler.
 */
void alarm_add_handle(alarm_handler_t h);

#ifdef __cplusplus
}
#endif
