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

#define GOLDFISH_EVENTS_START 0x10002000
#define GOLDFISH_EVENTS_SIZE 0x1000

#define GOLDFISH_EVENTS_IRQ 2

// macro from
// https://github.com/NJU-ProjectN/nemu/blob/master/src/device/keyboard.c

// clang-format off
#define GOLDFISH_KEYS(f) \
  f(ESCAPE) f(F1) f(F2) f(F3) f(F4) f(F5) f(F6) f(F7) f(F8) f(F9) f(F10) f(F11) f(F12) \
f(GRAVE) f(1) f(2) f(3) f(4) f(5) f(6) f(7) f(8) f(9) f(0) f(MINUS) f(EQUALS) f(BACKSPACE) \
f(TAB) f(Q) f(W) f(E) f(R) f(T) f(Y) f(U) f(I) f(O) f(P) f(LEFTBRACKET) f(RIGHTBRACKET) f(BACKSLASH) \
f(CAPSLOCK) f(A) f(S) f(D) f(F) f(G) f(H) f(J) f(K) f(L) f(SEMICOLON) f(APOSTROPHE) f(RETURN) \
f(LSHIFT) f(Z) f(X) f(C) f(V) f(B) f(N) f(M) f(COMMA) f(PERIOD) f(SLASH) f(RSHIFT) \
f(LCTRL) f(APPLICATION) f(LALT) f(SPACE) f(RALT) f(RCTRL) \
f(UP) f(DOWN) f(LEFT) f(RIGHT) f(INSERT) f(DELETE) f(HOME) f(END) f(PAGEUP) f(PAGEDOWN)
// clang-format on

#define KEY_ESCAPE KEY_ESC
#define KEY_EQUALS KEY_EQUAL
#define KEY_LEFTBRACKET KEY_LEFTBRACE
#define KEY_RIGHTBRACKET KEY_RIGHTBRACE
#define KEY_RETURN KEY_ENTER
#define KEY_LSHIFT KEY_LEFTSHIFT
#define KEY_RSHIFT KEY_RIGHTSHIFT
#define KEY_PERIOD KEY_DOT
#define KEY_LCTRL KEY_LEFTCTRL
#define KEY_RCTRL KEY_RIGHTCTRL
#define KEY_APPLICATION KEY_APPSELECT
#define KEY_LALT KEY_LEFTALT
#define KEY_RALT KEY_RIGHTALT

void events_init();
void enqueue_event(unsigned int type, unsigned int code, int value);

#ifdef __cplusplus
}
#endif
