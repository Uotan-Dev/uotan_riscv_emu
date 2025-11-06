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

#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

#include "core/entropy.h"

uint16_t generate_entropy() {
    uint16_t entropy;
    ssize_t ret = getrandom(&entropy, sizeof(entropy), GRND_NONBLOCK);

    if (ret == sizeof(entropy)) {
        return entropy;
    }

    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t r = fread(&entropy, sizeof(entropy), 1, f);
        if (r == 1) {
            fclose(f);
            return entropy;
        }
    }

    return (uint16_t)random();
}
