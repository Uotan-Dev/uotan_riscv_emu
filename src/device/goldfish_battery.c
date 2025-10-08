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

#include <SDL2/SDL_timer.h>
#include <string.h>

#include "local-include/power_supply.h"

#include "core/riscv.h"
#include "device/goldfish_battery.h"
#include "device/plic.h"

enum {
    /* status register */
    BATTERY_INT_STATUS = 0x00,
    /* set this to enable IRQ */
    BATTERY_INT_ENABLE = 0x04,
    BATTERY_AC_ONLINE = 0x08,
    BATTERY_STATUS = 0x0C,
    BATTERY_HEALTH = 0x10,
    BATTERY_PRESENT = 0x14,
    BATTERY_CAPACITY = 0x18,
    BATTERY_STATUS_CHANGED = 1U << 0,
    AC_STATUS_CHANGED = 1U << 1,
    BATTERY_INT_MASK = BATTERY_STATUS_CHANGED | AC_STATUS_CHANGED,
};

typedef struct goldfish_battery_state {
    // IRQs
    uint32_t int_status;
    // irq enable mask for int_status
    uint32_t int_enable;
    int ac_online;
    int status;
    int health;
    int present;
    int capacity;

    pthread_mutex_t m;
} battery_t;

static battery_t battery;

static uint64_t battery_read(uint64_t addr, size_t n) {
    uint64_t offset = addr - BATT_BASE;
    uint64_t ret = 0;

    pthread_mutex_lock(&battery.m);

    switch (offset) {
        case BATTERY_INT_STATUS:
            // return current buffer status flags
            ret = battery.int_status & battery.int_enable;
            if (ret) {
                plic_set_irq(BATT_IRQ, 0);
                battery.int_status = 0;
            }
            break;
        case BATTERY_INT_ENABLE: ret = battery.int_enable; break;
        case BATTERY_AC_ONLINE: ret = battery.ac_online; break;
        case BATTERY_STATUS: ret = battery.status; break;
        case BATTERY_HEALTH: ret = battery.health; break;
        case BATTERY_PRESENT: ret = battery.present; break;
        case BATTERY_CAPACITY: ret = battery.capacity; break;
        default: ret = 0; break;
    }

    pthread_mutex_unlock(&battery.m);

    return ret;
}

static void battery_write(uint64_t addr, uint64_t value, size_t n) {
    uint64_t offset = addr - BATT_BASE;

    switch (offset) {
        case BATTERY_INT_ENABLE:
            pthread_mutex_lock(&battery.m);
            /* enable interrupts */
            battery.int_enable = value;
            pthread_mutex_unlock(&battery.m);
            break;
    }
}

void battery_init() {
    memset(&battery, 0, sizeof(battery));

    pthread_mutex_init(&battery.m, NULL);

    // default values for the battery
    battery.ac_online = 1;
    battery.status = POWER_SUPPLY_STATUS_CHARGING;
    battery.health = POWER_SUPPLY_HEALTH_GOOD;
    battery.present = 1;              // battery is present
    battery.capacity = BATT_INIT_CAP; // 32% charged

    rv_add_device((device_t){
        .name = "goldfish-battery",
        .start = BATT_BASE,
        .end = BATT_BASE + BATT_SIZE - 1ULL,
        .read = battery_read,
        .write = battery_write,
    });
}

static void battery_set_prop(int ac, int property, int value) {
    int new_status = (ac ? AC_STATUS_CHANGED : BATTERY_STATUS_CHANGED);
    if (ac) {
        switch (property) {
            case POWER_SUPPLY_PROP_ONLINE: battery.ac_online = value; break;
        }
    } else {
        switch (property) {
            case POWER_SUPPLY_PROP_STATUS: battery.status = value; break;
            case POWER_SUPPLY_PROP_HEALTH: battery.health = value; break;
            case POWER_SUPPLY_PROP_PRESENT: battery.present = value; break;
            case POWER_SUPPLY_PROP_CAPACITY: battery.capacity = value; break;
        }
    }
    if (new_status != battery.int_status) {
        battery.int_status |= new_status;
        plic_set_irq(BATT_IRQ, battery.int_status & battery.int_enable);
    }
}

void battery_update() {
    static bool batt_full = false;
    if (!batt_full) {
        uint32_t v = SDL_GetTicks() / 1000.0 / 60.0 + BATT_INIT_CAP;
        if (v >= 98) {
            v = 100;
            batt_full = true;
        }
        pthread_mutex_lock(&battery.m);
        battery_set_prop(0, POWER_SUPPLY_PROP_CAPACITY, v);
        pthread_mutex_unlock(&battery.m);
    }
}
