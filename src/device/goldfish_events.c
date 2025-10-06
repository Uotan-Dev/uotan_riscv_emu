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

#include <stdlib.h>
#include <string.h>

#include <linux/input-event-codes.h>

#include "core/riscv.h"
#include "device/goldfish_events.h"
#include "device/plic.h"

#define MAX_EVENTS (256 * 4)

enum {
    REG_READ = 0x00,
    REG_SET_PAGE = 0x00,
    REG_LEN = 0x04,
    REG_DATA = 0x08,
    PAGE_NAME = 0x00000,
    PAGE_EVBITS = 0x10000,
    PAGE_ABSDATA = 0x20000 | EV_ABS,
};

/* These corresponds to the state of the driver.
 * Unfortunately, we have to buffer events coming
 * from the UI, since the kernel driver is not
 * capable of receiving them until XXXXXX
 */
enum {
    STATE_INIT = 0, /* The device is initialized */
    STATE_BUFFERED, /* Events have been buffered, but no IRQ raised yet */
    STATE_LIVE      /* Events can be sent directly to the kernel */
};

/* NOTE: The ev_bits arrays are used to indicate to the kernel
 *       which events can be sent by the emulated hardware.
 */
typedef struct {
    int page;
    unsigned events[MAX_EVENTS];
    unsigned first;
    unsigned last;
    unsigned state;
    const char *name;

    struct {
        size_t len;
        uint8_t *bits;     /* bitmask arrays for EV_* capabilities */
    } ev_bits[EV_MAX + 1]; /* plenty of space for EV types */

    pthread_mutex_t m;
} events_t;

static events_t events_state;

void enqueue_event(unsigned int type, unsigned int code, int value) {
    pthread_mutex_lock(&events_state.m);

    int enqueued = events_state.last - events_state.first;
    if (enqueued < 0)
        enqueued += MAX_EVENTS;
    if (enqueued + 3 > MAX_EVENTS) {
        // fprintf(stderr, "##KBD: Full queue, lose event\n");
        pthread_mutex_unlock(&events_state.m);
        return;
    }
    if (events_state.first == events_state.last) {
        if (events_state.state == STATE_LIVE)
            plic_set_irq(GOLDFISH_EVENTS_IRQ, 1);
        else
            events_state.state = STATE_BUFFERED;
    }
    // fprintf(stderr, "##KBD: type=%d code=%d value=%d\n", type, code, value);
    events_state.events[events_state.last] = type;
    events_state.last = (events_state.last + 1) & (MAX_EVENTS - 1);
    events_state.events[events_state.last] = code;
    events_state.last = (events_state.last + 1) & (MAX_EVENTS - 1);
    events_state.events[events_state.last] = value;
    events_state.last = (events_state.last + 1) & (MAX_EVENTS - 1);

    pthread_mutex_unlock(&events_state.m);
}

static unsigned dequeue_event() {
    if (events_state.first == events_state.last)
        return 0;
    unsigned n = events_state.events[events_state.first];
    events_state.first = (events_state.first + 1) & (MAX_EVENTS - 1);
    if (events_state.first == events_state.last)
        plic_set_irq(GOLDFISH_EVENTS_IRQ, 0);
    return n;
}

/* set bits [bitl..bith] in the ev_bits[type] array
 */
static void events_set_bits(int type, int bitl, int bith) {
    uint8_t *bits;
    uint8_t maskl, maskh;
    int il, ih;
    il = bitl / 8;
    ih = bith / 8;
    if (ih >= events_state.ev_bits[type].len) {
        bits = calloc(ih + 1, sizeof(uint8_t));
        if (bits == NULL)
            return;
        memcpy(bits, events_state.ev_bits[type].bits,
               events_state.ev_bits[type].len);
        free(events_state.ev_bits[type].bits);
        events_state.ev_bits[type].bits = bits;
        events_state.ev_bits[type].len = ih + 1;
    } else {
        bits = events_state.ev_bits[type].bits;
    }
    maskl = 0xffU << (bitl & 7);
    maskh = 0xffU >> (7 - (bith & 7));
    if (il >= ih)
        maskh &= maskl;
    else {
        bits[il] |= maskl;
        while (++il < ih)
            bits[il] = 0xff;
    }
    bits[ih] |= maskh;
}

// Keep for future use
static void events_set_bit(int type, int bit) __attribute__((unused));
static void events_clr_bit(int type, int bit) __attribute__((unused));

static void events_set_bit(int type, int bit) {
    events_set_bits(type, bit, bit);
}

static void events_clr_bit(int type, int bit) {
    int ii = bit / 8;
    if (ii < events_state.ev_bits[type].len) {
        uint8_t *bits = events_state.ev_bits[type].bits;
        uint8_t mask = 0x01U << (bit & 7);
        bits[ii] &= ~mask;
    }
}

static int get_page_len() {
    int page = events_state.page;
    if (page == PAGE_NAME) {
        const char *name = events_state.name;
        return strlen(name);
    }
    if (page >= PAGE_EVBITS && page <= PAGE_EVBITS + EV_MAX)
        return events_state.ev_bits[page - PAGE_EVBITS].len;
    return 0;
}

static int get_page_data(int offset) {
    int page_len = get_page_len();
    int page = events_state.page;
    if (offset > page_len)
        return 0;
    if (page == PAGE_NAME) {
        const char *name = events_state.name;
        return name[offset];
    }
    if (page >= PAGE_EVBITS && page <= PAGE_EVBITS + EV_MAX)
        return events_state.ev_bits[page - PAGE_EVBITS].bits[offset];
    return 0;
}

static uint64_t events_read(uint64_t addr, size_t n) {
    uint64_t offset = addr - GOLDFISH_EVENTS_START;
    uint64_t r = 0;

    pthread_mutex_lock(&events_state.m);

    /* This gross hack below is used to ensure that we
     * only raise the IRQ when the kernel driver is
     * properly ready! If done before this, the driver
     * becomes confused and ignores all input events
     * as soon as one was buffered!
     */
    if (offset == REG_LEN && events_state.page == PAGE_ABSDATA) {
        if (events_state.state == STATE_BUFFERED)
            plic_set_irq(GOLDFISH_EVENTS_IRQ, 1);
        events_state.state = STATE_LIVE;
    }
    if (offset == REG_READ)
        r = dequeue_event();
    else if (offset == REG_LEN)
        r = get_page_len();
    else if (offset >= REG_DATA)
        r = get_page_data(offset - REG_DATA);

    pthread_mutex_unlock(&events_state.m);

    return r;
}

static void events_write(uint64_t addr, uint64_t value, size_t n) {
    pthread_mutex_lock(&events_state.m);
    if (addr - GOLDFISH_EVENTS_START == REG_SET_PAGE)
        events_state.page = value;
    pthread_mutex_unlock(&events_state.m);
}

void events_init() {
    memset(&events_state, 0, sizeof(events_state));
    pthread_mutex_init(&events_state.m, NULL);

    events_state.name = "goldfish_events_keyboard";

    /* since we want to implement Unicode reverse-mapping
     * allow any kind of key, even those not available on
     * the skin.
     *
     * the previous code did set the [1..0x1ff] range, but
     * we don't want to enable certain bits in the middle
     * of the range that are registered for mouse/trackball/joystick
     * events.
     *
     * see "linux_keycodes.h" for the list of events codes.
     */
    events_set_bits(EV_KEY, 1, 0xff);
    events_set_bits(EV_KEY, 0x160, 0x1ff);

    rv_add_device((device_t){
        .name = "goldfish-events",
        .start = GOLDFISH_EVENTS_START,
        .end = GOLDFISH_EVENTS_START + GOLDFISH_EVENTS_SIZE - 1ULL,
        .read = events_read,
        .write = events_write,
    });
}
