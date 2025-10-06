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

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>

#include "core/cpu.h"
#include "device/plic.h"

#define PLIC_BITMAP_WORDS (((PLIC_MAX_SOURCES) + 31) / 32)

typedef struct {
    std::atomic_uint_fast32_t priority[PLIC_MAX_SOURCES];
    std::atomic_uint_fast32_t pending[PLIC_BITMAP_WORDS];
    std::atomic_uint_fast32_t enable[PLIC_MAX_CONTEXTS][PLIC_BITMAP_WORDS];
    std::atomic_uint_fast32_t threshold[PLIC_MAX_CONTEXTS];
    std::atomic_uint_fast32_t claimed[PLIC_MAX_CONTEXTS];
} plic_t;

static plic_t plic;

// Check if a source is pending
static inline bool is_pending(uint32_t src) {
    // 0 is reserved as "no interrupt"
    if (src == 0 || src >= PLIC_MAX_SOURCES)
        return false;
    uint32_t word = src / 32;
    uint32_t bit = src % 32;
    return (bool)((plic.pending[word] >> bit) & 1U);
}

// Set / clear pending bit
static inline void set_pending(uint32_t src, int pending_val) {
    if (src == 0 || src >= PLIC_MAX_SOURCES)
        return;
    uint32_t word = src / 32;
    uint32_t bit = src % 32;
    if (pending_val)
        plic.pending[word] |= (1U << bit);
    else
        plic.pending[word] &= ~(1U << bit);
}

// Check if a source is enabled on a context
static inline bool is_enabled(uint32_t src, int ctx) {
    if (src == 0 || src >= PLIC_MAX_SOURCES)
        return false;
    if (ctx < 0 || ctx >= PLIC_MAX_CONTEXTS)
        return false;
    uint32_t word = src / 32;
    uint32_t bit = src % 32;
    return (bool)((plic.enable[ctx][word] >> bit) & 1U);
}

// Find the best intr for a context
static uint32_t find_best_intr(int ctx) {
    uint32_t best_src = 0;
    uint32_t best_priority = 0;

    for (uint32_t s = 1; s < PLIC_MAX_SOURCES; s++) {
        if (!is_pending(s) || !is_enabled(s, ctx))
            continue;
        uint32_t p = plic.priority[s] & 0x7U;
        if (p <= (plic.threshold[ctx] & 0x7U))
            continue;
        if (p > best_priority ||
            (p == best_priority && (best_src == 0 || s < best_src))) {
            best_priority = p;
            best_src = s;
        }
    }
    return best_src;
}

// Set CSRs according to find_best_intr()
static void update_intr_output(int ctx) {
    uint32_t best = find_best_intr(ctx);

    if (ctx == PLIC_CONTEXT_M_MODE) {
        if (best)
            cpu_raise_intr(MIP_MEIP, PRIV_M);
        else
            cpu_clear_intr(MIP_MEIP, PRIV_M);
    } else if (ctx == PLIC_CONTEXT_S_MODE) {
        if (best)
            cpu_raise_intr(SIP_SEIP, PRIV_S);
        else
            cpu_clear_intr(SIP_SEIP, PRIV_S);
    } else {
        // Unknown ctx
        __UNREACHABLE;
    }
}

// Update IRQ output for all contexts
static void update_all_outputs(void) {
    for (int i = 0; i < PLIC_MAX_CONTEXTS; i++)
        update_intr_output(i);
}

static uint64_t plic_read(uint64_t addr, size_t n) {
    if (n != 4 || addr % 4 != 0)
        return 0;
    if (addr >= PLIC_PRIORITY_BASE &&
        addr < PLIC_PRIORITY_BASE + PLIC_PRIORITY_SIZE) {
        uint64_t reg_offset = addr - PLIC_PRIORITY_BASE;
        uint32_t source = (uint32_t)(reg_offset / 4);
        if (source < PLIC_MAX_SOURCES) {
            return (uint64_t)(plic.priority[source] & 0x7U);
        }
    } else if (addr >= PLIC_PENDING_BASE &&
               addr < PLIC_PENDING_BASE + PLIC_PENDING_SIZE) {
        uint64_t reg_offset = addr - PLIC_PENDING_BASE;
        uint32_t word = (uint32_t)(reg_offset / 4);
        if (word < PLIC_BITMAP_WORDS) {
            return (uint64_t)plic.pending[word];
        }
    } else if (addr >= PLIC_ENABLE_BASE &&
               addr < PLIC_ENABLE_BASE + PLIC_ENABLE_SIZE) {
        uint64_t reg_offset = addr - PLIC_ENABLE_BASE;
        uint32_t context = (uint32_t)(reg_offset / PLIC_ENABLE_CONTEXT_SIZE);
        uint32_t ctx_off = (uint32_t)(reg_offset % PLIC_ENABLE_CONTEXT_SIZE);
        uint32_t word = ctx_off / 4;
        if (context < PLIC_MAX_CONTEXTS && word < PLIC_BITMAP_WORDS) {
            return (uint64_t)plic.enable[context][word];
        }
    } else if (addr >= PLIC_CONTEXT_BASE &&
               addr < PLIC_CONTEXT_BASE + PLIC_CONTEXT_SIZE) {
        uint64_t reg_offset = addr - PLIC_CONTEXT_BASE;
        uint32_t context = (uint32_t)(reg_offset / PLIC_CONTEXT_STRIDE);
        uint32_t context_offset = (uint32_t)(reg_offset % PLIC_CONTEXT_STRIDE);
        if (context < PLIC_MAX_CONTEXTS) {
            if (context_offset == PLIC_THRESHOLD_OFFSET) {
                return (uint64_t)(plic.threshold[context] & 0x7U);
            } else if (context_offset == PLIC_CLAIM_OFFSET) {
                uint32_t source = find_best_intr(context);
                if (source != 0) {
                    set_pending(source, 0);
                    plic.claimed[context] = source;
                    update_all_outputs();
                } else {
                    plic.claimed[context] = 0;
                }
                return (uint64_t)source;
            }
        }
    }

    return 0;
}

static void plic_write(uint64_t addr, uint64_t value, size_t n) {
    if (n != 4 || addr % 4 != 0)
        return;
    if (addr >= PLIC_PRIORITY_BASE &&
        addr < PLIC_PRIORITY_BASE + PLIC_PRIORITY_SIZE) {
        uint64_t reg_offset = addr - PLIC_PRIORITY_BASE;
        uint32_t source = (uint32_t)(reg_offset / 4);
        if (source < PLIC_MAX_SOURCES) {
            plic.priority[source] = (uint32_t)(value & 0x7U);
            update_all_outputs();
        }
    } else if (addr >= PLIC_ENABLE_BASE &&
               addr < PLIC_ENABLE_BASE + PLIC_ENABLE_SIZE) {
        uint64_t reg_offset = addr - PLIC_ENABLE_BASE;
        uint32_t context = (uint32_t)(reg_offset / PLIC_ENABLE_CONTEXT_SIZE);
        uint32_t ctx_off = (uint32_t)(reg_offset % PLIC_ENABLE_CONTEXT_SIZE);
        uint32_t word = ctx_off / 4;
        if (context < PLIC_MAX_CONTEXTS && word < PLIC_BITMAP_WORDS) {
            plic.enable[context][word] = (uint32_t)value;
            update_all_outputs();
        }
    } else if (addr >= PLIC_CONTEXT_BASE &&
               addr < PLIC_CONTEXT_BASE + PLIC_CONTEXT_SIZE) {
        uint64_t reg_offset = addr - PLIC_CONTEXT_BASE;
        uint32_t context = (uint32_t)(reg_offset / PLIC_CONTEXT_STRIDE);
        uint32_t context_offset = (uint32_t)(reg_offset % PLIC_CONTEXT_STRIDE);
        if (context < PLIC_MAX_CONTEXTS) {
            if (context_offset == PLIC_THRESHOLD_OFFSET) {
                plic.threshold[context] = (uint32_t)(value & 0x7U);
                update_all_outputs();
            } else if (context_offset == PLIC_CLAIM_OFFSET) {
                uint32_t source = (uint32_t)(value & 0xFFFFFFFFU);
                if (plic.claimed[context] == source && source != 0) {
                    plic.claimed[context] = 0;
                    update_all_outputs();
                }
            }
        }
    }
}

void plic_init(void) {
    std::fill(plic.priority, plic.priority + PLIC_MAX_SOURCES, 0);
    std::fill(plic.pending, plic.pending + PLIC_BITMAP_WORDS, 0);
    for (size_t i = 0; i < PLIC_MAX_CONTEXTS; i++)
        std::fill(plic.enable[i], plic.enable[i] + PLIC_BITMAP_WORDS, 0);
    std::fill(plic.threshold, plic.threshold + PLIC_MAX_CONTEXTS, 0);
    std::fill(plic.claimed, plic.claimed + PLIC_MAX_CONTEXTS, 0);

    rv_add_device((device_t){
        .name = "PLIC",
        .start = PLIC_BASE,
        .end = PLIC_BASE + PLIC_SIZE - 1ULL,
        .read = plic_read,
        .write = plic_write,
    });
}

// level 1 for setting IRQ
void plic_set_irq(uint32_t src, int level) {
    if (src == 0 || src >= PLIC_MAX_SOURCES)
        return;
    bool pending = is_pending(src);
    if (level && !pending) {
        set_pending(src, 1);
        update_all_outputs();
    } else if (!level && pending) {
        set_pending(src, 0);
        update_all_outputs();
    }
}
