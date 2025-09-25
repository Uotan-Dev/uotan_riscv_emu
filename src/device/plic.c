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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "core/cpu.h"
#include "device/plic.h"
#include "utils/misc.h"

#define PLIC_BITMAP_WORDS (((PLIC_MAX_SOURCES) + 31) / 32)

typedef struct {
    uint32_t priority[PLIC_MAX_SOURCES];
    uint32_t pending[PLIC_BITMAP_WORDS];
    uint32_t enable[PLIC_MAX_CONTEXTS][PLIC_BITMAP_WORDS];
    uint32_t threshold[PLIC_MAX_CONTEXTS];
    uint32_t claimed[PLIC_MAX_CONTEXTS];
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
            cpu_write_csr(CSR_MIP, cpu_read_csr(CSR_MIP) | MIP_MEIP);
        else
            cpu_write_csr(CSR_MIP, cpu_read_csr(CSR_MIP) & ~MIP_MEIP);
    } else if (ctx == PLIC_CONTEXT_S_MODE) {
        if (best)
            cpu_write_csr(CSR_SIP, cpu_read_csr(CSR_SIP) | SIP_SEIP);
        else
            cpu_write_csr(CSR_SIP, cpu_read_csr(CSR_SIP) & ~SIP_SEIP);
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

static inline bool is_full_word_access(uint32_t byte_offset, size_t n) {
    return (byte_offset == 0 && n == 4);
}

// For normal registers, return the corresponding fields
// For the claim register, execute only if n == 4
static uint64_t plic_read(uint64_t addr, size_t n) {
    const uint64_t mask = make_mask_bytes(n);
    uint64_t offset = addr - PLIC_BASE;

    uint64_t pri_base = (PLIC_PRIORITY_BASE - PLIC_BASE);
    uint64_t pri_end = pri_base + PLIC_PRIORITY_SIZE;
    uint64_t pend_base = (PLIC_PENDING_BASE - PLIC_BASE);
    uint64_t pend_end = pend_base + PLIC_PENDING_SIZE;
    uint64_t en_base = (PLIC_ENABLE_BASE - PLIC_BASE);
    uint64_t en_end = en_base + PLIC_ENABLE_SIZE;
    uint64_t ctx_base = (PLIC_CONTEXT_BASE - PLIC_BASE);
    uint64_t ctx_end = ctx_base + PLIC_CONTEXT_SIZE;

    if (offset >= pri_base && offset < pri_end) {
        // Priority registers
        uint64_t reg_offset = offset - pri_base;
        uint32_t source = reg_offset / 4;
        uint32_t byte_offset = reg_offset % 4;
        if (source < PLIC_MAX_SOURCES) {
            uint32_t reg_val = plic.priority[source] & 0x7U;
            return (reg_val >> (byte_offset * 8)) & mask;
        }
    } else if (offset >= pend_base && offset < pend_end) {
        // Pending registers
        uint64_t reg_offset = offset - pend_base;
        uint32_t word = reg_offset / 4;
        uint32_t byte_offset = reg_offset % 4;
        if (word < PLIC_BITMAP_WORDS) {
            uint32_t reg_val = plic.pending[word];
            return (reg_val >> (byte_offset * 8)) & mask;
        }
    } else if (offset >= en_base && offset < en_end) {
        // Enable registers
        uint64_t reg_offset = offset - en_base;
        uint32_t context = reg_offset / PLIC_ENABLE_CONTEXT_SIZE;
        uint32_t ctx_off = reg_offset % PLIC_ENABLE_CONTEXT_SIZE;
        uint32_t word = ctx_off / 4;
        uint32_t byte_offset = ctx_off % 4;
        if (context < PLIC_MAX_CONTEXTS && word < PLIC_BITMAP_WORDS) {
            uint32_t reg_val = plic.enable[context][word];
            return (reg_val >> (byte_offset * 8)) & mask;
        }
    } else if (offset >= ctx_base && offset < ctx_end) {
        // Context registers（threshold and claim/complete)
        uint64_t reg_offset = offset - ctx_base;
        uint32_t context = reg_offset / PLIC_CONTEXT_STRIDE;
        uint32_t context_offset = reg_offset % PLIC_CONTEXT_STRIDE;
        uint32_t byte_offset = context_offset % 4;
        if (context < PLIC_MAX_CONTEXTS) {
            if (context_offset == PLIC_THRESHOLD_OFFSET) {
                uint32_t reg_val = plic.threshold[context] & 0x7U;
                return (reg_val >> (byte_offset * 8)) & mask;
            } else if (context_offset == PLIC_CLAIM_OFFSET) {
                if (is_full_word_access(byte_offset, n)) {
                    uint32_t source = find_best_intr(context);
                    if (source != 0) {
                        set_pending(source, 0);
                        plic.claimed[context] = source;
                        update_all_outputs();
                    } else {
                        plic.claimed[context] = 0;
                    }
                    return (uint64_t)source & mask;
                } else {
                    uint32_t cur = plic.claimed[context];
                    return ((uint64_t)cur >> (byte_offset * 8)) & mask;
                }
            }
        }
    }

    return 0;
}

static void plic_write(uint64_t addr, uint64_t value, size_t n) {
    const uint64_t mask = make_mask_bytes(n);
    uint64_t offset = addr - PLIC_BASE;

    uint64_t pri_base = (PLIC_PRIORITY_BASE - PLIC_BASE);
    uint64_t pri_end = pri_base + PLIC_PRIORITY_SIZE;
    uint64_t en_base = (PLIC_ENABLE_BASE - PLIC_BASE);
    uint64_t en_end = en_base + PLIC_ENABLE_SIZE;
    uint64_t ctx_base = (PLIC_CONTEXT_BASE - PLIC_BASE);
    uint64_t ctx_end = ctx_base + PLIC_CONTEXT_SIZE;

    if (offset >= pri_base && offset < pri_end) {
        // Priority
        uint64_t reg_offset = offset - pri_base;
        uint32_t source = reg_offset / 4;
        uint32_t byte_offset = reg_offset % 4;
        if (source < PLIC_MAX_SOURCES) {
            uint32_t cur = plic.priority[source];
            uint32_t reg_val = cur;
            uint32_t clear_mask = ~((uint32_t)mask << (byte_offset * 8));
            reg_val &= clear_mask;
            reg_val |= (uint32_t)((value & mask) << (byte_offset * 8));
            plic.priority[source] = reg_val & 0x7U;
            update_all_outputs();
        }
    } else if (offset >= en_base && offset < en_end) {
        // Enable
        uint64_t reg_offset = offset - en_base;
        uint32_t context = reg_offset / PLIC_ENABLE_CONTEXT_SIZE;
        uint32_t ctx_off = reg_offset % PLIC_ENABLE_CONTEXT_SIZE;
        uint32_t word = ctx_off / 4;
        uint32_t byte_offset = ctx_off % 4;
        if (context < PLIC_MAX_CONTEXTS && word < PLIC_BITMAP_WORDS) {
            uint32_t cur = plic.enable[context][word];
            uint32_t reg_val = cur;
            uint32_t clear_mask = ~((uint32_t)mask << (byte_offset * 8));
            reg_val &= clear_mask;
            reg_val |= (uint32_t)((value & mask) << (byte_offset * 8));
            plic.enable[context][word] = reg_val;
            update_all_outputs();
        }
    } else if (offset >= ctx_base && offset < ctx_end) {
        // Context
        uint64_t reg_offset = offset - ctx_base;
        uint32_t context = reg_offset / PLIC_CONTEXT_STRIDE;
        uint32_t context_offset = reg_offset % PLIC_CONTEXT_STRIDE;
        uint32_t byte_offset = context_offset % 4;

        if (context < PLIC_MAX_CONTEXTS) {
            if (context_offset == PLIC_THRESHOLD_OFFSET) {
                uint32_t cur = plic.threshold[context];
                uint32_t reg_val = cur;
                uint32_t clear_mask = ~((uint32_t)mask << (byte_offset * 8));
                reg_val &= clear_mask;
                reg_val |= (uint32_t)((value & mask) << (byte_offset * 8));
                plic.threshold[context] = reg_val & 0x7U;
                update_all_outputs();
            } else if (context_offset == PLIC_CLAIM_OFFSET) {
                if (is_full_word_access(byte_offset, n)) {
                    uint32_t source = (uint32_t)(value & 0xFFFFFFFFU);
                    if (plic.claimed[context] == source && source != 0) {
                        plic.claimed[context] = 0;
                        update_all_outputs();
                    }
                }
            }
        }
    }
}

void plic_init(void) {
    memset(&plic, 0, sizeof(plic_t));
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
