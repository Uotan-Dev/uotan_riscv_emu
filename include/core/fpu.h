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

#include <stdint.h>

#include "softfloat.h"  // IWYU pragma: keep
#include "specialize.h" // IWYU pragma: keep

#include "common.h"

#define F32_DEFAULT_NAN 0x7FC00000
#define F64_DEFAULT_NAN 0x7FF8000000000000

#define F32_SIGN (1U << 31)
#define F64_SIGN (1ULL << 63)

// Floating-point rounding modes (frm)
#define FRM_RNE 0 // Round to nearest, ties to even
#define FRM_RTZ 1 // Round towards zero
#define FRM_RDN 2 // Round down (towards -∞)
#define FRM_RUP 3 // Round up (towards +∞)
#define FRM_RMM 4 // Round to nearest, ties to max magnitude
#define FRM_DYN 7 // Dynamic rounding mode (use frm field of fcsr)

#define FCSR_MASK 0xFF

typedef struct {
    union {
        uint32_t value;

        struct {
            unsigned fflags : 5;    // Floating-point exception flags [4:0]
            unsigned frm : 3;       // Floating-point rounding mode [7:5]
            unsigned reserved : 24; // Reserved bits [31:8]
        } fields;

        struct {
            unsigned NX : 1; // invalid operation
            unsigned UF : 1; // divide by zero
            unsigned OF : 1; // overflow
            unsigned DZ : 1; // underflow
            unsigned NV : 1; // inexact
        } fflags;
    };
} fcsr_t;

typedef float64_t fpr_t;

FORCE_INLINE bool is_boxed_f32(float64_t x) {
    return (x.v >> 32) == (uint32_t)-1;
}

FORCE_INLINE float32_t unbox_f32(float64_t x) {
    return (float32_t){(uint32_t)x.v};
}

FORCE_INLINE float64_t box_f32(float32_t x) {
    return (float64_t){(uint64_t)x.v | 0xFFFFFFFF00000000};
}

FORCE_INLINE bool f32_isNegative(float32_t x) { return x.v & F32_SIGN; }

FORCE_INLINE bool f64_isNegative(float64_t x) { return x.v & F64_SIGN; }

FORCE_INLINE float32_t f32_neg(float32_t x) {
    return (float32_t){x.v ^ F32_SIGN};
}

FORCE_INLINE float64_t f64_neg(float64_t x) {
    return (float64_t){x.v ^ F64_SIGN};
}

FORCE_INLINE bool f32_isNaN(float32_t x) {
    return ((~x.v & 0x7F800000) == 0) && (x.v & 0x007FFFFF);
}

FORCE_INLINE bool f64_isNaN(float64_t x) {
    return ((~x.v & 0x7FF0000000000000) == 0) && (x.v & 0x000FFFFFFFFFFFFF);
}

FORCE_INLINE float32_t fpr_get_f32(fpr_t reg) {
    if (is_boxed_f32(reg))
        return unbox_f32(reg);
    return (float32_t){F32_DEFAULT_NAN};
}

FORCE_INLINE void fpr_write32(fpr_t *fpr, float32_t x) { *fpr = box_f32(x); }

FORCE_INLINE void fpr_write64(fpr_t *fpr, float64_t x) { *fpr = x; }
