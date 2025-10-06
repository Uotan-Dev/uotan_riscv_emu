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
#include <string.h>

#include "core/riscv.h"
#include "device/plic.h"
#include "device/uart16550.h"
#include "utils/fifo.h"
#include "utils/misc.h"

//
// UART16550
//
// Implementation inspired by QEMU's ns16550a emulation (hw/char/serial.c)
// QEMU is licensed under GPL v2 or later.
//
// https://github.com/qemu/qemu/blob/master/hw/char/serial.c
//

#define UART_LCR_DLAB 0x80 // Divisor latch access bit

#define UART_IER_MSI 0x08  // Enable Modem status interrupt
#define UART_IER_RLSI 0x04 // Enable receiver line status interrupt
#define UART_IER_THRI 0x02 // Enable Transmitter holding register int.
#define UART_IER_RDI 0x01  // Enable receiver data interrupt

#define UART_IIR_NO_INT 0x01 // No interrupts pending
#define UART_IIR_ID 0x06     // Mask for the interrupt ID

#define UART_IIR_MSI 0x00  // Modem status interrupt
#define UART_IIR_THRI 0x02 // Transmitter holding register empty
#define UART_IIR_RDI 0x04  // Receiver data interrupt
#define UART_IIR_RLSI 0x06 // Receiver line status interrupt
#define UART_IIR_CTI 0x0C  // Character Timeout Indication

#define UART_IIR_FENF 0x80 // Fifo enabled, but not functioning
#define UART_IIR_FE 0xC0   // Fifo enabled

#define UART_MCR_LOOP 0x10 // Enable loopback test mode
#define UART_MCR_OUT2 0x08 // Out2 complement
#define UART_MCR_OUT1 0x04 // Out1 complement
#define UART_MCR_RTS 0x02  // RTS complement
#define UART_MCR_DTR 0x01  // DTR complement

#define UART_MSR_DCD 0x80       // Data Carrier Detect
#define UART_MSR_RI 0x40        // Ring Indicator
#define UART_MSR_DSR 0x20       // Data Set Ready
#define UART_MSR_CTS 0x10       // Clear to Send
#define UART_MSR_DDCD 0x08      // Delta DCD
#define UART_MSR_TERI 0x04      // Trailing edge ring indicator
#define UART_MSR_DDSR 0x02      // Delta DSR
#define UART_MSR_DCTS 0x01      // Delta CTS
#define UART_MSR_ANY_DELTA 0x0F // Any of the delta bits!

#define UART_LSR_TEMT 0x40 // Transmitter empty
#define UART_LSR_THRE 0x20 // Transmit-hold-register empty
#define UART_LSR_BI 0x10   // Break interrupt indicator
#define UART_LSR_FE 0x08   // Frame error indicator
#define UART_LSR_PE 0x04   // Parity error indicator
#define UART_LSR_OE 0x02   // Overrun error indicator
#define UART_LSR_DR 0x01   // Receiver data ready
#define UART_LSR_INT_ANY 0x1E

#define UART_FCR_ITL_1 0x00 // 1 byte ITL
#define UART_FCR_ITL_2 0x40 // 4 bytes ITL
#define UART_FCR_ITL_3 0x80 // 8 bytes ITL
#define UART_FCR_ITL_4 0xC0 // 14 bytes ITL

#define UART_FCR_DMS 0x08 // DMA Mode Select
#define UART_FCR_XFR 0x04 // XMIT Fifo Reset
#define UART_FCR_RFR 0x02 // RCVR Fifo Reset
#define UART_FCR_FE 0x01  // FIFO Enable

#define MAX_XMIT_RETRY 4

typedef struct {
    fifo_t recv_fifo;
    fifo_t xmit_fifo;

    uint16_t divider;
    uint8_t rbr;
    uint8_t thr;
    uint8_t ier;
    uint8_t iir;
    uint8_t lcr;
    uint8_t mcr;
    uint8_t lsr;
    uint8_t msr;
    uint8_t scr;
    uint8_t fcr;

    int thr_ipending;

    pthread_mutex_t m;
} uart_t;

static uart_t uart;

static inline void uart_update_irq() {
    uint8_t tmp_iir = UART_IIR_NO_INT;

    if ((uart.ier & UART_IER_RLSI) && (uart.lsr & UART_LSR_INT_ANY))
        tmp_iir = UART_IIR_RLSI;
    else if ((uart.ier & UART_IER_RDI) && (uart.lsr & UART_LSR_DR))
        tmp_iir = UART_IIR_RDI;
    else if ((uart.ier & UART_IER_THRI) && uart.thr_ipending)
        tmp_iir = UART_IIR_THRI;
    else if ((uart.ier & UART_IER_MSI) && (uart.msr & UART_MSR_ANY_DELTA))
        tmp_iir = UART_IIR_MSI;

    uart.iir = tmp_iir;
    if (uart.fcr & UART_FCR_FE)
        uart.iir |= UART_IIR_FE;

    if (tmp_iir != UART_IIR_NO_INT)
        plic_set_irq(UART_IRQ, 1);
    else
        plic_set_irq(UART_IRQ, 0);
}

static inline void uart_receive_char(uint8_t ch) {
    if (uart.fcr & UART_FCR_FE) { // FIFO mode
        if (!fifo_is_full(&uart.recv_fifo)) {
            fifo_push(&uart.recv_fifo, ch);
            uart.lsr |= UART_LSR_DR;
        } else {
            uart.lsr |= UART_LSR_OE; // Overrun Error
        }
    } else { // Non-fifo mode
        if (uart.lsr & UART_LSR_DR) {
            uart.lsr |= UART_LSR_OE;
        }
        uart.rbr = ch;
        uart.lsr |= UART_LSR_DR;
    }
    uart_update_irq();
}

static uint64_t uart_read(uint64_t addr, size_t n) {
    uint32_t offset = addr & 0x7;
    uint32_t ret = 0;

    pthread_mutex_lock(&uart.m);

    switch (offset) {
        case 0:
            if (uart.lcr & UART_LCR_DLAB) {
                ret = uart.divider & 0xff;
            } else {
                if (uart.fcr & UART_FCR_FE) {
                    ret = fifo_is_empty(&uart.recv_fifo)
                              ? 0
                              : fifo_pop(&uart.recv_fifo);
                    if (fifo_is_empty(&uart.recv_fifo)) {
                        uart.lsr &= ~UART_LSR_DR;
                    }
                } else {
                    ret = uart.rbr;
                    uart.lsr &= ~UART_LSR_DR;
                }
                uart_update_irq();
            }
            break;
        case 1:
            if (uart.lcr & UART_LCR_DLAB) {
                ret = (uart.divider >> 8) & 0xff;
            } else {
                ret = uart.ier;
            }
            break;
        case 2:
            ret = uart.iir;
            if ((ret & UART_IIR_ID) == UART_IIR_THRI) {
                uart.thr_ipending = 0;
                uart_update_irq();
            }
            break;
        case 3: ret = uart.lcr; break;
        case 4: ret = uart.mcr; break;
        case 5:
            ret = uart.lsr;
            if (uart.lsr &
                (UART_LSR_BI | UART_LSR_OE | UART_LSR_PE | UART_LSR_FE)) {
                uart.lsr &=
                    ~(UART_LSR_BI | UART_LSR_OE | UART_LSR_PE | UART_LSR_FE);
                uart_update_irq();
            }
            break;
        case 6:
            ret = uart.msr;
            uart.msr &= 0xF0;
            uart_update_irq();
            break;
        case 7: ret = uart.scr; break;
    }

    pthread_mutex_unlock(&uart.m);

    return ret;
}

static void uart_write(uint64_t addr, uint64_t value, size_t n) {
    uint32_t offset = addr & 0x7;
    value &= 0xff;

    pthread_mutex_lock(&uart.m);

    switch (offset) {
        case 0:
            if (uart.lcr & UART_LCR_DLAB) {
                uart.divider = (uart.divider & 0xFF00) | value;
            } else {
                uart.thr_ipending = 0;
                uart.lsr &= ~(UART_LSR_THRE | UART_LSR_TEMT);
                if (uart.fcr & UART_FCR_FE) {
                    fifo_push(&uart.xmit_fifo, value);
                } else {
                    uart.lsr |= UART_LSR_THRE | UART_LSR_TEMT;
                    uart.thr_ipending = 1;
                    putchar((unsigned char)value);
                    fflush(stdout);
                }
                uart_update_irq();
            }
            break;
        case 1:
            if (uart.lcr & UART_LCR_DLAB) {
                uart.divider = (uart.divider & 0x00FF) | (value << 8);
            } else {
                uint8_t old_ier = uart.ier;
                uart.ier = value & 0x0f;
                if (uart.ier != old_ier) {
                    if ((uart.ier & UART_IER_THRI) &&
                        (uart.lsr & UART_LSR_THRE)) {
                        uart.thr_ipending = 1;
                    }
                    uart_update_irq();
                }
            }
            break;
        case 2:
            uart.fcr = value & 0xC9;
            if (value & UART_FCR_RFR)
                fifo_init(&uart.recv_fifo);
            if (value & UART_FCR_XFR)
                fifo_init(&uart.xmit_fifo);
            break;
        case 3: uart.lcr = value; break;
        case 4: uart.mcr = value & 0x1f; break;
        case 5: /* LSR is read-only */ break;
        case 6: /* MSR is read-only */ break;
        case 7: uart.scr = value; break;
    }

    pthread_mutex_unlock(&uart.m);
}

void uart_tick() {
    // Input from host
    char c;
    int ret = read(STDIN_FILENO, &c, 1);

    pthread_mutex_lock(&uart.m);

    if (ret > 0)
        uart_receive_char((uint8_t)c);

    // Output to host
    if (!(uart.lsr & UART_LSR_THRE)) {
        if (uart.mcr & UART_MCR_LOOP) {
            if (!fifo_is_empty(&uart.xmit_fifo)) {
                uint8_t ch = fifo_pop(&uart.xmit_fifo);
                uart_receive_char(ch);
            }
        } else {
            while (!fifo_is_empty(&uart.xmit_fifo))
                putchar(fifo_pop(&uart.xmit_fifo));
            fflush(stdout);
        }
        uart.lsr |= UART_LSR_THRE | UART_LSR_TEMT;
        uart.thr_ipending = 1;
        uart_update_irq();
    }

    pthread_mutex_unlock(&uart.m);
}

void uart_init() {
    memset(&uart, 0, sizeof(uart_t));

    fifo_init(&uart.recv_fifo);
    fifo_init(&uart.xmit_fifo);

    uart.lsr = UART_LSR_TEMT | UART_LSR_THRE;
    uart.iir = UART_IIR_NO_INT;
    uart.mcr = UART_MCR_OUT2;
    uart.msr = UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS;
    uart.divider = 12;

    set_stdin_nonblocking();

    static bool blocking_handler_registered = false;
    if (!blocking_handler_registered) {
        blocking_handler_registered = true;
        atexit(set_stdin_blocking);
    }

    rv_add_device((device_t){
        .name = "UART16550",
        .start = UART_BASE,
        .end = UART_BASE + UART_SIZE - 1ULL,
        .read = uart_read,
        .write = uart_write,
    });
}
