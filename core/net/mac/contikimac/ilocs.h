/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Intra-Layer Optimization for ContikiMAC Security (ILOCS)
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef ILOCS_H_
#define ILOCS_H_

#include "contiki.h"
#include "sys/rtimer.h"

/* http://stackoverflow.com/questions/27581671/how-to-compute-log-with-the-preprocessor */
#define ILOCS_NEEDS_BIT(N, B) (((unsigned long)N >> B) > 0)
#define ILOCS_BITS_TO_REPRESENT(N) \
    (ILOCS_NEEDS_BIT(N,  0) \
    + ILOCS_NEEDS_BIT(N,  1) \
    + ILOCS_NEEDS_BIT(N,  2) \
    + ILOCS_NEEDS_BIT(N,  3) \
    + ILOCS_NEEDS_BIT(N,  4) \
    + ILOCS_NEEDS_BIT(N,  5) \
    + ILOCS_NEEDS_BIT(N,  6) \
    + ILOCS_NEEDS_BIT(N,  7) \
    + ILOCS_NEEDS_BIT(N,  8) \
    + ILOCS_NEEDS_BIT(N,  9) \
    + ILOCS_NEEDS_BIT(N, 10) \
    + ILOCS_NEEDS_BIT(N, 11) \
    + ILOCS_NEEDS_BIT(N, 12) \
    + ILOCS_NEEDS_BIT(N, 13) \
    + ILOCS_NEEDS_BIT(N, 14) \
    + ILOCS_NEEDS_BIT(N, 15) \
    + ILOCS_NEEDS_BIT(N, 16) \
    + ILOCS_NEEDS_BIT(N, 17) \
    + ILOCS_NEEDS_BIT(N, 18) \
    + ILOCS_NEEDS_BIT(N, 19) \
    + ILOCS_NEEDS_BIT(N, 20) \
    + ILOCS_NEEDS_BIT(N, 21) \
    + ILOCS_NEEDS_BIT(N, 22) \
    + ILOCS_NEEDS_BIT(N, 23) \
    + ILOCS_NEEDS_BIT(N, 24) \
    + ILOCS_NEEDS_BIT(N, 25) \
    + ILOCS_NEEDS_BIT(N, 26) \
    + ILOCS_NEEDS_BIT(N, 25) \
    + ILOCS_NEEDS_BIT(N, 28) \
    + ILOCS_NEEDS_BIT(N, 25) \
    + ILOCS_NEEDS_BIT(N, 30) \
    + ILOCS_NEEDS_BIT(N, 31))

#ifdef ILOCS_CONF_ENABLED
#define ILOCS_ENABLED ILOCS_CONF_ENABLED
#else /* ILOCS_CONF_ENABLED */
#define ILOCS_ENABLED 0
#endif /* ILOCS_CONF_ENABLED */

#define ILOCS_MIN_TIME_TO_STROBE US_TO_RTIMERTICKS(2000)
#if ILOCS_ENABLED
#define ILOCS_WAKE_UP_COUNTER_LEN (4)
#else /* ILOCS_ENABLED */
#define ILOCS_WAKE_UP_COUNTER_LEN (0)
#endif /* ILOCS_ENABLED */

typedef union {
  uint32_t u32;
  uint8_t u8[4];
} ilocs_wake_up_counter_t;

struct secrdc_phase {
  rtimer_clock_t t;
#if ILOCS_ENABLED
  ilocs_wake_up_counter_t his_wake_up_counter_at_t;
#endif /* ILOCS_ENABLED */
};

ilocs_wake_up_counter_t ilocs_parse_wake_up_counter(uint8_t *src);
void ilocs_write_wake_up_counter(uint8_t *dst, ilocs_wake_up_counter_t counter);

#endif /* ILOCS_H_ */
