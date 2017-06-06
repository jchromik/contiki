/*
 * Copyright (c) 2017, Hasso-Plattner-Institut.
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

#include "contiki.h"
#include "lib/aes-128.h"
#include "dev/gpio.h"
#include "sys/rtimer.h"
#include "net/netstack.h"
#include <stdio.h>

static void on_timeout(struct rtimer *rt, void *ptr);
static char measure(void);

PROCESS(energy_process, "energy_process");
AUTOSTART_PROCESSES(&energy_process);
static struct rtimer t;
static struct pt pt;

/*---------------------------------------------------------------------------*/
static void
schedule_timeout(rtimer_clock_t time)
{
  if(rtimer_set(&t, time, 1, on_timeout, NULL) != RTIMER_OK) {
    printf("rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
on_timeout(struct rtimer *rt, void *ptr)
{
  measure();
}
/*---------------------------------------------------------------------------*/
static char
measure(void)
{
  PT_BEGIN(&pt);

  {
    rtimer_clock_t now;

    /* set the AD3/DIO3 pin */
    now = RTIMER_NOW();
    GPIO_SET_PIN(GPIO_D_BASE, 1);
    while(!rtimer_has_timed_out(now + 10));
    GPIO_CLR_PIN(GPIO_D_BASE, 1);
    /* sleep for 1ms */
    schedule_timeout(now + US_TO_RTIMERTICKS(1000));
    PT_YIELD(&pt);
  }

  /* do something energy consuming to see a peak */
  NETSTACK_RADIO_ASYNC.on();
  NETSTACK_RADIO_ASYNC.get_rssi();
  NETSTACK_RADIO_ASYNC.off();

  /* schedule next measurement */
  schedule_timeout(RTIMER_NOW() + RTIMER_ARCH_SECOND);

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(energy_process, ev, data)
{
  PROCESS_BEGIN();

  /* we use the AD3/DIO3 pin as an external trigger */
  GPIO_SET_OUTPUT(GPIO_D_BASE, 1);

  /* schedule first measurement */
  schedule_timeout(RTIMER_NOW() + RTIMER_ARCH_SECOND);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
