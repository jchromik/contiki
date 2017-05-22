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
#include "dev/sys-ctrl.h"
#include "cc2538_cm3.h"
#include <stdio.h>

PROCESS(duration_process, "duration_process");
AUTOSTART_PROCESSES(&duration_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(duration_process, ev, data)
{
  uint8_t some_key[AES_128_KEY_LENGTH];
  uint8_t some_block[AES_128_BLOCK_SIZE];
  uint32_t instants[2];

  PROCESS_BEGIN();

  instants[0] = SysTick->VAL;
  AES_128.set_key(some_key);
  AES_128.encrypt(some_block);
  instants[1] = SysTick->VAL;

  if(instants[1] < instants[0]) {
    printf("%lu;%lu\n",
        instants[0] - instants[1],
        REG(SYS_CTRL_CLOCK_STA) & SYS_CTRL_CLOCK_STA_SYS_DIV);
    /* 16 000 000 ticks / s if div == 1 */
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
