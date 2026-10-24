#pragma once
/* Paula's four audio channels and the CIA-B timer A, enough to play the Amiga game's sound: the custom
 * chip writes (amiga_mem's register hook) set the channels; DMA fetches the samples from amiga_mem; a
 * channel raises its audio interrupt at the start of every block; the timer calls its server at the rate
 * its latch gives. The output is mono at the host's rate, each byte held for its period and averaged
 * over each output sample, then a one-pole low-pass like the Amiga 500's fixed filter. */
#include "types.h"

#define PAULA_CLOCK 3579545.0                       /* NTSC; the player's effect periods assume it */
#define CIA_ECLOCK  715909.0

void paula_reset(int rate);
void paula_write(u32 addr, u16 value, int size);    /* amiga_set_reg_hook(paula_write) */
void paula_set_servers(void (*audio_int)(u16 intreqr), void (*timer)(void));
void paula_render(s16 *out, int n);
