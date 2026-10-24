#pragma once
/* The Amiga game's own sample driver for the race sounds (in duel, not sfx/song), translated from its
 * 68000 code. Samples are in amiga_mem; the driver writes the custom chip registers through awr16/awr32.
 *   - race_sound_vblank is its vertical blank server ($1231c, without the siren sweep it calls first);
 *   - race_sound_audio_int is its level 4 audio interrupt ($1226e), with INTREQR and INTENAR as it
 *     reads them. See docs/amiga.md, "The race sounds". */
#include "types.h"

void race_sound_init(void);                                         /* $11f96, without the OS calls */
void race_sound_play(u32 sample, u32 bytes, u16 channel, u16 period, u16 volume, u16 repeats);   /* $120cc */
void race_sound_play_raw(u32 file, u16 channel, u16 volume);       /* $12072: a raw sample file */
void race_sound_stop(u16 channel);                                  /* $1218a */
bool race_sound_busy(u16 channel);                                  /* $121ea */
void race_sound_set(u16 channel, s16 period, s16 volume);           /* $12202: negative leaves it */
void race_sound_ramp(u16 channel, u16 target, u32 step);            /* $12250: volume towards target, 16.16 per frame */
void race_sound_vblank(u16 intenar);
void race_sound_audio_int(u16 intreqr, u16 intenar);
