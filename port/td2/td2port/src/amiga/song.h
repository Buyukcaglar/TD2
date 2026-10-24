#pragma once
/* The Amiga game's music and effect player, translated from its 68000 code in sfx/song (Accolade's
 * player: its symbols are in the file). It runs on the song file laid out in amiga_mem and drives the
 * custom chip registers through awr16/awr32, as the original does:
 *   - song_tick is SongInt, the CIA-B timer server (the song sets the timer with its DD/DE commands);
 *   - song_audio_int is SongIntHandler, the level 4 audio interrupt (INTREQR as it reads it);
 *   - the rest are the commands of its entry point (segentry, D0 = 0..12).
 * See docs/amiga.md, "Sound". */
#include "types.h"
#include "amiga/amiga_mem.h"

bool song_load(const u8 *file, u32 len, char *err, size_t errlen);   /* sfx/song at 10000h */

void song_open(void);                               /* 0 _OpenTimerInt (the variables; no OS calls) */
void song_read_instruments(void);                   /* 1 _ReadInstruments */
void song_play(void);                               /* 2 _PlaySong: the title song */
void song_stop(void);                               /* 3 _StopSong */
u16  song_status(void);                             /* 5 _GetSongStat: PlayState */
void song_fade(u16 speed);                          /* 6 _FadeSong */
void song_play_sfx(u32 form, u16 channel, u16 volume, u16 count, u16 music_volume);  /* 7 _PlaySfx */
void song_stop_sfx(u16 channel);                    /* 8 _StopSfx */
bool song_sfx_status(u16 channel);                  /* 9 _SfxStat */
void song_pause(void);                              /* 10 _PauseMusic */
void song_restart(void);                            /* 11 _RestartMusic */
void song_adjust_sfx(u16 channel, u16 rate, u16 volume);   /* 12 _AdjustSfx */

void song_tick(void);                               /* SongInt */
void song_audio_int(u16 intreqr);                   /* SongIntHandler */

extern AmigaSeg song_seg;
