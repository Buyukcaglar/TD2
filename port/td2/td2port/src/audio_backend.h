#pragma once
/* Audio backends: what the player hears (host side, no SDL).
 *
 * The game's own sound code is game logic and runs the same with every backend: the effect and music
 * stream players (platform/sound.c) and the drive tones (game/sim.c) keep their state in DGROUP, and the
 * game reads some of it back (snd_busy, sfx_is_playing). A backend only turns what that code outputs
 * into samples. The PC speaker backend (speaker.c) takes the speaker writes: PIT channel 2 and the two
 * low bits of port 61h. A sample-based backend (Amiga) will also need to know which effect or song
 * started; those events are added together with it.
 *
 * The host holds one active backend (host_set_audio_backend, before host_init). */
#include "types.h"

typedef struct AudioBackend {
    const char *name;
    void (*reset)(int rate);                        /* silence, output at rate samples per second */
    void (*speaker)(u16 divisor, u8 port61_bits);   /* divisor 0 means 65536 */
    void (*render)(s16 *out, int n);                /* the next n samples */
} AudioBackend;

extern const AudioBackend audio_pc_speaker;         /* speaker.c */
