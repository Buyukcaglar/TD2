#pragma once
/* Audio backends: what the player hears (host side, no SDL).
 *
 * The game's own sound code is game logic and runs the same with every backend: the effect and music
 * stream players (platform/sound.c) and the drive tones (game/sim.c) keep their state in DGROUP, and the
 * game reads some of it back (snd_busy, sfx_is_playing). A backend only turns what that code outputs
 * into samples. The PC speaker backend (speaker.c) takes the speaker writes: PIT channel 2 and the two
 * low bits of port 61h. A sample-based backend (Amiga, amiga/audio_amiga.c) takes the game's sound
 * events and, during a race, the car's state instead.
 *
 * The host holds one active backend (host_set_audio_backend) and passes the events on (host_sound_event,
 * host_sound_drive); it can switch backends at any time. */
#include "types.h"

typedef enum {
    SOUND_SONG,             /* n: the song the game starts (1 title and menus, 2 and 3 the police ending) */
    SOUND_RACE_START,       /* a life starts on a stage; car: the player's car code ("F40", "P959", ...) */
    SOUND_RACE_END,         /* the car stops: the stage or the life is over */
    SOUND_BUMP,             /* the car hit the road's edge or another car */
    SOUND_CRASH,            /* a crash or a blown engine */
} SoundEvent;

typedef struct DriveSound { /* the car's state, ten times a second while the race runs */
    bool sound_on;          /* the game's sound effects are on */
    bool running;           /* the race goes on (no crash, finish or stop yet) */
    u16 rpm;                /* as the rev counter shows it */
    u16 speed;              /* mph * 256 */
    s8 throttle;            /* below 0 braking, 0 off, above 0 on */
    u8 gear;                /* 0 neutral */
    bool in_gear;           /* a working gear is engaged */
    u16 skid;               /* 0, or how far the steering is past the grip limit */
    bool siren, radar;      /* the police siren sounds; the radar detector beeps */
    u32 pos, cop_pos;       /* road units, 16.16 */
    u16 cop_speed;          /* mph * 256 */
} DriveSound;

typedef struct AudioBackend {
    const char *name;
    void (*reset)(int rate);                        /* silence, output at rate samples per second */
    void (*speaker)(u16 divisor, u8 port61_bits);   /* divisor 0 means 65536 */
    void (*render)(s16 *out, int n);                /* the next n samples */
    void (*event)(SoundEvent e, int n, const char *car);    /* NULL: not needed */
    void (*drive)(const DriveSound *d);                     /* NULL: not needed */
} AudioBackend;

extern const AudioBackend audio_pc_speaker;         /* speaker.c */
