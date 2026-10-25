#pragma once
/* The Amiga game's race sound logic: what duel plays through its race driver (race_sound.h), from the
 * car's state, translated from its 68000 code ($1cd1a..$1d30a). Channel 0 has the one-shot effects and
 * the siren, channel 1 the tyre squeal, channel 2 the car's turbo sample and channel 3 its engine
 * sample. The game fills race_car with the duel variables the logic reads (named here by meaning) and
 * calls the routines at the moments duel does. See docs/amiga.md, "The race sounds". */
#include "types.h"

typedef struct RaceCar {
    u16 rpm;                    /* $261fa */
    s32 speed;                  /* $2619c: mph, 16.16 */
    s16 throttle;               /* $260f8: below 0 braking, 0 off, above 0 on */
    bool in_gear;               /* $262de[gear]: a working gear is engaged */
    bool engine_on;             /* $26b38 */
    bool squeal_held;           /* $262d2: the squeal channel keeps what it plays */
    u16 squeal_volume;          /* $289d2: from the skid, 0..64 */
    s32 pos, cop_pos;           /* $25228, $26178: road units, 16.16 */
    s32 cop_speed;              /* $26180: mph << 10 */
    bool bump, bump2;           /* $262d8, $277ba: a bump to play at the next step */
    bool low_rev_turbo;         /* the car record's word at 0Ah is 0 (no shipped car has that) */
    s16 shift_squeal;           /* $234ee: step of the gear change squeal; negative: none */
} RaceCar;

typedef struct RaceSamples {    /* amiga_mem addresses of the loaded files, 0 if missing */
    u32 radar, squeal, bump, crash, siren;          /* $250f0, $250fc, $25100, $25104, $25108 */
    u32 engine, turbo;                              /* $250f4, $250f8: "<car>engine", "<car>turbo" */
} RaceSamples;

extern RaceCar race_car;
extern RaceSamples race_samples;
extern bool race_sound_on;      /* $22932: the sound setting */

void race_logic_reset(void);
void race_start_loops(void);    /* $1d044: squeal, turbo and engine loops, engine up to full volume */
void race_fade_out(void);       /* $1d0e2: squeal, turbo and engine down to silence */
void race_step(void);           /* $1d118: each physics step; gear change squeal, bump, engine, turbo */
/* The turbo sample's volume (0..64) that race_step ramps to, one a frame: from the revs (2000 to 4000)
 * with the throttle on in gear, plus the speed above 20 mph / 4. duel's turbo gauge shows the channel's
 * volume as it ramps ($1ac44 reads -$3094, channel 2's volume at +0Eh). */
u16 race_turbo_volume(const RaceCar *c);
void race_squeal_off(void);     /* $1d206 */
void race_radar(void);          /* $1cde4: one radar beep */
void race_crash(void);          /* $1ce10 */
void race_siren_start(void);    /* $1ce50 */
void race_siren_stop(void);     /* $1cec2 */
void race_siren_sweep(void);    /* $1cedc: each vertical blank, before the driver's server */
bool race_crashed(void);
bool race_siren_on(void);
