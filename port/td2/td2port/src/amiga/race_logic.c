/* The Amiga race sound logic (race_logic.h), routine by routine from duel's 68000 code. The calls duel
 * makes to the operating system between plays (Delay and WaitTOF, a few frames) are left out: the
 * driver itself starts a sample no earlier than the second frame after its channel stopped. */
#include "amiga/amiga_mem.h"
#include "amiga/race_logic.h"
#include "amiga/race_sound.h"

RaceCar race_car;
RaceSamples race_samples;
bool race_sound_on = true;

static bool crashed;                                /* $289e2 */
static bool siren;                                  /* $28a8e */
static s16 siren_pitch, siren_dir, siren_period;    /* $28a90, $28a92, $28a94 (7D00h: none yet) */
static u16 engine_period;                           /* $28a96 */

/* The gear change squeal, one entry per step: volume ($1d268) and period ($1d29a) on the squeal channel. */
static const u8 shift_volume[25] = {
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x3C, 0x32, 0x2D, 0x20, 0x14, 0x0A, 0x00,
};
static const u16 shift_period[25] = {
    0x15C, 0x15C, 0x15C, 0x172, 0x17C, 0x182, 0x188, 0x18B, 0x186, 0x186, 0x181, 0x181, 0x180,
    0x17F, 0x17E, 0x17D, 0x17A, 0x177, 0x172, 0x168, 0x15E, 0x154, 0x14F, 0x14F, 0x14F,
};

/* $20858, Lattice's signed long division (the quotient truncated towards zero) */
static s32 ldivs(s32 a, s32 b) { return b ? a / b : 0; }

void race_logic_reset(void)
{
    crashed = false;            /* duel clears it outside these routines; the game calls this per race */
    siren = false;
    siren_pitch = siren_dir = siren_period = 0;     /* duel's initial data */
    engine_period = 0;
    race_car.shift_squeal = -1;
}

bool race_crashed(void) { return crashed; }
bool race_siren_on(void) { return siren; }

void race_start_loops(void)                         /* $1d044 */
{
    if (!race_sound_on) return;
    RaceSamples *s = &race_samples;
    race_sound_play(s->squeal, ard32(s->squeal), 1, 0x166, 0, 0xFFFF);
    race_sound_play(s->turbo, ard32(s->turbo), 2, 800, 0, 0xFFFF);
    race_sound_play(s->engine, ard32(s->engine), 3, 800, 0, 0xFFFF);
    if (race_sound_on) {
        race_sound_ramp(3, 0x3F, 0x7000);
        race_car.squeal_volume = 0;
        race_car.shift_squeal = -1;
    }
}

void race_fade_out(void)                            /* $1d0e2 */
{
    race_sound_ramp(1, 0, 0x7000);
    race_sound_ramp(2, 0, 0x7000);
    race_sound_ramp(3, 0, 0x7000);
}

void race_squeal_off(void)                          /* $1d206: st.b on the step's high byte */
{
    race_car.shift_squeal = (s16)(0xFF00u | ((u16)race_car.shift_squeal & 0xFF));
    race_car.squeal_volume = 0;
}

static void shift_squeal_step(void)                 /* $1d210 */
{
    RaceCar *c = &race_car;
    if (c->shift_squeal >= 0) {
        c->shift_squeal++;
        /* After 32767 held steps the original would read before its tables; here it ends instead. */
        if (c->shift_squeal >= 0 && c->shift_squeal < 25) {
            race_sound_set(1, (s16)shift_period[c->shift_squeal], shift_volume[c->shift_squeal]);
            return;
        }
    }
    if (!c->squeal_held) {
        c->shift_squeal = -1;
        race_sound_set(1, 0x166, (s16)c->squeal_volume);
    }
}

static void bump_step(void)                         /* $1d2cc */
{
    if ((race_car.bump || race_car.bump2) && !siren && !race_sound_busy(0) && race_sound_on)
        race_sound_play_raw(race_samples.bump, 0, 0x40);
    race_car.bump = race_car.bump2 = false;
}

void race_step(void)                                /* $1d118 */
{
    RaceCar *c = &race_car;
    shift_squeal_step();
    bump_step();
    if (!c->engine_on) return;

    u16 r = (s16)c->rpm < 800 ? 800 : c->rpm;
    u16 p = (u16)(0x249988u / r);
    if ((s16)p < 0x82) p = 0x82;
    if ((s16)p > 0x708) p = 0x708;
    engine_period = p;
    race_sound_set(3, (s16)p, -1);

    u16 v = 0;
    if (c->throttle >= 0) {
        bool add_speed = true;
        if (c->throttle > 0) {
            add_speed = false;
            if (c->in_gear) {
                u16 d = c->rpm;
                if (c->low_rev_turbo) d = (u16)(d + 1500);
                if ((s16)d > 2000) {
                    if ((s16)d > 4000) d = 4000;
                    v = (u16)(((u32)(u16)(d - 2000) * 0x831) >> 16);
                    add_speed = true;
                }
            }
        }
        u16 s = (u16)((u16)(c->speed >> 16) - 20);
        if (add_speed && (s16)s > 0) {
            s >>= 2;
            if ((s16)s >= 0x20) s = 0x20;
            v = (u16)(v + s);
            if ((s16)v > 0x40) v = 0x40;
        }
    }
    race_sound_ramp(2, v, 0x10000);
    u16 t = engine_period;
    if (c->low_rev_turbo) t = (u16)(t << 1);
    race_sound_set(2, (s16)t, -1);
}

void race_radar(void)                               /* $1cde4 */
{
    if (race_sound_on && !crashed && !siren) race_sound_play_raw(race_samples.radar, 0, 0x40);
}

void race_crash(void)                               /* $1ce10 */
{
    if (!race_sound_on) return;
    crashed = true;
    siren = false;
    race_sound_stop(0);
    race_sound_play_raw(race_samples.crash, 0, 0x40);
}

void race_siren_start(void)                         /* $1ce50 */
{
    u32 s = race_samples.siren;
    if (!race_sound_on || s == 0 || crashed) return;
    siren = true;
    race_sound_stop(0);
    siren_pitch = 6000;
    siren_period = 32000;
    siren_dir = 0;
    u16 period = (u16)ldivs(siren_pitch, (s32)ard32(s));
    race_sound_play(s + 6, ard32(s), 0, period, 0x40, 0xFFFF);
}

void race_siren_stop(void)                          /* $1cec2 */
{
    if (siren) race_sound_stop(0);
    siren = false;
}

/* The siren rises and falls between pitches 14,000 and 23,000; the gap to the police car and the speed
 * between the two shift it (a Doppler factor 450 / (450 - closing mph)) and set its volume. */
void race_siren_sweep(void)                         /* $1cedc */
{
    RaceCar *c = &race_car;
    if (!siren || !race_sound_on) return;
    s16 gap = (s16)((c->pos - c->cop_pos) >> 16);
    s16 closing = (s16)(((c->speed >> 6) - c->cop_speed) >> 10);
    gap = (s16)((s16)(u16)(gap << 1) / 4);
    if (gap < 0) {
        gap = (s16)-gap;
        closing = (s16)-closing;
    }
    if (gap > 60) gap = 60;

    if (siren_dir == 0) {
        siren_pitch = (s16)(siren_pitch + siren_pitch / 50);
        if (siren_pitch > 23000) siren_dir = -1;
    } else if (siren_dir > 0) {
        siren_pitch = (s16)(siren_pitch + siren_pitch / 100);
        if (siren_pitch > 23000) siren_dir = -1;
    } else {
        siren_pitch = (s16)(siren_pitch - siren_pitch / 100);
        if (siren_pitch < 14000) siren_dir = 1;
    }
    s32 q = ldivs((s32)siren_pitch * 450, 450 - (s32)closing);
    s16 p = (s16)ldivs(q, (s32)ard32(race_samples.siren));
    if (p < 0x7C) p = 0x7C;
    if (siren_period != 32000) {
        s16 hi = (s16)(siren_period + siren_period / 50), lo = (s16)(siren_period - siren_period / 50);
        if (p > hi) p = hi;
        if (p < lo) p = lo;
    }
    siren_period = p;
    race_sound_set(0, p, (s16)(0x40 - gap));
}
