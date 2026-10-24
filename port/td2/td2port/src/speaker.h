#pragma once
/* PC-speaker synthesis (host side, no SDL): PIT channel 2 in mode 3 drives the speaker through the
 * data bit of port 61h. The square wave is rendered band-limited (exact average over each sub-sample
 * on a 4x grid), then filtered by a model of the speaker cone: a two-pole low-pass and a DC-blocking
 * high-pass. The speaker sits at rest (silence) whatever constant level it is left at. */
#include "types.h"

#define SPK_OVERSAMPLE 4
#define SPK_LOWPASS_HZ 9000.0               /* cone roll-off; also removes what would alias */
#define SPK_HIGHPASS_HZ 10.0                /* the cone does not hold a DC offset; low enough not to tilt bass notes */

typedef struct {
    double rate;                            /* output samples per second */
    double phase;                           /* PIT output phase in cycles: [0, 0.5) high, [0.5, 1) low */
    u8 bits;                                /* port 61h bit 0 = PIT gate, bit 1 = speaker data */
    double a_lp, a_hp;                      /* filter coefficients */
    double lp1, lp2, hp_in, hp_out;         /* filter state */
} Speaker;

void speaker_init(Speaker *s, int rate);
/* New port 61h bits. Raising the gate restarts the PIT count (output high); a low gate holds the
 * output high, so with the data bit set the speaker sees a constant level. */
void speaker_set(Speaker *s, u8 port61_bits);
/* Renders n samples at the current state; divisor 0 means 65536. */
void speaker_render(Speaker *s, u16 divisor, s16 *out, int n, int amplitude);
