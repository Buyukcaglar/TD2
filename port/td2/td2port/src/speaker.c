#include "speaker.h"
#include "audio_backend.h"
#include "host.h"

#include <math.h>
#include <string.h>

#define PI 3.14159265358979323846

void speaker_init(Speaker *s, int rate)
{
    memset(s, 0, sizeof *s);
    s->rate = rate;
    double sub = (double)rate * SPK_OVERSAMPLE;
    s->a_lp = 1.0 - exp(-2.0 * PI * SPK_LOWPASS_HZ / sub);
    s->a_hp = 1.0 / (1.0 + 2.0 * PI * SPK_HIGHPASS_HZ / rate);
}

void speaker_set(Speaker *s, u8 port61_bits)
{
    port61_bits &= 3;
    if ((port61_bits & 1) && !(s->bits & 1)) s->phase = 0.0;   /* gate rising: count restarts, output high */
    s->bits = port61_bits;
}

/* Time the PIT output is high from phase 0 to phase x (in cycles). */
static double high_time(double x)
{
    double whole = floor(x);
    double frac = x - whole;
    return whole * 0.5 + (frac < 0.5 ? frac : 0.5);
}

void speaker_render(Speaker *s, u16 divisor, s16 *out, int n, int amplitude)
{
    double step = (double)PIT_HZ / (divisor ? divisor : 65536) / (s->rate * SPK_OVERSAMPLE);
    for (int i = 0; i < n; i++) {
        double acc = 0.0;
        for (int k = 0; k < SPK_OVERSAMPLE; k++) {
            double level;
            if (!(s->bits & 2)) level = 0.0;                /* data bit off: speaker input low */
            else if (!(s->bits & 1)) level = 1.0;           /* gate off: PIT output held high */
            else {
                level = (high_time(s->phase + step) - high_time(s->phase)) / step;
                s->phase += step;
                s->phase -= floor(s->phase);
            }
            s->lp1 += s->a_lp * (level - s->lp1);
            s->lp2 += s->a_lp * (s->lp1 - s->lp2);
            acc += s->lp2;
        }
        double x = acc / SPK_OVERSAMPLE;
        s->hp_out = s->a_hp * (s->hp_out + x - s->hp_in);
        s->hp_in = x;
        double v = s->hp_out * 2.0 * amplitude;             /* a 0..1 swing becomes +-amplitude */
        out[i] = (s16)(v > 32767.0 ? 32767 : v < -32768.0 ? -32768 : lrint(v));
    }
}

/* ---- the PC speaker audio backend */

#define SPK_AMPLITUDE 5000

static Speaker pcs;
static u16 pcs_divisor;

static void pcs_reset(int rate)
{
    speaker_init(&pcs, rate);
    pcs_divisor = 0;
}

static void pcs_speaker(u16 divisor, u8 port61_bits)
{
    pcs_divisor = divisor;
    speaker_set(&pcs, port61_bits);
}

static void pcs_render(s16 *out, int n)
{
    speaker_render(&pcs, pcs_divisor, out, n, SPK_AMPLITUDE);
    for (int i = n - 1; i >= 0; i--) out[2 * i + 1] = out[2 * i] = out[i];   /* mono to both sides */
}

const AudioBackend audio_pc_speaker = { "PC speaker", pcs_reset, pcs_speaker, pcs_render, NULL, NULL, NULL, false };
