/* The Amiga race sound driver (race_sound.h), routine by routine from duel's 68000 code. The channel
 * records are duel's at $264a0 (1Eh bytes each); they live here as a C array with the same fields. */
#include <string.h>

#include "amiga/amiga_mem.h"
#include "amiga/race_sound.h"

#define CUSTOM 0xDFF000u
#define DMACON (CUSTOM + 0x96)
#define INTENA (CUSTOM + 0x9A)
#define INTREQ (CUSTOM + 0x9C)
#define ADKCON (CUSTOM + 0x9E)
#define AUD(ch, r) (CUSTOM + 0xA0 + 16u * (ch) + (r))   /* r: 0 LC, 4 LEN, 6 PER, 8 VOL */

static struct {
    u32 sample;                                     /* +00 0: the channel is free */
    u32 stopped;                                    /* +04 frame of the last stop */
    u16 pending;                                    /* +08 FFFFh: start at the next frame */
    u16 words, period;                              /* +0A, +0C */
    u32 volume;                                     /* +0E 16.16 */
    u16 repeats;                                    /* +12 */
    s16 left;                                       /* +14 interrupts left before it stops */
    s32 target;                                     /* +16 the ramp's volume, 16.16; -1: none */
    u32 step;                                       /* +1A */
} ch[4];

static u32 frame;                                   /* A4-30E2h, counted by the server */
static u16 dma_set;                                 /* A4-2BA4h */
/* The original also keeps marks for the game about channel 2 (A4-2BAAh, -2BA8h, -2BACh); they change no
 * register, so they are left out. */

void race_sound_init(void)                          /* $11f96 */
{
    frame = 0;
    for (int c = 0; c < 4; c++) {
        ch[c].sample = 0;
        ch[c].pending = 0;
        ch[c].target = -1;
        ch[c].stopped = 0;
    }
    awr16(INTENA, 0x0780);
    awr16(DMACON, 0x000F);
    awr16(ADKCON, 0x00FF);
    awr16(INTREQ, 0x0780);
    awr16(INTENA, 0x8780);
}

bool race_sound_busy(u16 c) { return ch[c & 3].sample != 0; }      /* $121ea */

void race_sound_stop(u16 c)                         /* $1218a */
{
    awr16(INTENA, (u16)(0x80u << (c & 15)));
    ch[c].pending = 0;
    awr16(DMACON, (u16)(1u << (c & 15)));
    ch[c].target = -1;
    awr16(AUD(c, 8), 0);
    ch[c].stopped = frame;
    ch[c].sample = 0;
}

void race_sound_play(u32 sample, u32 bytes, u16 c, u16 period, u16 volume, u16 repeats)   /* $120cc */
{
    if (sample == 0) return;
    if (race_sound_busy(c & 3)) race_sound_stop(c & 3);
    if (c == 6) c = 2;
    u16 bit = (u16)(1u << ((c + 7) & 31));
    awr16(INTREQ, bit);
    awr16(INTENA, (u16)(bit | 0x8000));
    ch[c].words = (u16)(bytes >> 1);
    ch[c].period = period;
    ch[c].volume = (u32)volume << 16;
    ch[c].repeats = repeats;
    ch[c].sample = sample;
    ch[c].target = -1;
    ch[c].pending = 0xFFFF;
}

void race_sound_play_raw(u32 file, u16 c, u16 volume)        /* $12072 */
{
    if (file == 0) return;
    u16 rate = ard16(file + 4);
    if (rate < 100) rate = (u16)(rate * 1000u);   /* mulu.w, then the low word */
    u16 period = rate ? (u16)(0x369E99u / rate) : 0;
    race_sound_play(file + 6, ard32(file), c, period, volume, 1);
}

void race_sound_set(u16 c, s16 period, s16 volume)          /* $12202 */
{
    if (period >= 0) awr16(AUD(c, 6), (u16)period);
    if (volume >= 0) {
        ch[c].target = -1;
        ch[c].volume = (u32)(u16)volume << 16;
        awr16(AUD(c, 8), (u16)volume);
    }
}

void race_sound_ramp(u16 c, u16 target, u32 step)            /* $12250 */
{
    ch[c].step = step;
    ch[c].target = (s32)((u32)target << 16);
}

void race_sound_vblank(u16 intenar)                 /* $1231c */
{
    frame++;
    u16 saved = intenar & 0x0780;
    awr16(INTENA, 0x0780);
    dma_set = 0x8000;
    for (int c = 0; c < 4; c++) {
        if (ch[c].pending != 0 && (s32)(frame - ch[c].stopped) >= 2) {
            awr32(AUD(c, 0), ch[c].sample);
            awr16(AUD(c, 4), ch[c].words);
            awr16(AUD(c, 6), ch[c].period);
            awr16(AUD(c, 8), (u16)(ch[c].volume >> 16));
            ch[c].left = (s16)ch[c].repeats;
            dma_set |= (u16)(1u << c);
            ch[c].pending = 0;
        }
        if (ch[c].target >= 0) {                    /* the volume ramp */
            s32 v = (s32)ch[c].volume;
            bool done;
            if (v == ch[c].target) {
                done = true;
            } else if (v > ch[c].target) {
                v -= (s32)ch[c].step;
                done = v <= ch[c].target;
            } else {
                v += (s32)ch[c].step;
                done = v >= ch[c].target;
            }
            if (done) {
                v = ch[c].target;
                ch[c].target = -1;
            }
            ch[c].volume = (u32)v;
            awr16(AUD(c, 8), (u16)((u32)v >> 16));
        }
    }
    if (saved) awr16(INTENA, (u16)(saved | 0x8000));
    if (dma_set & 0xFF) awr16(DMACON, dma_set);
}

void race_sound_audio_int(u16 intreqr, u16 intenar) /* $1226e */
{
    awr16(INTENA, 0x4000);
    u16 d0 = intreqr & intenar & 0x0780;
    u16 ack = 0;
    for (int c = 0; c < 4; c++) {
        u16 bit = (u16)(0x80u << c);
        if (!(d0 & bit)) continue;
        if (ch[c].sample != 0) {
            if (ch[c].left < 0) {                   /* loops for ever */
                ack |= bit;
                continue;
            }
            if (--ch[c].left >= 0) {
                ack |= bit;
                continue;
            }
        }
        ack |= bit;
        awr16(INTENA, ack);                         /* the original's: all channels acknowledged so far */
        awr16(DMACON, (u16)(1u << c));
        ch[c].target = -1;
        awr16(AUD(c, 8), 0);
        ch[c].volume = 0;
        ch[c].stopped = frame;
        ch[c].sample = 0;
    }
    if (ack) awr16(INTREQ, ack);
    awr16(INTENA, 0xC000);
}
