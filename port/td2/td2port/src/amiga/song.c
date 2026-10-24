/* The Amiga music and effect player (song.h), routine by routine from sfx/song's 68000 code. Addresses in
 * the comments are the routines' as tools/amiga/hunk.py lays the file out (code at 10000h). */
#include <stdio.h>
#include <string.h>

#include "amiga/song.h"

AmigaSeg song_seg;

/* The player's variables (symbols of the file) and its unnamed tables in the data section. */
static u32 PlayState, TrackState, SfxState, SfxMusicVol, SongAddr, FadeCount, FadeSpeed, Paused;
static u32 SoundPtr, SoundChannel, SoundVolume, SoundCount, TrackInfo, titlesong, voices;
static u32 data0;                                   /* __H1_org: the DMACON / INTENA words of the track */
#define DMA_ON    (data0 + 0)                       /* 10b90 DMACON set value for this track's channel */
#define DMA_BIT   (data0 + 2)                       /* 10b92 the channel's DMA bit */
#define INT_ON    (data0 + 4)                       /* 10b94 INTENA set value */
#define TRACK_NO  (data0 + 6)                       /* 10b96 track number */
#define PERIODS   (data0 + 0x134)                   /* 10cc4 period numerators, from note 1Bh */
#define DURATIONS (data0 + 0x254)                   /* 10de4 note lengths: ticks, release before end */

/* Track (Track0Info..Track3Info) fields. */
enum {
    T_ACTIVE = 0x00, T_SEQ = 0x02, T_PATTERN = 0x06, T_SEQ_INDEX = 0x0A, T_COUNT = 0x0E, T_RELEASE = 0x10,
    T_SAMPLE = 0x12,       /* 1: note started, -1: idle, 0: one-shot playing (stop at its end) */
    T_VHDR = 0x14, T_BODY = 0x18, T_OCTAVE_DIV = 0x1C, T_VOLUME = 0x1E, T_PERIOD = 0x20,
    T_REPEAT_LEN = 0x22, T_REPEAT = 0x24, T_REG_VOL = 0x28, T_REG_PER = 0x2C, T_REG_LC = 0x30,
    T_REG_LEN = 0x34, T_HOLD = 0x38, T_TIE = 0x3A, T_VOICE = 0x3C, T_NOTE = 0x40, T_CUR_PERIOD = 0x42,
    T_VIB_STEP = 0x44, T_SFX = 0x46, T_SFX_COUNT = 0x48,
};
/* Voice (instrument) fields. */
enum {
    V_VHDR = 0x00, V_BODY = 0x04, V_OCTAVE_DIV = 0x08, V_FORM = 0x0A, V_VIB_UP = 0x12, V_VIB_DOWN = 0x14,
    V_VIB_STEP = 0x16, V_VIB_DELAY = 0x18, V_VIB_DELAY0 = 0x1A, V_VIB_COUNT = 0x1C, V_VIBRATO = 0x1E,
    V_ARPEGGIO = 0x22, V_ARP_STEPS = 0x24, V_ARP_INDEX = 0x2C,
};

#define DMACON 0xDFF096u
#define INTENA 0xDFF09Au
#define INTREQ 0xDFF09Cu
#define INTREQR 0xDFF01Eu
#define ADKCON 0xDFF09Eu
#define CIAB_TALO 0xBFE401u
#define CIAB_TAHI 0xBFE501u
#define CIAB_CRA  0xBFEE01u

static u32 track(int k) { return ard32(TrackInfo + 4u * (u32)k); }
static void reg_w(u32 t, int field, u16 v) { awr16(ard32(t + (u32)field), v); }   /* through the track's pointer */
static u16 tw(u32 t, int f) { return ard16(t + (u32)f); }
static void tw_set(u32 t, int f, u16 v) { awr16(t + (u32)f, v); }

/* divu.w: quotient in the low word, remainder in the high word; on overflow the 68000 leaves d unchanged. */
static u32 divu(u32 d, u16 s)
{
    if (s == 0) return d;                           /* a divide trap; the player never divides by zero */
    u32 q = d / s;
    if (q > 0xFFFF) return d;
    return (d % s) << 16 | q;
}

static u32 find_chunk(u32 a, u32 id)                /* 109a0 / 109b0: scan by words, step past the header */
{
    for (int n = 0; n < 0x40000 && ard32(a) != id; n++) a += 2;
    return a + 8;
}

bool song_load(const u8 *file, u32 len, char *err, size_t errlen)
{
    if (!amiga_load_seg(file, len, 0x10000, &song_seg, err, errlen)) return false;
    struct { u32 *v; const char *name; } syms[] = {
        { &PlayState, "PlayState" }, { &TrackState, "TrackState" }, { &SfxState, "SfxState" },
        { &SfxMusicVol, "SfxMusicVol" }, { &SongAddr, "SongAddr" }, { &FadeCount, "FadeCount" },
        { &FadeSpeed, "FadeSpeed" }, { &Paused, "Paused" }, { &SoundPtr, "SoundPtr" },
        { &SoundChannel, "SoundChannel" }, { &SoundVolume, "SoundVolume" }, { &SoundCount, "SoundCount" },
        { &TrackInfo, "TrackInfo" }, { &titlesong, "titlesong" }, { &voices, "voices" }, { &data0, "__H1_org" },
    };
    for (size_t i = 0; i < sizeof syms / sizeof syms[0]; i++) {
        *syms[i].v = amiga_seg_symbol(&song_seg, syms[i].name);
        if (*syms[i].v == 0) {
            snprintf(err, errlen, "sfx/song has no symbol %s", syms[i].name);
            return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------------------------------- commands */

void song_open(void)                                /* 109c0, without the OS calls */
{
    awr16(PlayState, 0);
    awr32(TrackState, 0);
    awr8(CIAB_CRA, 0x01);                           /* timer A runs (its server is SongInt) */
    awr16(INTENA, 0x0780);
    awr16(INTREQR, 0x0780);                         /* as the original, a no-op */
    awr16(INTENA, 0x8780);                          /* the four audio interrupts (SongIntHandler) */
}

void song_read_instruments(void)                    /* 1095e */
{
    for (u32 a0 = voices + 4;; a0 += 4) {
        u32 v = ard32(a0);
        if (v == 0) return;
        u32 form = ard32(v + V_FORM);
        if (form == 0) continue;
        u32 vhdr = find_chunk(form, 0x56484452u);  /* VHDR */
        awr32(v + V_VHDR, vhdr);
        awr16(v + V_OCTAVE_DIV, (u16)divu(0x53, ard8(vhdr + 0x0E)));
        awr32(v + V_BODY, find_chunk(vhdr, 0x424F4459u));   /* BODY */
    }
}

static void play_song(u32 song)                     /* 10294 PlaySong */
{
    if ((s32)song <= 0) return;
    awr32(SongAddr, song);
    awr16(PlayState, 1);
}

void song_play(void)                                /* 10942 */
{
    if (song_status() == 0) play_song(titlesong);
}

void song_stop(void)                                /* 1007c */
{
    if (ard16(PlayState) == 0) return;
    awr16(Paused, 0);
    awr16(DMACON, 0x000F);
    awr16(PlayState, 3);
}

u16 song_status(void) { return ard16(PlayState); }  /* 102b6 */

void song_fade(u16 speed)                           /* 1009c */
{
    if (ard16(Paused) != 0) {
        song_stop();
        return;
    }
    if (ard16(PlayState) == 0) return;
    awr16(FadeCount, speed);
    awr16(FadeSpeed, speed);
    awr16(PlayState, 4);
}

void song_play_sfx(u32 form, u16 channel, u16 volume, u16 count, u16 music_volume)   /* 100c2 */
{
    if (form == 0) return;
    awr16(SoundChannel, channel);
    awr16(SoundVolume, volume);
    awr16(SoundCount, count);
    awr16(SfxMusicVol, music_volume);
    awr8(SfxState, (u8)(ard8(SfxState) | 1u << (channel & 7)));
    u32 t = track(channel & 0x3FFF);                /* lsl.w #2: the index as a word */
    awr32(SoundPtr, form);
    reg_w(t, T_REG_VOL, 0);
    reg_w(t, T_REG_PER, 0x7C);
    awr16(DMACON, (u16)(1u << (channel & 15)));   /* the channel off; it starts on the next tick */
}

static void sfx_start(void)                         /* 1011c: the pending effect, from SongInt */
{
    u16 ch = ard16(SoundChannel), vol = ard16(SoundVolume), count = ard16(SoundCount);
    u32 form = ard32(SoundPtr);
    awr8(SfxState, (u8)(ard8(SfxState) | 1u << (ch & 7)));
    u16 d7 = (u16)(1u << (ch & 15));
    awr16(DMA_BIT, d7);
    d7 |= 0x8000;
    awr16(DMA_ON, d7);
    d7 = (u16)(d7 << 7) | 0x8000;
    awr16(INT_ON, d7);
    u32 t = track(ch & 0x3FFF);
    tw_set(t, T_SFX, 0xFFFF);
    u32 vhdr = find_chunk(form, 0x56484452u);
    u32 body = find_chunk(vhdr, 0x424F4459u);
    reg_w(t, T_REG_VOL, vol);
    tw_set(t, T_SFX_COUNT, count);
    awr32(ard32(t + T_REG_LC), body);
    reg_w(t, T_REG_LEN, (u16)(ard32(vhdr) & 0xFFFF) >> 1);
    reg_w(t, T_REG_PER, (u16)divu(0x369E99u, ard16(vhdr + 0x0C)));
    awr16(DMACON, ard16(DMA_ON));
    awr16(INTENA, ard16(INT_ON));
    awr32(SoundPtr, 0);
}

static void sfx_off(u32 t, u16 dma_bit)
{
    reg_w(t, T_REG_VOL, 0);
    reg_w(t, T_REG_PER, 0x7C);
    awr16(DMACON, dma_bit);
    tw_set(t, T_SAMPLE, 0xFFFF);
    tw_set(t, T_SFX_COUNT, 0);
    tw_set(t, T_SFX, 0);
}

void song_stop_sfx(u16 channel)                     /* 101c0 */
{
    awr8(SfxState, (u8)(ard8(SfxState) & ~(1u << (channel & 7))));
    sfx_off(track(channel & 0x3FFF), (u16)(1u << (channel & 15)));
}

bool song_sfx_status(u16 channel) { return (ard8(SfxState) >> (channel & 7)) & 1; }    /* 10202 (btst on memory: a byte) */

static void restart_pattern(u32 t)                  /* 10244 */
{
    awr32(t + T_PATTERN, ard32(ard32(t + T_SEQ) + (u32)(s16)(ard32(t + T_SEQ_INDEX) & 0xFFFF)));
    tw_set(t, T_COUNT, 0);
}

void song_pause(void)                               /* 10212 */
{
    awr16(Paused, 0xFFFF);
    for (int k = 0; k < 4; k++) restart_pattern(TrackInfo + 0x10 + 0x4Au * (u32)k);
    awr16(DMACON, 0x000F);
}

void song_restart(void)                             /* 10258 */
{
    if (ard16(PlayState) == 0) {
        song_play();
        return;
    }
    awr16(Paused, 0);
}

void song_adjust_sfx(u16 channel, u16 rate, u16 volume)   /* 1026a */
{
    if (!song_sfx_status(channel)) return;
    u32 t = track(channel & 0x3FFF);
    reg_w(t, T_REG_VOL, volume);
    reg_w(t, T_REG_PER, (u16)divu(0x369E99u, rate));
}

/* ---------------------------------------------------------------------------------------- the tick */

/* 10802: the period of note d1 for the track's voice. Returns the octave shift (D3) and leaves the
 * voice's sample (A0) and VHDR (A2). */
static u16 note_period(u32 t, u16 d1, u32 *a0, u32 *a2)
{
    *a0 = ard32(t + T_BODY);
    *a2 = ard32(t + T_VHDR);
    u16 q = (u16)divu(d1, tw(t, T_OCTAVE_DIV));
    u16 d3 = (u16)(ard8(*a2 + 0x0E) - q - 1);
    if ((s16)d3 < 0) d3 = 0;
    u16 idx = (u16)((u16)(d1 - 0x1B) << 2);
    u32 num = ard32(PERIODS + (u32)(s32)(s16)idx);
    u32 per = divu(num, (u16)(ard32(*a2 + 0x08) << (d3 & 63)));
    if (tw(t, T_SFX) == 0) reg_w(t, T_REG_PER, (u16)per);
    tw_set(t, T_PERIOD, (u16)per);
    tw_set(t, T_CUR_PERIOD, (u16)per);
    u32 v = ard32(t + T_VOICE);
    awr16(v + V_VIB_COUNT, ard16(v + V_VIB_DELAY0));
    tw_set(t, T_VIB_STEP, ard16(v + V_VIB_STEP));
    return d3;
}

static void note_start(u32 t, u16 d1, u16 d2)       /* 1071c: d1 the note, d2 its length index */
{
    awr32(t + T_PATTERN, ard32(t + T_PATTERN) + 2);
    u32 dur = DURATIONS + (u32)(s32)(s16)(u16)(d2 << 1);
    u16 d3 = (u16)(ard8(dur) - 1);
    tw_set(t, T_COUNT, d3);
    d3 = (u16)((d3 & 0xFF00) | (u8)((u8)d3 - ard8(dur + 1)));
    tw_set(t, T_RELEASE, d3);
    if (ard32(t + T_VHDR) != 0) {
        u16 tie = tw(t, T_TIE);
        if (tie != 0) {
            if (tie == 1) goto active;
            tw_set(t, T_TIE, (u16)(tie - 1));
        }
        u32 a0, a2;
        u16 oct = note_period(t, d1, &a0, &a2);
        if (oct) {
            u32 step = ard32(a2) + ard32(a2 + 4);
            for (u16 k = oct; k; k--) {
                a0 += step;
                step <<= 1;
            }
        }
        if (tw(t, T_SFX) == 0) awr32(ard32(t + T_REG_LC), a0);
        a0 += ard32(a2) << (oct & 63);
        awr32(t + T_REPEAT, a0);
        tw_set(t, T_SAMPLE, 1);
        u32 len = ((ard32(a2) + ard32(a2 + 4)) << (oct & 63)) >> 1;
        if (tw(t, T_SFX) == 0) reg_w(t, T_REG_LEN, (u16)len);
        tw_set(t, T_REPEAT_LEN, (u16)((ard32(a2 + 4) << (oct & 63)) >> 1));
        if (tw(t, T_SFX) == 0) {
            u16 vol = tw(t, T_VOLUME);
            if (ard16(SfxState) != 0) vol = (u16)(((u32)(u16)(vol << 8) * ard16(SfxMusicVol)) >> 16);
            reg_w(t, T_REG_VOL, vol);
        }
        awr16(ADKCON, 0x00FF);
        awr16(DMACON, ard16(DMA_ON));
        awr16(INTENA, ard16(INT_ON));
    }
active:
    awr8(TrackState, (u8)(ard8(TrackState) | 1u << (ard16(TRACK_NO) & 7)));
}

static void read_events(u32 t, u16 d3)              /* 105ea */
{
    u32 a0 = ard32(t + T_SEQ);
    u32 a1 = ard32(t + T_PATTERN);
    u32 d0 = ard32(t + T_SEQ_INDEX);
    for (;;) {
        u16 d1 = ard8(a1), d2 = ard8(a1 + 1);
        if (d1 < 0xD9) {
            if (d1 & 0x80) {
                if (tw(t, T_TIE) == 0) tw_set(t, T_TIE, 2);
            } else {
                tw_set(t, T_TIE, 0);
            }
            d1 = (u16)((d1 & 0x7F) + ard16(a0 + (u32)(s32)(s16)(u16)d0 + 4));
            tw_set(t, T_NOTE, d1);
            note_start(t, (u16)(d1 + d3), d2);
            return;
        }
        switch (d1) {
        case 0xD9:                                  /* next pattern of the sequence */
            awr32(t + T_SEQ_INDEX, ard32(t + T_SEQ_INDEX) + 6);
            d0 += 6;
            awr32(t + T_PATTERN, ard32(a0 + (u32)(s32)(s16)(u16)d0));
            a1 = ard32(t + T_PATTERN);
            continue;
        case 0xDB:                                  /* back to the start of the sequence */
            awr32(t + T_SEQ_INDEX, 0);
            a0 = ard32(t + T_SEQ);
            awr32(t + T_PATTERN, ard32(a0));
            a1 = ard32(t + T_PATTERN);
            d0 = ard32(t + T_SEQ_INDEX);
            continue;
        case 0xDA:                                  /* the track ends */
            tw_set(t, T_ACTIVE, 0);
            return;
        case 0xDC: {                                /* voice d2 */
            u32 v = ard32(voices + (u32)(s32)(s16)(u16)(d2 << 2));
            awr32(t + T_VOICE, v);
            awr32(t + T_VHDR, ard32(v + V_VHDR));
            awr32(t + T_BODY, ard32(v + V_BODY));
            tw_set(t, T_OCTAVE_DIV, ard16(v + V_OCTAVE_DIV));
            break;
        }
        case 0xDD:                                  /* tempo, timer high byte */
            awr8(CIAB_TAHI, (u8)d2);
            awr8(CIAB_CRA, 0x10);
            awr8(CIAB_CRA, 0x01);
            break;
        case 0xDE:                                  /* tempo, timer low byte */
            awr8(CIAB_TALO, (u8)d2);
            awr8(CIAB_CRA, 0x10);
            awr8(CIAB_CRA, 0x01);
            break;
        case 0xDF:                                  /* volume, unless the song is fading */
            if (ard16(PlayState) == 4) break;
            if (tw(t, T_SFX) == 0) reg_w(t, T_REG_VOL, d2);
            tw_set(t, T_VOLUME, d2);
            break;
        case 0xE0:
            tw_set(t, T_HOLD, d2);
            break;
        default:
            break;
        }
        awr32(t + T_PATTERN, ard32(t + T_PATTERN) + 2);    /* 10666 */
        a1 += 2;
    }
}

static void track_tick(u32 t)                       /* 1050c */
{
    if (tw(t, T_ACTIVE) == 0) return;
    u16 d3 = 0;
    if (tw(t, T_COUNT) == 0) {
        read_events(t, d3);
        return;
    }
    u32 v = ard32(t + T_VOICE);
    if (ard16(v + V_ARPEGGIO) != 0) {
        u16 i = ard16(v + V_ARP_INDEX);
        awr16(v + V_ARP_INDEX, (u16)(i + 1));
        d3 = ard16(v + V_ARP_STEPS + (u32)((i & 3) << 1));
    }
    tw_set(t, T_COUNT, (u16)(tw(t, T_COUNT) - 1));
    if (tw(t, T_COUNT) == tw(t, T_RELEASE)) {       /* 105b0: release */
        if (tw(t, T_HOLD) == 1 || tw(t, T_TIE) != 0) return;
        if (tw(t, T_SFX) == 0) {
            awr16(DMACON, ard16(DMA_BIT));
            reg_w(t, T_REG_VOL, 0);
            reg_w(t, T_REG_PER, 0x7C);
        }
        tw_set(t, T_SAMPLE, 0xFFFF);
        return;
    }
    v = ard32(t + T_VOICE);
    if (ard16(v + V_ARPEGGIO) != 0) {
        u32 a0, a2;
        note_period(t, (u16)(tw(t, T_NOTE) + d3), &a0, &a2);
        return;
    }
    if (ard16(v + V_VIBRATO) == 0) return;
    u16 c = (u16)(ard16(v + V_VIB_COUNT) - 1);
    awr16(v + V_VIB_COUNT, c);
    if ((s16)c > 0) return;
    awr16(v + V_VIB_COUNT, ard16(v + V_VIB_DELAY));
    u16 base = tw(t, T_PERIOD), cur = tw(t, T_CUR_PERIOD);
    u16 d0 = (u16)(cur - base);
    bool turn;
    if ((s16)tw(t, T_VIB_STEP) >= 0) turn = d0 > ard16(v + V_VIB_UP);
    else turn = !(d0 > ard16(v + V_VIB_DOWN));
    if (turn) tw_set(t, T_VIB_STEP, (u16)-tw(t, T_VIB_STEP));
    cur = (u16)(cur + tw(t, T_VIB_STEP));
    if (tw(t, T_SFX) == 0) reg_w(t, T_REG_PER, cur);
    tw_set(t, T_CUR_PERIOD, cur);
}

static void all_off(void)                           /* 104f2 */
{
    awr16(INTENA, 0x0780);
    awr16(INTREQR, 0x0780);                         /* the original's: INTREQR is read-only, a no-op */
    awr16(DMACON, 0x000F);
}

void song_tick(void)                                /* 102be SongInt */
{
    if (ard32(SoundPtr) != 0) sfx_start();
    if (ard16(Paused) != 0) return;
    u16 state = ard16(PlayState);
    if (state == 0) return;
    if (state == 3) {
    stop:
        awr16(PlayState, 0);
        all_off();
        return;
    }
    if (state == 4) {
        u16 n = (u16)(ard16(FadeCount) - 1);
        awr16(FadeCount, n);
        if ((s16)n < 0) {
            awr16(FadeCount, ard16(FadeSpeed));
            bool any = false;
            for (int k = 0; k < 4; k++) {
                u32 t = TrackInfo + 0x10 + 0x4Au * (u32)k;
                if (tw(t, T_VOLUME) != 0) {
                    tw_set(t, T_VOLUME, (u16)(tw(t, T_VOLUME) - 1));
                    any = true;
                }
            }
            if (!any) goto stop;
        }
    } else if (state == 1) {                        /* 10372: start the song's four tracks */
        u32 song = ard32(SongAddr);
        for (int k = 0; k < 4; k++) {
            u32 t = TrackInfo + 0x10 + 0x4Au * (u32)k;
            u32 seq = ard32(song + 4u * (u32)k);
            tw_set(t, T_ACTIVE, 0xFFFF);
            awr32(t + T_SEQ, seq);
            awr32(t + T_PATTERN, ard32(seq));
            awr32(t + T_SEQ_INDEX, 0);
            tw_set(t, T_COUNT, 0);
            tw_set(t, T_VOLUME, 0x20);
        }
        awr16(PlayState, 2);
        awr16(DMACON, 0x000F);
    } else if (state != 2) {
        return;
    }
    for (int k = 0; k < 4; k++) {                   /* 10436 */
        awr16(DMA_ON, (u16)(0x8000 | 1u << k));
        awr16(DMA_BIT, (u16)(1u << k));
        awr16(INT_ON, (u16)(0x8000 | 0x80u << k));
        awr16(TRACK_NO, (u16)k);
        track_tick(TrackInfo + 0x10 + 0x4Au * (u32)k);
    }
    if (ard32(TrackState) != 0) return;
    awr16(PlayState, 0);
    all_off();
}

/* 108c6 CheckChannelInt for track t: d1 its INTREQR bit, d2 its DMA bit, d3 its INTREQ bit. */
static void channel_int(u32 t, u16 intreqr, int d1, u16 d2, u16 d3)
{
    if (!((intreqr >> d1) & 1)) goto ack;
    if (tw(t, T_SFX) != 0) {
        u16 n = tw(t, T_SFX_COUNT);
        if (n == 0xFFFF) goto ack;
        if (n != 0) {
            tw_set(t, T_SFX_COUNT, (u16)(n - 1));
            goto ack;
        }
        goto stop;
    }
    {
        s16 s = (s16)tw(t, T_SAMPLE);
        if (s < 0) goto ack;
        if (s == 0) goto stop;
        if (tw(t, T_REPEAT_LEN) != 0) {             /* the one-shot part is under way: queue the loop */
            reg_w(t, T_REG_LEN, tw(t, T_REPEAT_LEN));
            awr32(ard32(t + T_REG_LC), ard32(t + T_REPEAT));
            tw_set(t, T_SAMPLE, 0xFFFF);
        } else {
            tw_set(t, T_SAMPLE, 0);
        }
        goto ack;
    }
stop:
    awr8(SfxState, (u8)(ard8(SfxState) & ~(1u << ((d1 - 7) & 7))));
    sfx_off(t, d2);
ack:
    awr16(INTREQ, d3);
}

void song_audio_int(u16 intreqr)                    /* 10860 SongIntHandler */
{
    for (int k = 0; k < 4; k++)
        channel_int(TrackInfo + 0x10 + 0x4Au * (u32)k, intreqr, 7 + k, (u16)(1u << k), (u16)(0x80u << k));
}
