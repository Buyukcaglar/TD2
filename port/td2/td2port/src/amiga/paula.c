/* Paula and the CIA-B timer (paula.h). */
#include <math.h>
#include <string.h>

#include "amiga/amiga_mem.h"
#include "amiga/paula.h"

typedef struct {
    u32 lc;                                         /* AUDxLC, AUDxLEN, AUDxPER, AUDxVOL as written */
    u16 len, per, vol;
    bool on;                                        /* DMA running */
    u32 ptr, words;                                 /* the block being played */
    u16 word;
    int byte;                                       /* 0: high byte of word, 1: low */
    double left;                                    /* clocks left on the current byte */
    s8 out;
} Channel;

static struct {
    Channel ch[4];
    u16 dmacon, intena, intreq;
    u16 latch, counter_lo, counter_hi;
    bool timer_on;
    double timer_left;                              /* clocks of Paula's clock until the next underflow */
    double clocks_per_sample;
    float lp, lp_k;
    void (*audio_int)(u16);
    void (*timer)(void);
    void (*vblank)(void);
    double vblank_left;
} p;

void paula_set_servers(void (*audio_int)(u16), void (*timer)(void))
{
    p.audio_int = audio_int;
    p.timer = timer;
}

void paula_set_vblank(void (*server)(void)) { p.vblank = server; }
u16 paula_intena(void) { return p.intena; }

void paula_reset(int rate)
{
    void (*a)(u16) = p.audio_int;
    void (*t)(void) = p.timer;
    void (*vb)(void) = p.vblank;
    memset(&p, 0, sizeof p);
    p.audio_int = a;
    p.timer = t;
    p.vblank = vb;
    p.vblank_left = PAULA_FRAME;
    for (int i = 0; i < 4; i++) p.ch[i].per = 0x7C;
    p.latch = 0xFFFF;
    p.clocks_per_sample = PAULA_CLOCK / (rate > 0 ? rate : 44100);
    p.lp_k = (float)(1.0 - exp(-2.0 * 3.14159265358979 * 4420.0 / (rate > 0 ? rate : 44100)));
}

static void raise(int c)
{
    p.intreq |= (u16)(0x80u << c);
    if ((p.intena & (0x80u << c)) && p.audio_int) {
        u16 pending = p.intreq;
        p.audio_int(pending);
    }
}

static void block_start(int c)
{
    Channel *ch = &p.ch[c];
    ch->ptr = ch->lc & ~1u;
    ch->words = ch->len ? ch->len : 0x10000u;
    raise(c);                                       /* the handler may queue the next block's LC/LEN */
}

static void fetch(int c)
{
    Channel *ch = &p.ch[c];
    if (ch->words == 0) block_start(c);
    if (!ch->on) return;
    ch->word = ard16(ch->ptr);
    ch->ptr += 2;
    ch->words--;
}

static void next_byte(int c)
{
    Channel *ch = &p.ch[c];
    if (ch->byte == 0) {
        ch->out = (s8)(ch->word >> 8);
        ch->byte = 1;
    } else {
        ch->out = (s8)ch->word;
        ch->byte = 0;
    }
    ch->left += ch->per < 124 ? 124 : ch->per;
}

static void dma_on(int c)
{
    Channel *ch = &p.ch[c];
    ch->on = true;
    ch->words = 0;
    fetch(c);
    ch->byte = 0;
    ch->left = 0;
    next_byte(c);
}

void paula_write(u32 addr, u16 v, int size)
{
    (void)size;
    if (addr >= 0xDFF0A0u && addr < 0xDFF0E0u) {
        Channel *ch = &p.ch[(addr - 0xDFF0A0u) >> 4];
        switch (addr & 0x0F) {
        case 0x0: ch->lc = (ch->lc & 0xFFFFu) | (u32)v << 16; break;
        case 0x2: ch->lc = (ch->lc & 0xFFFF0000u) | v; break;
        case 0x4: ch->len = v; break;
        case 0x6: ch->per = v; break;
        case 0x8: ch->vol = v > 64 ? 64 : v; break;
        default: break;
        }
        return;
    }
    switch (addr) {
    case 0xDFF096:                                  /* DMACON */
        for (int c = 0; c < 4; c++) {
            if (!(v & (1u << c))) continue;
            if (v & 0x8000) {
                if (!p.ch[c].on) dma_on(c);
            } else {
                p.ch[c].on = false;
                p.ch[c].out = 0;
            }
        }
        break;
    case 0xDFF09A:                                  /* INTENA */
        if (v & 0x8000) p.intena |= v & 0x7FFF;
        else p.intena &= (u16)~v;
        break;
    case 0xDFF09C:                                  /* INTREQ */
        if (v & 0x8000) p.intreq |= v & 0x7FFF;
        else p.intreq &= (u16)~v;
        break;
    case 0xBFE401: p.counter_lo = v & 0xFF; break;  /* timer A low and high latch */
    case 0xBFE501: p.counter_hi = v & 0xFF; break;
    case 0xBFEE01:                                  /* CRA: bit 4 loads the latch, bit 0 runs */
        if (v & 0x10) {
            p.latch = (u16)(p.counter_hi << 8 | p.counter_lo);
            p.timer_left = (p.latch + 1.0) * (PAULA_CLOCK / CIA_ECLOCK);
        }
        if ((v & 1) && !p.timer_on && p.timer_left <= 0)
            p.timer_left = (p.latch + 1.0) * (PAULA_CLOCK / CIA_ECLOCK);
        p.timer_on = v & 1;
        break;
    default:
        break;
    }
}

void paula_render(s16 *out, int n)
{
    for (int i = 0; i < n; i++) {
        double span = p.clocks_per_sample, acc = 0;
        while (span > 0) {
            double step = span;
            if (p.timer_on && p.timer_left < step) step = p.timer_left > 0 ? p.timer_left : 0;
            if (p.vblank && p.vblank_left < step) step = p.vblank_left > 0 ? p.vblank_left : 0;
            for (int c = 0; c < 4; c++)
                if (p.ch[c].on && p.ch[c].left < step) step = p.ch[c].left > 0 ? p.ch[c].left : 0;
            for (int c = 0; c < 4; c++) {
                Channel *ch = &p.ch[c];
                if (!ch->on) continue;
                acc += (double)ch->out * ch->vol * step;
                ch->left -= step;
                if (ch->left <= 1e-9) {
                    if (ch->byte == 0) fetch(c);
                    if (ch->on) next_byte(c);
                }
            }
            span -= step;
            if (p.timer_on) {
                p.timer_left -= step;
                if (p.timer_left <= 1e-9) {
                    p.timer_left += (p.latch + 1.0) * (PAULA_CLOCK / CIA_ECLOCK);
                    if (p.timer) p.timer();
                }
            }
            if (p.vblank) {
                p.vblank_left -= step;
                if (p.vblank_left <= 1e-9) {
                    p.vblank_left += PAULA_FRAME;
                    p.vblank();
                }
            }
            if (step == 0 && span > 0) continue;
        }
        /* 4 channels x 127 x 64 at most: scale to about half of full range */
        float s = (float)(acc / p.clocks_per_sample) * (32767.0f / (4 * 128 * 64)) * 1.6f;
        p.lp += p.lp_k * (s - p.lp);
        float o = p.lp;
        out[i] = (s16)(o > 32767 ? 32767 : o < -32768 ? -32768 : o);
    }
}
