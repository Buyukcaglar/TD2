/* CGA backend: the scene renderer's own pixel writers (gfx_backend.h SceneRaster), transcribed from
 * TD2CGA.EXE. Colours are pattern words; odd rows rotate them by one pixel, which turns 8888h-style
 * patterns into checkerboards. The ground span state keeps the EGA build's DS words (span x, and the
 * pixel within the byte, here 0..3). */
#include "gfx_cga.h"
#include "../host.h"

static u16 view_seg;            /* TD2CGA DS:09B4 / DS:295E: the view buffer's segment */

static const u8 from_px[4] = { 0xFF, 0x3F, 0x0F, 0x03 };          /* DS:531C */
static const u8 keep_l[4]  = { 0x00, 0xC0, 0xF0, 0xFC };          /* DS:5320 */
static const u8 upto_px[4] = { 0xC0, 0xF0, 0xFC, 0xFF };          /* DS:5324: pixels 0..k */
static const u8 keep_r[4]  = { 0x3F, 0x0F, 0x03, 0x00 };          /* DS:5328 */
static const u8 one_px[4]  = { 0xC0, 0x30, 0x0C, 0x03 };          /* DS:532C: pixel k, colour 3 */

static inline u16 ror16(u16 v, unsigned n) { return (u16)(v >> n | v << (16 - n)); }

static void cga_view_begin(void)
{
    view_seg = CUR_PLANE(0);
}

/* 06cf:0c1c span_fill_to: fills the ground row at *di from DS_span_x to end - 1 with the pattern's
 * low byte (the word rotated by 2 bits on odd rows). */
static bool cga_span_to(u16 *di, s16 end, u16 colour, bool odd_row)
{
    s16 dx = DSS(DS_span_x);
    if (end == dx) return false;                                   /* je: TD2CGA tests only equality */
    if (odd_row) colour = ror16(colour, 2);
    dx = (s16)(dx >> 2);
    DSS(DS_span_x) = end;
    u8 pat = (u8)colour;
    s16 e = (s16)(end - 1);
    u16 ebit = (u16)(e & 3);
    s16 cnt = (s16)((s16)(e >> 2) - dx);
    u8 m = from_px[DSW(DS_span_bit) & 3];
    u8 *p = mp(view_seg, *di);
    *p = (u8)((*p & (u8)~m) | (pat & m));
    /* PORT: a span ending before the current x would make rep stosb run ~64K bytes; never with the
     * shipped data (the spans are ordered), so nothing is written. */
    if (cnt > 0) {
        *di = (u16)(*di + 1);
        for (s16 n = 0; n < cnt; n++) wr8(view_seg, (u16)(*di + (u16)n), pat);
        *di = (u16)(*di + (u16)cnt - 1);
    }
    u16 sb = (u16)(ebit + 1);
    DSW(DS_span_bit) = sb;
    if ((u8)sb == 4) {
        *di = (u16)(*di + 1);
        DSW(DS_span_bit) = 0;
        if (DSW(DS_span_x) == DSW(DS_view_width)) return true;   /* jmp [DS:0702] */
    }
    return false;
}

/* 06cf:0c8e hline: row y from x0 to x1 - 1, no clipping, with the colour's high byte (rotated by 2
 * bits on odd rows). A span inside one byte also clears that byte's pixels after it, as the
 * original's masks combine. */
static void cga_hline(s16 x0, s16 x1, s16 y, u16 colour)
{
    if (x0 >= x1) return;
    u8 bh = (u8)(colour >> 8);
    if (y & 1) bh = ror8(bh, 2);
    u16 bp = (u16)x0 & 3;
    s16 dx = (s16)(x0 >> 2);
    u16 di = (u16)(row_at((u16)y) + (u16)dx);
    s16 ax = (s16)(x1 - 1);
    u16 bx = (u16)ax & 3;
    ax = (s16)(ax >> 2);
    s16 cx = (s16)(ax - dx);
    u8 *p = mp(view_seg, di);
    *p &= keep_l[bp];
    u8 al = (u8)((from_px[bp] & bh) | *p);
    if (--cx >= 0) {
        *p = al;
        di++;
        al = bh;
        for (s16 n = 0; n < cx; n++) wr8(view_seg, di++, al);
        p = mp(view_seg, di);
    }
    *p &= keep_r[bx];
    *p |= (u8)(al & upto_px[bx]);
}

/* road markings (06cf:0d71..0dec): white pixels, ORed */
static void cga_marking(u16 di, s16 x, bool centre)
{
    (void)centre;
    u8 *p = mp(view_seg, (u16)(di + (u16)(x >> 2)));
    *p |= one_px[x & 3];
}

/* crash_sequence (06cf:3505): colour select 0 (dim) on even frames, 30h on odd ones */
static void cga_crash_flash(bool flash)
{
    gfx_cga.colour_sel = flash ? 0x00 : 0x30;
    gfx_cga.dirty = true;
}

const SceneRaster cga_scene_raster = {
    .view_begin = cga_view_begin,
    .span_to = cga_span_to,
    .hline = cga_hline,
    .marking = cga_marking,
    .crash_flash = cga_crash_flash,
};
