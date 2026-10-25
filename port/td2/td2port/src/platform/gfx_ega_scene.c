/* EGA backend: the scene renderer's own pixel writers (gfx_backend.h SceneRaster). They are the
 * scene code of TD2EGA.EXE that writes the view buffer's four planes itself, moved here from
 * game/scene*.c unchanged. The view buffers are off-screen, so their planes are RAM in mem[]. */
#include "gfx_ega.h"

/* The view buffer's plane 4 with five planes (the Amiga backend), else 0. The game's colours have no
 * fifth bit, so the scene clears it wherever it draws. With Amiga colours (the race in its Amiga form)
 * each colour draws the pen the view's colour map gives it instead. */
static u16 plane4_seg;
static bool mapped;
static u8 pen_of[16];

/* Writes pen into plane byte b of the five planes, under mask m. */
static void put_pen(u16 b, u8 m, u8 pen)
{
    for (int k = 0; k < 4; k++) {
        u8 *p = mp(DSW((u16)(DS_plane_seg + 2 * k)), b);
        *p = (u8)(pen >> k & 1 ? *p | m : *p & ~m);
    }
    u8 *p = mp(plane4_seg, b);
    *p = (u8)(pen >> 4 & 1 ? *p | m : *p & ~m);
}

/* draw_front / draw_mirror (06c9:00e7 / 1f99): the selected target's plane segments to DS:5420..5426 */
static void ega_view_begin(void)
{
    for (int k = 0; k < 4; k++)
        DSW((u16)(DS_plane_seg + 2 * k)) = CSW((u16)(GFX_CUR_PLANE0 + 2 * k));
    plane4_seg = gfx_ega.planes == 5 ? ram_plane(4) : 0;
    mapped = false;
    for (u16 c = 0; plane4_seg && c < 16; c++) {
        pen_of[c] = gfx_amiga_colour(c);
        mapped = mapped || pen_of[c] != c;
    }
}

/* 06c9:0c17 span_fill_to: fills the current scanline (row offset *di in the cached plane segments
 * DS:5420..5426) from span_x to end - 1, the last byte to its end. Returns true when the original jumps
 * to [DS:0702] (scanline full), i.e. the caller continues with the next scanline. */
static bool ega_span_to(u16 *di, s16 end, u16 colour, bool odd_row)
{
    (void)odd_row;
    s16 dx = DSS(DS_span_x);
    if (end <= dx) return false;
    dx = (s16)(dx >> 3);
    DSS(DS_span_x) = end;
    u16 c = colour & 0xF;
    u8 p[4];
    for (int k = 0; k < 4; k++) {
        p[k] = DSB((u16)(DS_colour_plane_tables + 0x10 * k + c));
        DSB((u16)(0x08AE + k)) = p[k];                    /* scratch bytes DS:08AE..08B1 */
    }
    s16 e = (s16)(end - 1);
    u16 ebit = (u16)(e & 7);
    s16 eb = (s16)(e >> 3);
    u8 cnt = (u8)(eb - dx);                                /* xor ch,ch */
    u8 m = DSB((u16)(DS_mask_from_bit + DSW(DS_span_bit)));
    if (mapped) {                                          /* PORT: the Amiga colours */
        u8 pen = colour >= AMIGA_PEN(0) && colour < AMIGA_PEN(32) ? (u8)(colour - AMIGA_PEN(0)) : pen_of[c];
        put_pen(*di, m, pen);
        for (u16 n = 1; n <= cnt; n++) put_pen((u16)(*di + n), 0xFF, pen);
        *di = (u16)(*di + cnt);
        goto end;
    }
    for (int k = 0; k < 4; k++) {
        u16 seg = DSW((u16)(DS_plane_seg + 2 * k));
        u8 *b = mp(seg, *di);
        *b = (u8)((*b & (u8)~m) | (p[k] & m));
    }
    if (plane4_seg) mp(plane4_seg, *di)[0] &= (u8)~m;
    if (cnt != 0) {
        *di = (u16)(*di + 1);
        for (int k = 0; k < 4; k++) {
            u16 seg = DSW((u16)(DS_plane_seg + 2 * k));
            for (u16 n = 0; n < cnt; n++) wr8(seg, (u16)(*di + n), p[k]);
        }
        if (plane4_seg)
            for (u16 n = 0; n < cnt; n++) wr8(plane4_seg, (u16)(*di + n), 0);
        *di = (u16)(*di + cnt - 1);
    }
end:;
    u16 sb = (u16)(ebit + 1);
    DSW(DS_span_bit) = sb;
    if (sb == 8) {
        DSW(DS_span_bit) = 0;
        *di = (u16)(*di + 1);
        if (DSW(DS_span_x) == DSW(DS_view_width)) return true;   /* jmp [DS:0702] */
    }
    return false;
}

/* 06c9:0d01 hline: DX = x0, AX = x1, DI = y, BX = colour */
static void ega_hline(s16 x0, s16 x1, s16 y, u16 colour)
{
    if (x0 < x1) gfx_draw_line(x0, y, x1, y, colour);
}

/* road markings (06c9:0d97 / 29dc): the centre dot is colour 14 (plane 0 cleared), lane lines 15 */
static void ega_marking(u16 di, s16 x, bool centre)
{
    u16 bx = (u16)(di + (u16)(x >> 3));
    u8 m = DSB((u16)(DS_pixel_mask + (x & 7)));
    if (mapped) {                                          /* PORT: the Amiga colours */
        put_pen(bx, m, pen_of[centre ? 14 : 15]);
        return;
    }
    if (centre) {
        mp(DSW(DS_plane_seg), bx)[0] &= (u8)~m;
        mp(DSW(DS_plane_seg + 2), bx)[0] |= m;
        mp(DSW(DS_plane_seg + 4), bx)[0] |= m;
        mp(DSW(DS_plane_seg + 6), bx)[0] |= m;
    } else {
        for (int k = 0; k < 4; k++) mp(DSW((u16)(DS_plane_seg + 2 * k)), bx)[0] |= m;
    }
    if (plane4_seg) mp(plane4_seg, bx)[0] &= (u8)~m;
}

/* crash_sequence (06c9:3532): the flash palette on even frames, the normal one on odd frames */
static void ega_crash_flash(bool flash)
{
    gfx_set_palette(flash ? DS_pal_flash : DS_pal_normal);
}

const SceneRaster ega_scene_raster = {
    .view_begin = ega_view_begin,
    .span_to = ega_span_to,
    .hline = ega_hline,
    .marking = ega_marking,
    .crash_flash = ega_crash_flash,
};
