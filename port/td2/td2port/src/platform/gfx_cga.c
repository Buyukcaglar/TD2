/* CGA graphics backend — the pixel routines of the TD2CGA.EXE assembly graphics library in segment
 * 06cf (docs/cga.md). The shared half of the library is in gfx.c (gfx_backend.h describes the split).
 *
 * Every routine is transcribed from the TD2CGA disassembly; the comments give its address. The CGA
 * build keeps its target state at its own code-segment addresses (live copy CS:913E, screen descriptor
 * CS:9158, row pool CS:93D6); the port keeps the same 13-word layout at the EGA build's addresses
 * (gfx.h), so the game code reads and pokes it in one place. The sprite blitters are in gfx_cga_blit.c,
 * the scene renderer's own pixel writers in gfx_cga_scene.c. */
#include "gfx_cga.h"
#include "res.h"
#include "../host.h"

#include <string.h>

CgaState gfx_cga;

/* Masks of the 2-bit pixels, leftmost pixel in the top bits (TD2CGA keeps these as small tables). */
static const u8 from_px[4] = { 0xFF, 0x3F, 0x0F, 0x03 };   /* pixels k..3   (DS:66D8 is this with 0 at k=0) */
static const u8 upto_px[4] = { 0x00, 0xC0, 0xF0, 0xFC };   /* pixels 0..k-1 (DS:66DC, CS:80A6) */
static const u8 px_mask[4] = { 0xC0, 0x30, 0x0C, 0x03 };   /* pixel k       (CS:80AA) */

/* ------------------------------------------------------------------------------------------------ */
/* Port setup / presentation                                                                        */

/* The CGA screen descriptor and its interleaved row table (TD2CGA CS:9158 and CS:9172), written at
 * the EGA build's places (CS:AF54, CS:AF6E), and the live copy CS:AF3A selecting the screen. */
static void cga_screen_desc(void)
{
    static const u16 desc[GFX_DESC_WORDS] = {
        0, CGA_SEG, 0, 0, 0, CS_gfx_screen_rows, 0, 80, 0, 200, 80, 0, 320
    };
    for (u16 i = 0; i < GFX_DESC_WORDS; i++) {
        CSW((u16)(GFX_SCREEN_DESC_OFF + 2 * i)) = desc[i];
        CSW((u16)(GFX_CUR_OFF + 2 * i)) = desc[i];
    }
    for (u16 y = 0; y < 200; y++)
        CSW((u16)(CS_gfx_screen_rows + 2 * y)) = (u16)((y & 1) * 0x2000 + (y >> 1) * 80);
}

static void cga_reset(void)
{
    memset(mp(CGA_SEG, 0), 0, CGA_BYTES);
    memset(gfx_cga.shown, 0, sizeof gfx_cga.shown);
    gfx_cga.mode_ctrl = 0x29;                                      /* BIOS text mode 3 */
    gfx_cga.colour_sel = 0x30;
    gfx_cga.dirty = true;
    cga_screen_desc();
}

/* The 16 RGBI colours of a CGA monitor (colour 6 is brown). */
static const u32 rgbi[16] = {
    0x000000, 0x0000AA, 0x00AA00, 0x00AAAA, 0xAA0000, 0xAA00AA, 0xAA5500, 0xAAAAAA,
    0x555555, 0x5555FF, 0x55FF55, 0x55FFFF, 0xFF5555, 0xFF55FF, 0xFFFF55, 0xFFFFFF,
};

static bool cga_compose(u32 *xrgb)
{
    const u8 *v = mp(CGA_SEG, 0);
    if (!gfx_cga.dirty && memcmp(v, gfx_cga.shown, CGA_BYTES) == 0) return false;
    memcpy(gfx_cga.shown, v, CGA_BYTES);
    gfx_cga.dirty = false;
    u8 sel = gfx_cga.colour_sel, hi = (u8)((sel & 0x10) ? 8 : 0);
    u32 pal[4];
    pal[0] = rgbi[sel & 0x0F];
    if (gfx_cga.mode_ctrl & 4) {                                   /* black-and-white bit: cyan, red, white */
        pal[1] = rgbi[3 + hi]; pal[2] = rgbi[4 + hi]; pal[3] = rgbi[7 + hi];
    } else if (sel & 0x20) {                                       /* palette 1: cyan, magenta, white */
        pal[1] = rgbi[3 + hi]; pal[2] = rgbi[5 + hi]; pal[3] = rgbi[7 + hi];
    } else {                                                       /* palette 0: green, red, brown */
        pal[1] = rgbi[2 + hi]; pal[2] = rgbi[4 + hi]; pal[3] = rgbi[6 + hi];
    }
    bool on = (gfx_cga.mode_ctrl & 0x0A) == 0x0A;                  /* graphics mode, video enabled */
    for (int y = 0; y < 200; y++) {
        const u8 *row = v + (y & 1) * 0x2000 + (y >> 1) * 80;
        for (int bx = 0; bx < 80; bx++) {
            u8 b = row[bx];
            for (int k = 0; k < 4; k++)
                xrgb[y * 320 + bx * 4 + k] = on ? pal[b >> (6 - 2 * k) & 3] : 0;
        }
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------ */
/* Video mode, palette                                                                              */

static void bios_equipment(u16 bits)
{
    /* PORT: BIOS data area 0040:0010 is not part of the port's memory model; the write is dropped. */
    (void)bits;
}

/* INT 10h AH=0Bh: BH=0 sets the background and intensity (bits 0-4), BH=1 the palette (bit 5). */
static void bios_colour(u8 bh, u8 bl)
{
    if (bh == 0) gfx_cga.colour_sel = (u8)((gfx_cga.colour_sel & 0xE0) | (bl & 0x1F));
    else gfx_cga.colour_sel = (u8)((gfx_cga.colour_sel & ~0x20) | (bl & 1) << 5);
    gfx_cga.dirty = true;
}

/* 06cf:5c18 gfx_video_hook: mode control 0Eh (graphics, black-and-white bit, video on), colour select
 * 30h (palette 1, bright, black background). */
static void cga_video_hook(void)
{
    gfx_cga.mode_ctrl = 0x0E;
    gfx_cga.colour_sel = 0x30;
    gfx_cga.dirty = true;
}

/* 06cf:907c gfx_set_palette: INT 10h AH=0Bh BH=1, BL = the argument's low byte (palette select). */
static void cga_set_palette(u16 arg)
{
    bios_colour(1, (u8)arg);
}

static void cga_clear_screen(u16 colour);

/* 06cf:8854 gfx_init_ega (CGA: mode 4) */
static void cga_set_mode(void)
{
    cga_clear_screen(0);
    bios_equipment(0x10);
    /* INT 10h AX=0004h clears video memory; mode control 2Ah, colour select 30h. */
    memset(mp(CGA_SEG, 0), 0, CGA_BYTES);
    gfx_cga.mode_ctrl = 0x2A;
    gfx_cga.colour_sel = 0x30;
    bios_colour(1, 1);
    bios_colour(0, 0);
}

/* 06cf:6350 gfx_shutdown */
static void cga_shutdown(void)
{
    cga_clear_screen(0);
    bios_equipment(0x10);
    /* PORT: INT 10h AX=0003h (text mode) has no host equivalent; modelled as the text mode register
     * value, which composes as a black screen. */
    gfx_cga.mode_ctrl = 0x29;
    bios_colour(0, 0);
}

/* ------------------------------------------------------------------------------------------------ */
/* Buffers, clears and fills                                                                        */

/* 06cf:9302 gfx_create_buffer: one 2-bit block of width_px/4 bytes per row (the plane mask is unused) */
static FarPtr cga_create_buffer(u16 width_px, u16 h, u16 plane_mask)
{
    (void)plane_mask;
    u16 w = (u16)(width_px >> 2);                                  /* bp-08 */
    u16 paras = (u16)((u16)((u16)(w * h) + 0x10) >> 4) + 1;        /* imul bx: low word */
    FarPtr blkp = mem_reserve(DS_s_window, paras);                /* "WINDOW"; DX (segment) is used */
    u16 seg = blkp.seg;
    wr16(seg, 0, w);
    wr16(seg, 2, h);
    wr16(seg, 8, 0); wr16(seg, 0x0A, 0); wr16(seg, 4, 0); wr16(seg, 6, 0);

    u16 bx = CSW(CS_gfx_rowpool_top);                              /* bp-04 */
    u16 next = (u16)(((u16)(h + 0x0D) << 1) + bx);
    if (next >= 0xBA3B) fatal("%s", (const char *)mp(DGROUP, 0x68B7));   /* "OUT OF ROW TABLE SPACE" */
    CSW(CS_gfx_rowpool_top) = next;
    CSW(bx) = 0;
    CSW((u16)(bx + 2)) = seg;
    CSW((u16)(bx + 0x0A)) = (u16)(bx + 0x1A);
    CSW((u16)(bx + 0x0C)) = 0;
    CSW((u16)(bx + 0x0E)) = w;
    CSW((u16)(bx + 0x14)) = w;
    CSW((u16)(bx + 0x10)) = 0;
    CSW((u16)(bx + 0x12)) = h;
    CSW((u16)(bx + 0x18)) = width_px;
    u16 cnt = h, off = 0x10, b = bx;
    do {                                                           /* loop: h == 0 -> 65536 */
        CSW((u16)(b + 0x1A)) = off;
        b = (u16)(b + 2);
        off = (u16)(off + w);
    } while (--cnt);
    return far_make(ASM_SEG, bx);
}

/* 06cf:8032 gfx_clear_screen: the colour word over both halves of B800h */
static void cga_clear_screen(u16 colour)
{
    for (u16 i = 0; i < 0xFA0; i++) {
        wr16(CGA_SEG, (u16)(2 * i), colour);
        wr16(CGA_SEG, (u16)(0x2000 + 2 * i), colour);
    }
}

/* 06cf:8052 gfx_clear_clip: the clip rectangle, even rows with the colour's high byte, odd rows with
 * its low byte */
static void cga_clear_clip(u16 colour)
{
    u16 seg = CUR_PLANE(0);
    u16 rows = (u16)(CUR_Y1 - CUR_Y0);
    u16 y = CUR_Y0;
    u16 x0 = CUR_X0, cols = (u16)(CUR_X1 - CUR_X0);
    u8 al = (u8)colour, ah = (u8)(colour >> 8);
    if (!(y & 1)) { u8 t = al; al = ah; ah = t; }
    u16 bx = (u16)(y * 2 + CUR_ROWTAB);
    do {
        u16 di = (u16)(CSW(bx) + x0);
        for (u16 n = 0; n < cols; n++) wr8(seg, (u16)(di + n), al);
        u8 t = al; al = ah; ah = t;
        bx = (u16)(bx + 2);
    } while (dec_jg(&rows));
}

/* 06cf:8438 gfx_fill_rect: no clipping. The colour word's high byte fills even rows, its low byte odd
 * rows. Left partial byte (L), whole bytes (M) and right partial byte (R) are cases of a jump table. */
static void cga_fill_rect(s16 x, s16 y, s16 w, s16 h, u16 colour)
{
    if (w <= 0 || h <= 0) return;
    u16 seg = CUR_PLANE(0);
    u16 col = (u16)(x >> 2);                                       /* bp-10 */
    u16 lpat = 0, rpat = 0;                                        /* bp-08, bp-0A */
    u8 lkeep = 0, rkeep = 0;                                       /* bp-05, bp-06 */
    u16 mid = 0;                                                   /* bp-0C */
    int cases = 0;
    u16 bx = (u16)x & 3;
    if (bx) {
        cases |= 8;
        u8 m = bx ? from_px[bx] : 0;
        lpat = (u16)(colour & (u16)(m | m << 8));
        lkeep = (u8)~m;
    }
    u16 e = (u16)(x + w);
    u16 d = (u16)((u16)((s16)e >> 2) - col);
    if (d) { cases |= 4; mid = d; }
    bx = e & 3;
    if (bx) {
        cases |= 2;
        u8 m = upto_px[bx];
        rpat = (u16)(colour & (u16)(m | m << 8));
        rkeep = (u8)~m;
    }
    bool even = !((u16)y & 1);
    u16 rows = (u16)h;
    u16 rt = (u16)((u16)y * 2 + CUR_ROWTAB);
    #define SWAP_IF_EVEN(v) do { if (even) v = (u16)((v) << 8 | (v) >> 8); } while (0)
    #define PARTIAL(pat, keep) do { u8 *p = mp(seg, di); *p = (u8)((*p & (keep)) | (u8)(pat)); \
                                    pat = (u16)((pat) << 8 | (pat) >> 8); } while (0)
    switch (cases) {
    case 0:
        return;
    case 2: case 8: case 10: {                                     /* one partial byte column */
        u16 pat; u8 keep;
        if (cases == 2) { pat = rpat; keep = rkeep; }
        else if (cases == 8) { pat = lpat; keep = lkeep; }
        else {                                                     /* L and R in the same byte */
            pat = (u16)(lpat | rpat);
            keep = (u8)(lkeep | rkeep);
            u8 m = (u8)~keep;
            pat &= (u16)(m | m << 8);
        }
        SWAP_IF_EVEN(pat);
        do {
            u16 di = (u16)(CSW(rt) + col);
            PARTIAL(pat, keep);
            rt = (u16)(rt + 2);
        } while (--rows);
        return;
    }
    case 4: {                                                      /* whole bytes only */
        u16 c = colour;
        SWAP_IF_EVEN(c);
        u8 cur = (u8)c, other = (u8)(c >> 8);
        do {
            u16 di = (u16)(CSW(rt) + col);
            for (u16 n = 0; n < mid; n++) wr8(seg, (u16)(di + n), cur);
            u8 t = cur; cur = other; other = t;
            rt = (u16)(rt + 2);
        } while (dec_jg(&rows));
        return;
    }
    case 6: {                                                      /* whole bytes, then R */
        u16 c = colour;
        SWAP_IF_EVEN(c);
        SWAP_IF_EVEN(rpat);
        u8 cur = (u8)c, other = (u8)(c >> 8);
        do {
            u16 di = (u16)(CSW(rt) + col);
            for (u16 n = 0; n < mid; n++) wr8(seg, di++, cur);
            u8 t = cur; cur = other; other = t;
            PARTIAL(rpat, rkeep);
            rt = (u16)(rt + 2);
        } while (dec_jg(&rows));
        return;
    }
    case 12: case 14: {                                            /* L, whole bytes [, R] */
        mid--;
        if (mid == 0) {
            if (cases == 12) {                                     /* only L */
                u16 pat = lpat;
                SWAP_IF_EVEN(pat);
                do {
                    u16 di = (u16)(CSW(rt) + col);
                    PARTIAL(pat, lkeep);
                    rt = (u16)(rt + 2);
                } while (--rows);
                return;
            }
            SWAP_IF_EVEN(lpat);                                    /* L and R in adjacent bytes */
            SWAP_IF_EVEN(rpat);
            do {
                u16 di = (u16)(CSW(rt) + col);
                PARTIAL(lpat, lkeep);
                di++;
                PARTIAL(rpat, rkeep);
                rt = (u16)(rt + 2);
            } while (--rows);
            return;
        }
        u16 c = colour;
        SWAP_IF_EVEN(c);
        SWAP_IF_EVEN(lpat);
        if (cases == 14) SWAP_IF_EVEN(rpat);
        u8 cur = (u8)c, other = (u8)(c >> 8);
        do {
            u16 di = (u16)(CSW(rt) + col);
            PARTIAL(lpat, lkeep);
            di++;
            for (u16 n = 0; n < mid; n++) wr8(seg, di++, cur);
            u8 t = cur; cur = other; other = t;
            if (cases == 14) PARTIAL(rpat, rkeep);
            rt = (u16)(rt + 2);
        } while (dec_jg(&rows));
        return;
    }
    }
    #undef SWAP_IF_EVEN
    #undef PARTIAL
}

/* 06cf:9ba6 gfx_plot: the colour's low byte shifted into place, not masked */
static void cga_plot(s16 x, s16 y, u16 colour)
{
    static const u8 keep[4] = { 0x3F, 0xCF, 0xF3, 0xFC };         /* DS:676E */
    static const u8 shift[4] = { 6, 4, 2, 0 };                     /* DS:6772 */
    u16 bx = (u16)x & 3;
    u16 di = (u16)(((u16)x >> 2) + row_at((u16)y));
    u8 *p = mp(CUR_PLANE(0), di);
    *p = (u8)((u8)((u8)colour << shift[bx]) | (*p & keep[bx]));
}

/* ------------------------------------------------------------------------------------------------ */
/* Lines: 06cf:80ae gfx_draw_line (pixel = colour within its mask) and 06cf:a326 gfx_draw_line_or    */
/* (pixel |= colour). The colour is a pattern byte; the clip rectangle is applied point by point.   */

static void line_px(u16 seg, u16 row, u16 x, u8 colour, bool or_mode)
{
    u8 m = px_mask[x & 3];
    u8 *p = mp(seg, (u16)(row + (x >> 2)));
    *p = or_mode ? (u8)(*p | (colour & m)) : (u8)((*p & (u8)~m) | (colour & m));
}

static void cga_draw_line(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour16, bool or_mode)
{
    u8 colour = (u8)colour16;
    u16 seg = CUR_PLANE(0);
    u16 cx0 = (u16)(CUR_X0 << 2), cx1 = (u16)(CUR_X1 << 2);        /* bp-0E, bp-10 */
    u16 X0 = (u16)x0, Y0 = (u16)y0, X1 = (u16)x1, Y1 = (u16)y1;
    if (Y0 == Y1) {                                                /* horizontal */
        if (slt(Y0, CUR_Y0) || !slt(Y0, CUR_Y1)) return;
        u16 di = row_at(Y0);
        u16 cnt = (u16)(X1 - X0), bx;
        if ((s16)cnt < 0) { cnt = (u16)-cnt; bx = X1; } else bx = X0;
        cnt++;
        if (slt(bx, cx0)) {
            cnt = (u16)(cnt + bx - cx0);
            if ((s16)cnt <= 0) return;
            bx = cx0;
        }
        if (!slt(bx, cx1)) return;
        u16 over = (u16)(cnt + bx - cx1);
        if ((s16)over > 0) cnt = (u16)(cnt - over);
        di = (u16)(di + (bx >> 2));
        bx &= 3;
        u8 m = from_px[bx];
        u8 al = (u8)(m & colour);
        u16 left = (u16)(cnt - (u16)(4 - bx));                     /* sub cl ; sbb ch,0 */
        u16 e;
        if ((s16)left < 0) {                                       /* the line ends in its first byte */
            e = (u16)(left + 4);                                   /* = start pixel + length */
        } else {
            u8 *p = mp(seg, di);
            *p = or_mode ? (u8)(*p | al) : (u8)((*p & (u8)~m) | al);
            di++;
            al = colour;
            m = 0xFF;
            e = left & 3;
            for (u16 n = 0; n < (u16)(left >> 2); n++) {
                u8 *q = mp(seg, di++);
                *q = or_mode ? (u8)(*q | al) : al;
            }
        }
        u8 lm = (u8)(m & upto_px[e & 3]);
        u8 *p = mp(seg, di);
        if (or_mode) *p = (u8)(*p | (al & upto_px[e & 3]));
        else *p = (u8)((*p & (u8)~lm) | (al & upto_px[e & 3]));
        return;
    }
    if (X0 == X1) {                                                /* vertical */
        if (sle(X0, cx0) || !slt(X0, cx1)) return;                 /* jle: not on the left clip column */
        u16 cnt = (u16)(Y1 - Y0), si;
        if ((s16)cnt < 0) { cnt = (u16)-cnt; si = Y1; } else si = Y0;
        cnt++;
        if (slt(si, CUR_Y0)) {
            cnt = (u16)(cnt + si - CUR_Y0);
            if ((s16)cnt <= 0) return;
            si = CUR_Y0;
        }
        if (!slt(si, CUR_Y1)) return;
        u16 over = (u16)(cnt + si - CUR_Y1);
        if ((s16)over > 0) cnt = (u16)(cnt - over);
        u16 rt = (u16)(si * 2 + CUR_ROWTAB);
        do {
            line_px(seg, CSW(rt), X0, colour, or_mode);
            rt = (u16)(rt + 2);
        } while (--cnt);
        return;
    }
    /* diagonal: 16.16 fixed-point steps along the major axis, from its lower end */
    u16 dxn = (u16)(X1 - X0), dyn = (u16)(Y1 - Y0);
    bool xneg = false, yneg = false;
    if ((s16)dxn < 0) { dxn = (u16)-dxn; xneg = true; }
    dxn++;
    if ((s16)dyn < 0) { dyn = (u16)-dyn; yneg = true; }
    dyn++;
    if (!slt(dxn, dyn)) {                                          /* x-major */
        u16 x, yi, yf = 0;
        if (xneg) { x = X1; yi = Y1; yneg = !yneg; }
        else { x = X0; yi = Y0; }
        u32 step;
        if (dxn == dyn) step = yneg ? 0xFFFF0000u : 0x00010000u;
        else {
            u16 q = (u16)(((u32)dyn << 16) / dxn);
            if (yneg) { step = (u32)(0xFFFF0000u | (u16)-q); yf = 0xFFFF; }
            else step = q;
        }
        u16 cnt = dxn;
        bool drawing = false;
        do {
            if (!drawing) {
                if (!slt(yi, CUR_Y0) && slt(yi, CUR_Y1) && !slt(x, cx0)) {
                    if (!slt(x, cx1)) return;
                    drawing = true;
                }
            }
            if (drawing) {
                if (slt(yi, CUR_Y0) || !slt(yi, CUR_Y1) || !slt(x, cx1)) return;
                line_px(seg, row_at(yi), x, colour, or_mode);
            }
            x++;
            u32 acc = ((u32)yi << 16 | yf) + step;
            yi = (u16)(acc >> 16); yf = (u16)acc;
        } while (--cnt);
    } else {                                                       /* y-major */
        u16 y, xi, xf = 0;
        if (yneg) { xi = X1; y = Y1; xneg = !xneg; }
        else { xi = X0; y = Y0; }
        u16 q = (u16)(((u32)dxn << 16) / dyn);
        u32 step;
        if (xneg) { step = (u32)(0xFFFF0000u | (u16)-q); xf = 0xFFFF; }
        else step = q;
        /* PORT: TD2CGA's gfx_draw_line_or stores the start x of a right-to-left x-major line in the
         * wrong word (bp-04 instead of bp-02); its only caller draws straight lines. */
        u16 cnt = dyn;
        bool drawing = false;
        do {
            if (!drawing) {
                if (!slt(xi, cx0) && slt(xi, cx1) && !slt(y, CUR_Y0)) {
                    if (!slt(y, CUR_Y1)) return;
                    drawing = true;
                }
            }
            if (drawing) {
                if (!slt(y, CUR_Y1) || slt(xi, cx0) || !slt(xi, cx1)) return;
                line_px(seg, row_at(y), xi, colour, or_mode);
            }
            y++;
            u32 acc = ((u32)xi << 16 | xf) + step;
            xi = (u16)(acc >> 16); xf = (u16)acc;
        } while (--cnt);
    }
}

/* ------------------------------------------------------------------------------------------------ */
/* 8x8 text: 06cf:8c45 (body of 06cf:8c2e / 8c45). Each glyph row's bits become 2-bit pixels: the     */
/* foreground colour's pattern where a bit is set, the background's where it is clear. x is byte-   */
/* aligned (x / 4), and the two bytes are written whole.                                            */

static u16 text_pattern(u16 c)
{
    static const u16 pat[4] = { 0x0000, 0x5555, 0xAAAA, 0xFFFF };  /* DS:6736 */
    /* PORT: TD2CGA reads past its 4-entry table for larger values; no caller passes one. */
    return pat[c & 3];
}

static u16 double_bits(u8 b)                                       /* DS:54FA: bit k -> pixel bits 2k, 2k+1 */
{
    u16 v = 0;
    for (int k = 0; k < 8; k++)
        if (b >> k & 1) v = (u16)(v | 3u << (2 * k));
    return v;
}

static void cga_draw_text(const u8 *s)
{
    u16 seg = CUR_PLANE(0);
    if (DSW(DS_text_enabled) != 1) return;
    u16 fg = text_pattern(DSW(DS_text_fg)), bg = text_pattern(DSW(DS_text_bg));
    for (;;) {
        u8 ch = *s;
        if (ch == 0) break;
        s++;
        u16 glyph = DSW((u16)(ch * 2 + DSW(DS_text_font)));
        if (glyph == 0) {
            if (ch == 0x0D || ch == 0x0A) {
                DSW(DS_text_x) = DSW(DS_text_margin_x);
                DSW(DS_text_y) = (u16)(DSW(DS_text_y) + DSW(DS_text_adv_y));
            }
            continue;
        }
        u16 col = (u16)(DSW(DS_text_x) >> 2);
        u16 rt = (u16)(DSW(DS_text_y) * 2 + CUR_ROWTAB);
        u16 cnt = DSW(DS_text_glyph_h);
        do {
            u16 e = double_bits(rd8(DGROUP, glyph++));
            u16 v = (u16)((e & fg) | ((u16)~e & bg));
            u16 di = (u16)(CSW(rt) + col);
            wr8(seg, di, (u8)(v >> 8));                            /* xchg ah,al ; stosw */
            wr8(seg, (u16)(di + 1), (u8)v);
            rt = (u16)(rt + 2);
        } while (--cnt);
        DSW(DS_text_x) = (u16)(DSW(DS_text_x) + DSW(DS_text_adv_x));
    }
}

/* ------------------------------------------------------------------------------------------------ */
/* Dissolves: 06cf:86d4 (4 phases) and 06cf:879e (8 phases). Each call draws the whole sprite at its */
/* own position through a pixel mask: 12 interleaved row groups, the mask chosen by phase + row and  */
/* rotated by one bit per byte.                                                                     */

static void cga_dissolve(FarPtr spr, u8 phase, int phases)
{
    static const u8 order_tab[12] = { 0x0B, 0x05, 0x08, 0x02, 0x0A, 0x04, 0x07, 0x01, 0x09, 0x03, 0x06, 0x00 };
    static const u8 mask4[4] = { 0xC0, 0x0C, 0x30, 0x03 };          /* CS:86D0 */
    static const u8 mask8[8] = { 0x01, 0x08, 0x40, 0x02, 0x10, 0x80, 0x04, 0x20 };   /* CS:8796 */
    u16 seg = CUR_PLANE(0);
    u16 col = (u16)((s16)rd16(spr.seg, (u16)(spr.off + 8)) >> 2);   /* bp-14 */
    u16 w = rd16(spr.seg, spr.off);                                 /* bp-16 */
    u16 skip = (u16)((u8)w * 11);                                   /* mul bl: AL * 11 */
    u16 rt0 = (u16)(rd16(spr.seg, (u16)(spr.off + 0x0A)) * 2 + CUR_ROWTAB);   /* bp-0E */
    u16 rt_end = (u16)(rt0 + 2 * rd16(spr.seg, (u16)(spr.off + 2)));          /* bp-10 */
    u16 data = (u16)(spr.off + 0x10);
    u16 bx = phase;
    for (int g = 11; g >= 0; g--) {
        u8 r = order_tab[g];
        u16 si = (u16)(data + (u16)((u8)w * r));                   /* mul dl */
        u16 rt = (u16)(rt0 + 2 * r);
        while (rt < rt_end) {
            u16 di = (u16)(CSW(rt) + col);
            u8 ah = phases == 4 ? mask4[bx & 3] : mask8[bx & 7];
            for (u16 n = 0; n < w; n++) {
                u8 al = (u8)(rd8(spr.seg, si++) & ah);
                u8 *p = mp(seg, di++);
                *p = (u8)((*p & (u8)~ah) | al);
                ah = ror8(ah, 1);
            }
            bx++;
            rt = (u16)(rt + 0x18);
            si = (u16)(si + skip);
        }
    }
}

/* CGA has no scroll routine: TD2CGA's car_slide builds its picture in a buffer instead. */
static void cga_scroll_window(s16 x, s16 y, s16 w, s16 h, s16 step, FarPtr spr, s16 srow)
{
    (void)x; (void)y; (void)w; (void)h; (void)step; (void)spr; (void)srow;
    host_fatal("gfx_scroll_window: not in the CGA library");
}

/* 06cf:a208 gfx_grab_screen: rows of the screen (B800h through the screen descriptor's row table)
 * into the current target; x and the width in pixels, used as bytes / 4. */
static void cga_grab_screen(s16 sx, s16 sy, s16 dx, s16 dy, s16 w_px, s16 h)
{
    u16 n = (u16)((u16)w_px >> 2);
    u16 srt = (u16)((u16)sy * 2 + CSW(GFX_SCREEN_DESC_OFF + 0x0A));
    u16 drt = (u16)((u16)dy * 2 + CUR_ROWTAB);
    u16 seg = CUR_PLANE(0);
    u16 scol = (u16)(sx >> 2), dcol = (u16)(dx >> 2);
    u16 rows = (u16)h;
    do {
        u16 si = (u16)(CSW(srt) + scol), di = (u16)(CSW(drt) + dcol);
        for (u16 k = 0; k < n; k++) wr8(seg, (u16)(di + k), rd8(CGA_SEG, (u16)(si + k)));
        srt = (u16)(srt + 2);
        drt = (u16)(drt + 2);
    } while (dec_jg(&rows));
}

/* 06cf:90f0 (body of grab_into_sprite_*): the current target's rows into the sprite's data */
static void cga_grab_into_sprite(FarPtr spr, u16 px, u16 py)
{
    u16 w = rd16(spr.seg, spr.off), rows = rd16(spr.seg, (u16)(spr.off + 2));
    u16 rt = (u16)(py * 2 + CUR_ROWTAB);
    u16 seg = CUR_PLANE(0);
    u16 col = (u16)((s16)px >> 2);
    u16 di = (u16)(spr.off + 0x10);
    do {
        u16 si = (u16)(CSW(rt) + col);
        for (u16 k = 0; k < w; k++) wr8(spr.seg, di++, rd8(seg, (u16)(si + k)));
        rt = (u16)(rt + 2);
    } while (dec_jg(&rows));
}

/* draw_cursor_glyph's glyphs (TD2CGA CS:A280): sprites of 2 bytes by 8 rows whose last 1, 2 or 6
 * rows are white, built in a spare segment above video memory. */
#define CGA_GLYPH_SEG 0xBC00

static FarPtr cga_cursor_glyph(u16 idx)
{
    static const u8 which[9] = { 0, 0, 1, 1, 1, 1, 1, 1, 2 };     /* A292 A292 A2B2 x6 A2D2 */
    static bool made;
    if (!made) {
        for (u16 g = 0; g < 3; g++) {
            u16 o = (u16)(g * 0x20);
            wr16(CGA_GLYPH_SEG, o, 2);
            wr16(CGA_GLYPH_SEG, (u16)(o + 2), 8);
            for (u16 k = 4; k < 0x20; k++) wr8(CGA_GLYPH_SEG, (u16)(o + k), 0);
        }
        for (u16 k = 0x1E; k < 0x20; k++) wr8(CGA_GLYPH_SEG, k, 0xFF);                  /* last row */
        for (u16 k = 0x3C; k < 0x40; k++) wr8(CGA_GLYPH_SEG, k, 0xFF);                  /* last 2 rows */
        for (u16 k = 0x54; k < 0x60; k++) wr8(CGA_GLYPH_SEG, k, 0xFF);                  /* last 6 rows */
        made = true;
    }
    return far_make(CGA_GLYPH_SEG, (u16)(which[idx < 9 ? idx : 8] * 0x20));
}

const GfxBackend gfx_cga_backend = {
    .name = "CGA",
    .adapter = GFX_CGA,
    .frame_w = 320,
    .frame_h = 200,
    .px_per_byte = 4,
    .own_x_mask = 0xFFFC,
    .shape_ext = { ".PCS", ".CSH" },
    .fixup_paras = 0x3EA,
    .fix_sprites = res_fix_pcs_archive,
    .cursor_glyph = cga_cursor_glyph,
    .scene = &cga_scene_raster,
    .reset = cga_reset,
    .compose = cga_compose,
    .video_hook = cga_video_hook,
    .set_mode = cga_set_mode,
    .shutdown = cga_shutdown,
    .set_palette = cga_set_palette,
    .create_buffer = cga_create_buffer,
    .clear_screen = cga_clear_screen,
    .clear_clip = cga_clear_clip,
    .fill_rect = cga_fill_rect,
    .plot = cga_plot,
    .draw_line = cga_draw_line,
    .draw_text = cga_draw_text,
    .dissolve = cga_dissolve,
    .scroll_window = cga_scroll_window,
    .grab_screen = cga_grab_screen,
    .grab_into_sprite = cga_grab_into_sprite,
    .blit = cga_blit,
};
