/* PORT: the Amiga screen changes (docs/amiga.md, "Screen changes"): duel's wipes, drawn into the Amiga
 * graphics' wipe mask (gfx_amiga_wipe_*). Each routine is the shape duel draws at each step; after each
 * step duel copies the new picture (or black) through the mask, shows it and waits for the vertical
 * blank. Width 320, height 200, the centre (160, 100). */
#include "flow.h"
#include "../host.h"
#include "../platform/gfx.h"
#include "../platform/timer.h"

#define W 320
#define H 200
#define CX (W / 2)
#define CY (H / 2)
/* NTSC frames per step: the masked copy of five planes takes the blitter more than a frame, so each
 * wait for the vertical blank ends in the second (an estimate). */
#define STEP_FRAMES 2

static u32 wipe_t0, wipe_frames;

static void step(u32 frames)
{
    gfx_amiga_wipe_show();
    host_present_now();
    wipe_frames += frames;
    while (ticks_get() - wipe_t0 < amiga_ticks(wipe_frames)) host_pump();
}

/* $10e46: a filled circle, as horizontal spans from the midpoint walk (transcribed). */
static void disk(s16 r)
{
    s16 x = 0, y = r, d = (s16)((1 - r) * 2);
    for (;;) {
        gfx_amiga_wipe_rect((s16)(CX - x), (s16)(CY - y), (s16)(CX + x), (s16)(CY - y));
        gfx_amiga_wipe_rect((s16)(CX - x), (s16)(CY + y), (s16)(CX + x), (s16)(CY + y));
        if (y < 0) return;
        if (d < 0 && 2 * (d + y) - 1 <= 0) {           /* across */
            x++;
            d = (s16)(d + 2 * (x + 1));
        } else if (d == 0 || (d > 0 && 2 * (d - x) - 1 <= 0)) {   /* diagonal */
            x++;
            y--;
            d = (s16)(d + 2 * (x - y) + 2);
        } else {                                        /* down */
            y--;
            d = (s16)(d - 2 * y + 1);
        }
    }
}

static void wipe(AmigaWipe kind, bool in, bool clear, s16 a, s16 b)
{
    if (!gfx_amiga_screens()) return;
    gfx_amiga_wipe_begin(flow_page_desc(), in, clear);
    select_screen();
    wipe_t0 = ticks_get();
    wipe_frames = 0;
    switch (kind) {
    case WIPE_BOX:                                      /* $10fde: a box from the centre */
        for (s16 r = a; r <= CX + a; r = (s16)(r + a)) {
            s16 rr = (s16)(H * r / W);
            gfx_amiga_wipe_rect((s16)(CX - r), (s16)(CY - rr), (s16)(CX + r), (s16)(CY + rr));
            step(STEP_FRAMES);
        }
        break;
    case WIPE_BARS: {                                   /* $11062: a frame closing in from the edges */
        s16 px = 0, py = 0;
        for (s16 r = a; r <= CX + a; r = (s16)(r + a)) {
            s16 rr = (s16)(H * r / W);
            gfx_amiga_wipe_rect(px, py, (s16)(W - px), rr);
            gfx_amiga_wipe_rect(px, (s16)(H - rr), (s16)(W - px), (s16)(H - py));
            gfx_amiga_wipe_rect(px, rr, r, (s16)(H - rr));
            gfx_amiga_wipe_rect((s16)(W - r), rr, (s16)(W - px), (s16)(H - rr));
            step(STEP_FRAMES);
            px = r;
            py = rr;
        }
        break;
    }
    case WIPE_CIRCLE:                                   /* $1115e: a circle from the centre */
        for (s16 r = a; (s32)(r - a) * (r - a) <= (s32)CX * CX + (s32)CY * CY; r = (s16)(r + a)) {
            disk(r);
            step(STEP_FRAMES);
        }
        break;
    case WIPE_SWEEP:                                    /* $111d2: lines from the centre, round the edges */
        for (int side = 0; side < 4; side++) {
            s16 n = side % 2 ? H : W;
            for (s16 i = 0; i < n; i = (s16)(i + a)) {
                for (s16 j = i; j < i + a && j < n; j++) {
                    s16 x = side == 0 ? j : side == 1 ? W - 1 : side == 2 ? (s16)(W - 1 - j) : 0;
                    s16 y = side == 0 ? 0 : side == 1 ? j : side == 2 ? H - 1 : (s16)(H - 1 - j);
                    gfx_amiga_wipe_line(CX, CY, x, y);
                }
                step(STEP_FRAMES);
            }
        }
        break;
    case WIPE_BANDS:                                    /* $1136c: a checker of a x b cells, in strips */
        for (s16 pass = 0; pass < 2; pass++)
            for (s16 y = 0; y < H; y = (s16)(y + b / 4)) {
                for (s16 x = 0; x < W; x = (s16)(x + 2 * a)) {
                    s16 xx = (y / b) & 1 ? (s16)(x + a - pass * a) : (s16)(pass * a + x);
                    gfx_amiga_wipe_rect(xx, y, (s16)(xx + a - 1), (s16)(y + b / 4 - 1));
                }
                step(STEP_FRAMES);
            }
        break;
    case WIPE_CHECKS:                                   /* $11434: a x b cells, alternately from the top */
        for (s16 k = 0; k < b; k = (s16)(k + 2)) {      /* and the bottom, two lines a step */
            for (s16 x = 0; x < W; x = (s16)(x + a))
                for (s16 y = 0; y < H; y = (s16)(y + b)) {
                    bool up = (x / a + y / b) & 1;
                    s16 y0 = up ? (s16)(y + b - 1 - k) : (s16)(y + k);
                    s16 y1 = up ? (s16)(y + b - 2 - k) : (s16)(y + k + 1);
                    gfx_amiga_wipe_line(x, y0, (s16)(x + a - 1), y0);
                    gfx_amiga_wipe_line(x, y1, (s16)(x + a - 1), y1);
                }
            step(STEP_FRAMES);
        }
        break;
    case WIPE_RIGHT:                                    /* $11558: left to right, with one more frame */
        for (s16 x = 0; x < W + a; x = (s16)(x + a)) {
            gfx_amiga_wipe_rect(x, 0, (s16)(x + a - 1), H - 1);
            step(STEP_FRAMES + 1);
        }
        break;
    case WIPE_DOWN:                                     /* $115ba: top to bottom */
        for (s16 y = 0; y < H + a; y = (s16)(y + a)) {
            gfx_amiga_wipe_rect(0, y, W - 1, (s16)(y + a - 1));
            step(STEP_FRAMES);
        }
        break;
    case WIPE_BLINDS:                                   /* $11618: every a-th column, one more a step */
        for (s16 j = 0; j < a; j++) {
            for (s16 x = 0; x < W; x = (s16)(x + a)) gfx_amiga_wipe_line((s16)(x + j), 0, (s16)(x + j), H - 1);
            step(STEP_FRAMES);
        }
        break;
    }
}

void amiga_wipe(AmigaWipe kind, bool in, s16 a, s16 b) { wipe(kind, in, true, a, b); }
void amiga_wipe_over(AmigaWipe kind, s16 a, s16 b) { wipe(kind, true, false, a, b); }
