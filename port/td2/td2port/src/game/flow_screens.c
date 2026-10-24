/* game_flow screens: intro (00c0, 010c), showroom (0143), main menu, car and scenery selection (019e) —
 * port/spec/game_flow.md §4.5-4.9. */
#include <SDL3/SDL.h>
#include <stdio.h>
#include <string.h>

#include "flow.h"
#include "scene.h"
#include "../codeptr.h"
#include "../host.h"
#include "../platform/gfx.h"
#include "../platform/gfx_backend.h"
#include "../platform/input.h"
#include "../platform/res.h"
#include "../platform/timer.h"

#define LOGO_LINES 38               /* DS:007E / DS:01AE: 38 x {x0, y0, x1, y1} */

/* (a * s + b * (32 - s)) >> 5 with 16-bit IMUL products, 16-bit sum and an arithmetic shift. */
static s16 morph(s16 a, s16 s, s16 b, s16 t)
{
    u16 v = (u16)((u16)(s16)(a * s) + (u16)(s16)(b * t));
    return (s16)((s16)v >> 5);
}

/* ================================================================================================
 * Segment 00c0: title, Accolade, intro sequence
 * ============================================================================================== */

/* Step s of 32 of the title's logo lines, growing from the centre, onto the screen (00c0:0004). */
static void title_lines(s16 s)
{
    s16 t = (s16)(0x20 - s);
    gfx_select_target(flow_page_desc());
    gfx_set_clip_current(XBYTES(5), XBYTES(0x23), 0x5E, 0x65);
    gfx_clear_clip(0);
    for (int i = 0; i < LOGO_LINES; i++) {
        u16 l = (u16)(DS_logo_lines_a + 8 * i);
        gfx_draw_line(morph(DSS(l),     s, 0xA0, t),
                      morph(DSS(l + 2), s, 0x64, t),
                      morph(DSS(l + 4), s, 0xA0, t),
                      morph(DSS(l + 6), s, 0x64, t), 0xFFFF);
    }
    select_screen();
    gfx_set_clip_current(XBYTES(5), XBYTES(0x23), 0x5E, 0x65);
    blit_copy_clip_own(flow_page_sprite());
}

static void title_lines_redraw(void *ctx) { (void)ctx; title_lines(0x20); }

/* PORT: the Amiga's title (duel $2b390, in overlay 1): "The Duel" (pics/title.shp "duel", planes 0 to 2)
 * dissolves in with 16 colours of its own ($245b4). Then duel gives the screens' bitmaps plane 3 alone
 * and, 111 steps one frame each, clears it and draws 33 lines that move from random points to the strokes
 * of "TEST DRIVE II" ($244ac); colours 9 to 15 repeat 1 to 7, so the lines show yellow on black and
 * leave the grey logo as it is. "titl" (the letters filled) is drawn over them at the end. */
#define AMIGA_TITLE_LINES 33
#define AMIGA_TITLE_STEPS 110
#define AMIGA_TITLE_PLANE 3

static u16 amiga_title_colours[16];
static u16 amiga_title_targets[AMIGA_TITLE_LINES][4];   /* x0, y0, x1, y1 */

static bool amiga_title_data(void)
{
    u8 c[32], t[AMIGA_TITLE_LINES * 8];
    if (!gfx_amiga_duel_data(0x245B4, c, sizeof c) || !gfx_amiga_duel_data(0x244AC, t, sizeof t)) return false;
    for (int i = 0; i < 16; i++) amiga_title_colours[i] = (u16)(c[2 * i] << 8 | c[2 * i + 1]);
    for (int i = 0; i < AMIGA_TITLE_LINES * 4; i++)
        amiga_title_targets[i / 4][i % 4] = (u16)(t[2 * i] << 8 | t[2 * i + 1]);
    return true;
}

/* Step s of the lines (0 at the start points, AMIGA_TITLE_STEPS at the letters) into the selected
 * target's plane 3. */
static void amiga_title_lines(u16 start[][4], s16 s)
{
    gfx_amiga_plane_clear(AMIGA_TITLE_PLANE);
    for (int i = 0; i < AMIGA_TITLE_LINES; i++) {
        s16 p[4];
        for (int k = 0; k < 4; k++)
            p[k] = (s16)((amiga_title_targets[i][k] * s + start[i][k] * (AMIGA_TITLE_STEPS - s)) / AMIGA_TITLE_STEPS);
        gfx_amiga_plane_line(AMIGA_TITLE_PLANE, p[0], p[1], p[2], p[3]);
    }
}

/* "The Duel" into the page in the title's colours, and with done the lines at the letters and "titl". */
static bool amiga_title_page(bool done)
{
    if (!gfx_amiga_screens() || !amiga_title_data()) return false;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (!gfx_amiga_sprite("pics/title.shp", "duel", 0, 0, AMIGA_AT_OWN)) return false;
    gfx_amiga_colours(amiga_title_colours, 16);
    if (done) {
        amiga_title_lines(amiga_title_targets, AMIGA_TITLE_STEPS);
        gfx_amiga_sprite("pics/title.shp", "titl", 0, 0, AMIGA_AT_OWN);
    }
    return true;
}

static void title_redraw(void *ctx);

/* The rest of the Amiga's title once "The Duel" is in the page. At the DOS pace a step takes a tick. */
static s16 amiga_title(void)
{
    host_sound_event(SOUND_TITLE, 0, NULL);
    s16 k = screen_reveal(1);
    if (k != 0) return k;
    static Uint64 seed = 1;                             /* duel's random points ($2b350, $2b370) */
    u16 start[AMIGA_TITLE_LINES][4];
    for (int i = 0; i < AMIGA_TITLE_LINES; i++)
        for (int j = 0; j < 4; j++) {
            u16 v;
            do v = (u16)(SDL_rand_bits_r(&seed) & (j & 1 ? 0xFF : 0x1FF)); while (v > (j & 1 ? 199 : 319));
            start[i][j] = v;
        }
    bool amiga = host_amiga_pace();
    u32 t0 = ticks_get();
    for (s16 s = 0; s <= AMIGA_TITLE_STEPS; s++) {
        if (gfx_pending_backend()) {                 /* the live switch shows the title as it ends */
            flow_switch_redraw(title_redraw, NULL);
            return 0;
        }
        select_screen();
        amiga_title_lines(start, s);
        DSL(DS_deadline) = t0 + (amiga ? amiga_ticks((u32)s + 1) : (u32)s + 1);
        if ((k = (s16)getkey_until_deadline()) != 0) return k;
    }
    select_screen();
    gfx_amiga_sprite("pics/title.shp", "titl", 0, 0, AMIGA_AT_OWN);
    return 0;
}

/* The title picture into the page. */
static void title_page(void)
{
    if (amiga_title_page(true)) return;              /* PORT */
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    FarPtr a = load_shapes(0x71E6);                  /* "testdrv2" */
    blit_copy_own(res_find(a, 0x71EF));              /* "tdri" */
    blit_copy_own(res_find(a, 0x71F4));              /* "duel" */
    mem_release_cache_old(a);
}

static void title_redraw(void *ctx) { (void)ctx; title_page(); flow_show_page(); }

/* 00c0:0004 title_screen — game_flow.md §4.5 (verified against the disassembly) */
s16 title_screen(void)
{
    s16 k;
    select_screen();
    gfx_clear_clip(0);
    if (amiga_title_page(false)) {                   /* PORT: the Amiga's title, then as TD2 */
        if ((k = amiga_title()) != 0) return k;
        goto shown;
    }
    for (s16 s = 0; s <= 0x20; s++) {
        if (gfx_pending_backend()) flow_switch_redraw(NULL, NULL);   /* PORT: the live switch */
        title_lines(s);
        flow_pace(3);                                /* PORT: unpaced in the original (§7) */
        k = (s16)getkey();
        if (k != 0) return k;
    }
    getkey_timeout_redraw(100, title_lines_redraw, NULL);   /* result ignored */
    title_page();
    host_sound_event(SOUND_TITLE, 0, NULL);          /* PORT: sample-based audio (the Amiga's speech) */
    k = screen_reveal(1);
    if (k != 0) return k;
shown:
    if (host_amiga_pace()) {                         /* PORT: duel's title ends with its speech, then 220 frames */
        if ((k = (s16)wait_sound_end(title_redraw, NULL)) != 0) return k;
        return (s16)getkey_timeout_redraw(amiga_ticks(220), title_redraw, NULL);
    }
    return (s16)getkey_timeout_redraw(300, title_redraw, NULL);
}

/* PORT: the Amiga's "Accolade presents" (duel's intro, overlay 1204h): pics/title2 into the page. */
static bool amiga_accolade_page(void)
{
    return gfx_amiga_screens() && gfx_amiga_picture("pics/title2", 0, 0);
}

/* PORT: the Accolade picture again after a graphics switch, the bull in its place. */
static void accolade_redraw(void *ctx)
{
    (void)ctx;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (amiga_accolade_page()) {
        gfx_amiga_sprite("pics/titlecar.shp", "bull", 0, 0, AMIGA_AT_OWN);
        flow_show_page();
        return;
    }
    FarPtr a = load_shapes(0x71F9);                  /* "accolade" */
    blit_copy_own(res_find(a, 0x7202));              /* "acc_" */
    blit_copy_own(res_find(a, 0x7207));              /* "pres" */
    blit_copy_own(res_find(a, 0x720C));              /* "copy" */
    blit_copy_own(res_find(a, 0x7211));              /* "bull" */
    mem_release_cache_old(a);
    flow_show_page();
}

/* PORT: the rest of the Amiga's "Accolade presents", the picture in the page: it dissolves in, then the
 * bar "bull" (pics/titlecar.shp, a black box with the bar at its right end) slides in at its own row
 * from the left edge to its own x, drawn whole so that it cuts a black line through the letters
 * ($2becc). At the Amiga's pace 4 pixels a frame, as duel; at the DOS pace 2 pixels a tick, as TD2. */
static s16 amiga_accolade(void)
{
    host_sound_event(SOUND_ACCOLADE, 0, NULL);
    s16 r = screen_reveal(1);
    s16 end, row;
    if (r != 0 || !gfx_amiga_sprite_rect("pics/titlecar.shp", "bull", &end, &row, NULL, NULL)) return r;
    bool amiga = host_amiga_pace();
    u32 t0 = ticks_get();
    for (s16 x = 0, n = 1;; x = (s16)(x + (amiga ? 4 : 2)), n++) {
        if (gfx_pending_backend()) {                 /* the live switch ends the slide */
            flow_switch_redraw(accolade_redraw, NULL);
            return 0;
        }
        DSL(DS_deadline) = t0 + (amiga ? amiga_ticks((u32)n) : (u32)n);
        select_screen();
        gfx_amiga_sprite("pics/titlecar.shp", "bull", x, 0, AMIGA_BOX_AT_X);
        if (x >= end) return 0;
        if ((r = (s16)getkey_until_deadline()) != 0) return r;
    }
}

/* 00c0:027a accolade_screen — game_flow.md §4.5 (verified) */
s16 accolade_screen(void)
{
    s16 r;
    select_screen();
    gfx_clear_clip(0);
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (amiga_accolade_page()) return amiga_accolade();   /* PORT */
    FarPtr a = load_shapes(0x71F9);                  /* "accolade" */
    blit_copy_own(res_find(a, 0x7202));              /* "acc_" */
    blit_copy_own(res_find(a, 0x7207));              /* "pres" */
    blit_copy_own(res_find(a, 0x720C));              /* "copy" */
    host_sound_event(SOUND_ACCOLADE, 0, NULL);       /* PORT: sample-based audio (the Amiga's speech) */
    r = screen_reveal(1);
    if (r == 0) {
        FarPtr bull = res_find(a, 0x7211);           /* "bull" slides in from the left */
        for (s16 x = 0; spr_x(bull) > x; x = (s16)(x + 2)) {
            if (gfx_pending_backend()) {             /* PORT: the live switch ends the slide */
                mem_release_cache_old(a);
                flow_switch_redraw(accolade_redraw, NULL);
                return 0;
            }
            deadline_set(1);
            blit_copy_clip_raw(bull, x, spr_y(bull));
            r = (s16)getkey_until_deadline();
            if (r != 0) break;
        }
    }
    mem_release_cache_old(a);
    return r;
}

/* 00c0:039c intro_sequence — game_flow.md §4.5 (verified) */
s16 intro_sequence(void)
{
    static const u16 preload[3] = { 0x7216, 0x721F, 0x7228 };   /* "dsititle", "testdrv2", "accolade" */
    s16 r = (s16)getkey();
    if (r != 0) return r;
    for (int i = 0; i < 3; i++) {
        if (ensure_disk(preload[i], DSS(DS_data_disk), 0) != 0) return KEY_ESC;
        mem_release_cache(load_shapes(DS_disk_path));
    }
    if ((r = accolade_screen()) != 0) return r;
    if (host_amiga_pace()) {                         /* PORT: duel's intro (overlay 1204h) waits for the speech */
        if ((r = (s16)wait_sound_end(accolade_redraw, NULL)) != 0) return r;
        if ((r = (s16)getkey_timeout_redraw(amiga_ticks(5), accolade_redraw, NULL)) != 0) return r;
    } else if ((r = (s16)getkey_timeout_redraw(300, accolade_redraw, NULL)) != 0) return r;
    r = showroom_intro(100);
    host_sound_event(SOUND_SHOWROOM_END, 0, NULL);   /* PORT: sample-based audio (the Amiga's starter) */
    if (r != 0) return r;
    if (host_amiga_pace() && (r = (s16)getkey_timeout_redraw(amiga_ticks(5), NULL, NULL)) != 0)
        return r;                                    /* PORT: as duel */
    if ((r = title_screen()) != 0) return r;
    if (gfx_amiga_screens() && amiga_title_data()) amiga_wipe(WIPE_DOWN, false, 6, 0);   /* PORT: as duel */
    if ((r = credits()) != 0) return r;
    if (DSS(DS_nscenes) == 0) return r;
    return hisc_show(700);
}

/* ================================================================================================
 * Segment 010c: DSI logo and credits
 * ============================================================================================== */

/* 010c:000e dsi_logo_screen — game_flow.md §4.5 (verified) */
s16 dsi_logo_screen(void)
{
    s16 k;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    for (s16 s = 0; s <= 0x20; s++) {
        s16 t = (s16)(0x20 - s);
        if (gfx_pending_backend()) flow_switch_redraw(NULL, NULL);   /* PORT: the live switch */
        gfx_select_target(flow_page_desc());
        gfx_set_clip_current(XBYTES(2), XBYTES(0x23), 0x5E, 0xBD);
        gfx_clear_clip(0);
        deadline_set(5);
        for (int i = 0; i < LOGO_LINES; i++) {
            u16 b = (u16)(DS_logo_lines_b + 8 * i);
            u16 a = (u16)(DS_logo_lines_a + 8 * i);
            gfx_draw_line(morph(DSS(b),     s, DSS(a),     t),
                          morph(DSS(b + 2), s, DSS(a + 2), t),
                          morph(DSS(b + 4), s, DSS(a + 4), t),
                          morph(DSS(b + 6), s, DSS(a + 6), t), 0xFFFF);
        }
        select_screen();
        gfx_set_clip_current(XBYTES(2), XBYTES(0x23), 0x5E, 0xBD);
        if (s == 0) {
            gfx_set_clip_current(0, XBYTES(0x28), 0, 0x65);
            k = screen_reveal(0);
            if (k != 0) return k;
        } else {
            blit_copy_own(flow_page_sprite());
        }
        k = (s16)getkey_until_deadline();
        if (k != 0) return k;
    }
    FarPtr arc = load_shapes(0x7232);                /* "dsititle" */
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    blit_or_own(res_find(arc, 0x723B));              /* "sqar" */
    blit_or_own(res_find(arc, 0x7240));              /* "text" */
    blit_or_own(res_find(arc, 0x7245));              /* "arow" */
    k = screen_reveal(1);
    if (k == 0) blit_or_own(res_find(arc, 0x724A));  /* "type", onto the screen */
    mem_release_cache(arc);
    return k;
}

/* The credits over the DSI logo, onto the screen. */
static void credits_text(void)
{
    gfx_set_text_colours(COL(0x0F, 2), 1);
    draw_text_centered(0x724F, 0x00);                /* " Created by " */
    draw_text_centered(0x725C, 0x20);                /* " Design and Programming " */
    draw_text_centered(0x7275, 0x48);                /* " Art " */
    draw_text_centered(0x727B, 0x60);                /* " Music " */
    gfx_set_text_colours(COL(0x0E, 3), 0);
    draw_text_centered(0x7283, 0x0C);                /* "Distinctive Software Inc." */
    draw_text_centered(0x729D, 0x14);                /* "Vancouver B.C." */
    draw_text_centered(0x72AC, 0x2C);                /* "Amory Wong   Rick Friesen Don Mattrick " */
    draw_text_centered(0x72D4, 0x34);                /* "Bruce Dawson Chris Taylor Al Johanson  " */
    draw_text_centered(0x72FC, 0x3C);                /* "Brad Gour    Erik Kiss    Kris Hatlelid" */
    draw_text_centered(0x7324, 0x54);                /* "John Boechler  Tony Lee  Theresa Henry" */
    draw_text_centered(0x734B, 0x6C);                /* "Kris Hatlelid" */
}

/* PORT: the DSI logo and the credits again after a graphics switch. */
static void credits_redraw(void *ctx)
{
    (void)ctx;
    FarPtr arc = load_shapes(0x7232);                /* "dsititle" */
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    blit_or_own(res_find(arc, 0x723B));              /* "sqar" */
    blit_or_own(res_find(arc, 0x7240));              /* "text" */
    blit_or_own(res_find(arc, 0x7245));              /* "arow" */
    blit_or_own(res_find(arc, 0x724A));              /* "type" */
    mem_release_cache(arc);
    flow_show_page();
    credits_text();
}

/* 010c:0285 credits — game_flow.md §4.5 (verified) */
s16 credits(void)
{
    s16 r = dsi_logo_screen();
    if (r != 0) return r;
    credits_text();
    return (s16)getkey_timeout_redraw(500, credits_redraw, NULL);
}

/* ================================================================================================
 * Segment 0143: showroom
 * ============================================================================================== */

/* PORT: the intro's showroom at the Amiga's pace (host_amiga_pace), as duel's overlay 1776h runs it in
 * frames: the first car stays 200 frames (80 to the starter sound, 120 more), its window opens one
 * picture every 8 frames, then the car gains 15E0h/10000h pixels a frame every frame and its window
 * goes on one picture every 2 frames. The second car keeps the first's final speed (duel never resets
 * it). The DOS pictures and distances stay. */
static bool amiga_showroom;
static s32 amiga_speed;                             /* pixels a frame, 16.16 */
static s16 showroom_intro_dos(s16 unused);

/* Waits until ticks reach t: a key, KEY_SWITCH for a pending graphics switch, or 0. */
static u16 wait_ticks(u32 t);

/* PORT: duel's fade out ($1a0a8): 16 steps, each caps every colour component of the screen's copper
 * list at one level less, from 15 to 0, then waits Delay(1), a 50 Hz tick; it stops once all are black. */
void amiga_fade_out(void)
{
    if (!gfx_amiga_screens()) return;
    for (int level = 15; level >= 0; level--) {
        if (!gfx_amiga_fade_level(level)) break;
        u32 t = ticks_get() + 2;
        while (ticks_get() < t) host_pump();
    }
}

/* PORT: game over in its Amiga form (duel $13b88), in place of TD2's words over the road: the picture
 * pics/gameover, its sample, and then the red letters drip, the sprites dr00 to dr36 of
 * pics/gameover.shp (the stage, then the drip) one a frame at their own places, each over the last.
 * Then 180 frames or a key, and the fade out. At the DOS pace TD2's wait follows the drips. False without
 * the Amiga graphics. */
bool amiga_game_over(void)
{
    if (!gfx_amiga_screens()) return false;
    select_screen();
    if (!gfx_amiga_picture("pics/gameover", 0, 0)) return false;
    host_sound_event(SOUND_GAME_OVER, 0, NULL);
    u32 t0 = ticks_get(), n = 0;
    u16 k = 0;
    for (int a = 0; a < 4 && k != KEY_SWITCH; a++)
        for (int b = 0; b < 7 && k != KEY_SWITCH; b++) {
            char name[5] = { 'd', 'r', (char)('0' + a), (char)('0' + b), 0 };
            gfx_amiga_sprite("pics/gameover.shp", name, 0, 0, AMIGA_AT_OWN);
            k = wait_ticks(t0 + amiga_ticks(++n));
            if (k != KEY_SWITCH) k = 0;              /* duel reads no keys while they drip */
        }
    if (k != KEY_SWITCH) {
        if (host_amiga_pace()) {
            kbd_flush();
            wait_ticks(ticks_get() + amiga_ticks(180));
        } else {
            wait_after_message();
        }
    }
    amiga_fade_out();
    return true;
}

/* PORT: the intro's showroom in its Amiga form (duel $2b776). The showroom is a viewport of 84 lines at
 * line 116 with the car's colours (<car>.st.p). duel draws the side view ("gcar" of <car>.sideview.shp)
 * as a whole box, its bottom on the viewport's, and moves the car by scrolling the viewport: the car
 * stands still in the bitmap. It brings the first car in with blinds (step 20), keeps it 200 frames,
 * then every 4 frames shows the next picture of its window ("wnd0" ... of <car>.anim.shp, as the first
 * car's .ss lists them: their count, the picture at which the car drives off, the names) for two steps.
 * From the drive-off picture on a step is a frame, the viewport moves left 15E0h/10000h pixels more a
 * step each step, and the wheels turn (frm0-2 and rrm0-2, picture (1050 - x) / 7 mod 3), while the
 * window goes on to its last picture. The second car enters from x = 350 with the speed the first had;
 * each leaves at x = -360. At the DOS pace the first car stands 150 ticks, as TD2's; a step is still an
 * NTSC frame. */
#define AMIGA_SHOWROOM_NONE ((s16)0x7FFF)            /* no Amiga showroom: TD2's */
#define SHOW_Y 116
#define SHOW_H 84

static u16 wait_ticks(u32 t)
{
    for (;;) {
        if (gfx_pending_backend()) return KEY_SWITCH;
        u16 k = getkey();
        if (k) return k;
        if (ticks_get() >= t) return 0;
        host_pump();
    }
}

static s16 amiga_showroom_intro(s16 first, s16 second)
{
    char side[2][48], anim[2][48], pal[2][48], file[48];
    s16 dy[2], cars[2] = { first, second };
    for (int i = 0; i < 2; i++) {
        const char *pre = amiga_car_prefix(DSTR(car_rec(cars[i])));
        s16 x, y, h;
        if (!pre || !gfx_amiga_sprite_rect(flow_concat(side[i], sizeof side[i], pre, ".sideview.shp"), "gcar",
                                           &x, &y, NULL, &h))
            return AMIGA_SHOWROOM_NONE;
        flow_concat(anim[i], sizeof anim[i], pre, ".anim.shp");
        flow_concat(pal[i], sizeof pal[i], pre, ".st.p");
        dy[i] = (s16)(SHOW_Y + SHOW_H - h - y);
    }
    u32 len;
    u8 *ss = gfx_amiga_file(flow_concat(file, sizeof file, amiga_car_prefix(DSTR(car_rec(first))), ".ss"), &len);
    char names[32][5];
    int frames = 0, drive = 0;
    if (ss && len >= 2) {
        drive = ss[1];
        for (u32 p = 2; frames < ss[0] && frames < 32 && p + 4 <= len; p += 5, frames++) {
            memcpy(names[frames], ss + p, 4);
            names[frames][4] = 0;
        }
    }
    SDL_free(ss);
    if (frames == 0) return AMIGA_SHOWROOM_NONE;

    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    gfx_amiga_picture(pal[0], 0, 0);
    gfx_amiga_sprite(side[0], "gcar", 0, dy[0], AMIGA_BOX_AT_OWN);
    gfx_amiga_sprite(anim[0], names[0], 0, dy[0], AMIGA_BOX_AT_OWN);
    amiga_wipe(WIPE_BLINDS, true, 20, 0);
    host_sound_event(SOUND_SHOWROOM, 80, NULL);      /* the backend plays the starter 80 frames on */
    u32 t0 = ticks_get() + (host_amiga_pace() ? amiga_ticks(200) : 150), g = 0;
    u16 k = wait_ticks(t0);
    s32 speed = 0;
    s16 step = 4, pic = 0;
    for (int i = 0; i < 2 && k == 0; i++) {
        s16 x = (s16)(i ? 350 : 0);
        bool moving = i != 0, done = false;
        if (i) {
            gfx_select_target(flow_page_desc());
            gfx_amiga_picture(pal[1], 0, 0);
            gfx_fill_rect(0, SHOW_Y, 0x140, SHOW_H, AMIGA_PEN(0));
            gfx_amiga_sprite(side[1], "gcar", 0, dy[1], AMIGA_BOX_AT_OWN);
        }
        while (k == 0 && !done) {
            gfx_select_target(flow_page_desc());
            if (moving) {
                x = (s16)(x - (speed >> 16));
                speed += 0x15E0;
                done = x <= -360;
                char wheel[5] = "frm0";
                wheel[3] = (char)('0' + (1050 - x) / 7 % 3);
                gfx_amiga_sprite(anim[i], wheel, 0, dy[i], AMIGA_BOX_AT_OWN);
                wheel[0] = 'r';
                gfx_amiga_sprite(anim[i], wheel, 0, dy[i], AMIGA_BOX_AT_OWN);
            }
            if (i == 0) {
                gfx_amiga_sprite(anim[0], names[pic / 2], 0, dy[0], AMIGA_BOX_AT_OWN);
                if (pic / 2 < frames - 1) pic++;
                if (pic / 2 >= drive) {
                    moving = true;
                    step = 1;
                }
            }
            gfx_amiga_show_scrolled(flow_page_desc(), SHOW_Y, SHOW_H, x);
            g += (u32)step;
            k = wait_ticks(t0 + amiga_ticks(g));
        }
    }
    if (k == KEY_SWITCH) {                           /* the live switch ends the showroom */
        flow_switch_redraw(NULL, NULL);
        return 0;
    }
    select_screen();
    gfx_clear_screen(0);
    return (s16)k;
}

s16 showroom_intro(s16 unused)                      /* PORT: the intro's showroom drives may take the Amiga's pace */
{
    amiga_showroom = true;
    amiga_speed = 0;
    s16 r = showroom_intro_dos(unused);
    amiga_showroom = false;
    return r;
}

/* 0143:000a showroom_intro — game_flow.md §4.6 (verified) */
static s16 showroom_intro_dos(s16 unused)
{
    char name[20];
    /* PORT: the player's car, then the computer's, as duel's intro shows them ($2b776 reads the cars the
     * car choice keeps at $251b0). The original always takes cars 0 and 1, the cars the choice starts
     * with, and checks their disks; the port has no disk swaps. */
    s16 first = DSS(DS_car_idx), second = DSS(DS_opp_idx);
    s16 r;
    (void)unused;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (first < 0 || first >= DSS(DS_ncars)) first = 0;
    if (second < 0 || second >= DSS(DS_ncars)) second = (DSS(DS_ncars) > 1) ? 1 : 0;
    if ((r = amiga_showroom_intro(first, second)) != AMIGA_SHOWROOM_NONE) return r;   /* PORT */
    /* preload the second car so no disk swap happens during the animation */
    ensure_disk_c(flow_concat(name, sizeof name, DSTR(car_rec(second)), DSTR(0x735A)), car_disk(second), 0);  /* "st" */
    mem_release_cache(load_shapes(DS_disk_path));
    ensure_disk_c(flow_concat(name, sizeof name, DSTR(car_rec(second)), DSTR(0x735D)), car_disk(second), 0);  /* ".ss" */
    mem_release_cache(load_raw(DS_disk_path));
    if (ensure_disk(car_rec(first), car_disk(first), 0) != 0) return KEY_ESC;
    r = showroom_drive(DSTR(DS_disk_path), 0xA0, 0xBE, 1, 1);
    if (r != 0) return r;
    if (ensure_disk(car_rec(second), car_disk(second), 0) != 0) return KEY_ESC;
    return showroom_drive(DSTR(DS_disk_path), 0x1E0, 0xBE, 0, 0);   /* enters from x = 480 at full speed */
}

/* 0143:019e showroom_tick — game_flow.md §4.6 (verified); timer routine */
void showroom_tick(void)
{
    DSS(DS_showroom_speed)++;
    DSS(DS_ss_ticks)++;
    if (DSS(DS_showroom_speed) > 0xC8) DSS(DS_showroom_speed) = 0xC8;
    DSS(DS_showroom_dist) = (s16)(DSS(DS_showroom_dist) + flow_idiv(DSS(DS_showroom_speed), 0x14));
    if (flow_imod(DSS(DS_ss_ticks), DSS(DS_ss_frame_ticks)) == 0) {
        DSS(DS_ss_frame)++;
        if (DSS(DS_ss_frame) >= DSS(DS_ss_frames)) DSS(DS_ss_frame) = (s16)(DSS(DS_ss_frames) - 1);
    }
}

/* sscanf over a C buffer (MSC semantics as in flow.c): %d into *out, %s into a C buffer. */
static bool buf_scan_int(FlowFile *f, s16 *out) { return flow_scan_int(f, out); }
static bool buf_scan_cstr(FlowFile *f, char *dst, size_t cap)
{
    while (f->pos < f->len && (f->data[f->pos] == ' ' || (f->data[f->pos] >= 9 && f->data[f->pos] <= 13))) f->pos++;
    if (f->pos >= f->len) return false;
    size_t n = 0;
    while (f->pos < f->len && !(f->data[f->pos] == ' ' || (f->data[f->pos] >= 9 && f->data[f->pos] <= 13))) {
        if (n + 1 < cap) dst[n++] = (char)f->data[f->pos];
        f->pos++;
    }
    dst[n] = 0;
    return true;
}

#define SS_MAX_FRAMES 64            /* PORT: the original's array holds 25 far pointers (.SS files use <= 15) */

/* The showroom's sprites of one car (its "st" archive), and where the car stands. */
typedef struct {
    const char *path, *names;
    s16 anim, x, y;
    s16 window;                                     /* PORT: the window's picture shown, -1 for none */
    FarPtr a, carS, win[SS_MAX_FRAMES], front[3], rear[3];
    int nwin;
} Showroom;

static void showroom_sprites(Showroom *v)
{
    char name[32];
    v->a = load_shapes_c(flow_concat(name, sizeof name, v->path, DSTR(0x7371)));     /* "st" */
    v->nwin = v->anim ? flow_find_list(v->a, v->names, v->win, SS_MAX_FRAMES) : 0;
    v->carS = res_find(v->a, 0x7374);                /* "carS" */
    res_find(v->a, 0x7379);                          /* "carM" (unused) */
    res_find(v->a, 0x737E);                          /* "logo" (unused) */
    flow_find_list(v->a, DSTR(0x7383), v->front, 3); /* "frm0frm1frm2" */
    flow_find_list(v->a, DSTR(0x7390), v->rear, 3);  /* "rrm0rrm1rrm2" */
}

/* PORT: a graphics switch in the showroom: the sprites again in the new mode. */
static void showroom_switch(Showroom *v)
{
    mem_release_cache(v->a);
    flow_switch_redraw(NULL, NULL);
    showroom_sprites(v);
}

/* PORT: the car standing with its window picture, drawn again after a graphics switch. */
static void showroom_redraw(void *ctx)
{
    Showroom *v = ctx;
    mem_release_cache(v->a);
    showroom_sprites(v);
    gfx_select_target(flow_page_desc());
    gfx_set_clip_current(0, XBYTES(0x28), (s16)(v->y - 0x50), v->y);
    gfx_clear_clip(0);
    blit_copy_clip_hot(v->carS, v->x, v->y);
    if (v->window >= 0 && v->window < v->nwin) blit_copy_clip_hot(v->win[v->window], v->x, v->y);
    select_screen();
    gfx_set_clip_current(0, XBYTES(0x28), (s16)(v->y - 0x50), v->y);
    blit_copy_clip_raw(flow_page_sprite(), 0, 0);
}

/* 0143:01e1 showroom_drive — game_flow.md §4.6 (verified against the disassembly) */
s16 showroom_drive(const char *path, s16 x, s16 y, s16 anim, s16 reveal)
{
    char name[32];
    char buf[257];
    char names[256];
    s16 count = 0;
    s16 r = 0;
    char pathc[32];
    snprintf(pathc, sizeof pathc, "%s", path);       /* path may be DS:8644, which ensure_disk rewrites */
    bool amiga = amiga_showroom && host_amiga_pace();   /* PORT */

    names[0] = 0;
    if (anim) {
        FarPtr h = load_raw_c(flow_concat(name, sizeof name, pathc, DSTR(0x7361)));   /* ".ss" */
        for (u16 i = 0; i < 0x100; i++) buf[i] = (char)far_mp(far_add(h, i))[0];      /* 06c9:5d01 */
        buf[256] = 0;
        mem_release_cache(h);
        FlowFile f = { (unsigned char *)buf, strlen(buf), 0, false };
        /* sscanf(buf, "%d %d %d %s", &ss_frames, &count, &ss_frame_ticks, names) */
        s16 v;
        if (buf_scan_int(&f, &v)) {
            DSS(DS_ss_frames) = v;
            if (buf_scan_int(&f, &v)) {
                count = v;
                if (buf_scan_int(&f, &v)) {
                    DSS(DS_ss_frame_ticks) = v;
                    buf_scan_cstr(&f, names, sizeof names);
                }
            }
        }
    }
    Showroom v = { pathc, names, anim, x, y, -1 };
    showroom_sprites(&v);
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    gfx_set_clip_current(0, XBYTES(0x28), (s16)(y - 0x50), y);
    if (anim) {
        if (reveal) {
            blit_copy_clip_hot(v.carS, x, y);
            r = screen_reveal(1);
            if (r != 0) goto out;
            host_sound_event(SOUND_SHOWROOM, 80, NULL);  /* PORT: sample-based audio (the Amiga's starter) */
        } else {
            select_screen();
            blit_copy_clip_hot(v.carS, x, y);
        }
        r = (s16)getkey_timeout_redraw(amiga ? amiga_ticks(200) : 0x96, showroom_redraw, &v);
        if (r != 0) goto out;
        for (DSS(DS_ss_frame) = 0; DSS(DS_ss_frame) < count; DSS(DS_ss_frame)++) {   /* window opens */
            u32 f = (u32)DSS(DS_ss_frame);
            if (gfx_pending_backend()) flow_switch_redraw(showroom_redraw, &v);   /* PORT: the live switch */
            deadline_set(amiga ? amiga_ticks(8 * (f + 1)) - amiga_ticks(8 * f) : (u32)(s32)DSS(DS_ss_frame_ticks));
            s16 fi = DSS(DS_ss_frame);
            if (fi >= 0 && fi < v.nwin) blit_copy_clip_hot(v.win[fi], x, y);   /* PORT: bounded */
            v.window = fi;
            r = (s16)getkey_until_deadline();
            if (r != 0) goto out;
        }
    }
    DSS(DS_showroom_dist) = 0;
    DSS(DS_showroom_speed) = (x > 300) ? 0xC8 : 0;
    DSS(DS_ss_ticks) = 0;
    timer_add_routine(codeptr_far(FN_showroom_tick));
    s16 window = DSS(DS_ss_frame);
    s32 amiga_dist = 0;
    u32 frames = 0;
    for (;;) {
        if (gfx_pending_backend()) showroom_switch(&v);   /* PORT: the live switch */
        if (amiga) {                                 /* PORT: duel's steps, one per frame of the ticks so far */
            u32 due = (u32)(u16)DSS(DS_ss_ticks) * 6005u / 10000u;
            for (; frames < due; frames++) {
                amiga_dist += amiga_speed >> 16;
                amiga_speed += 0x15E0;
            }
            DSS(DS_showroom_dist) = (s16)(amiga_dist < 0x7000 ? amiga_dist : 0x7000);
            s16 fi = (s16)(window + (s16)((frames ? frames - 1 : 0) / 2));
            DSS(DS_ss_frame) = fi < DSS(DS_ss_frames) ? fi : (s16)(DSS(DS_ss_frames) - 1);
        }
        if ((s16)(x - DSS(DS_showroom_dist)) <= -200) break;
        s16 d = DSS(DS_showroom_dist);
        s16 w = flow_imod(flow_idiv(d, 12), 3);
        s16 cx = (s16)(x - d);
        gfx_select_target(flow_page_desc());
        gfx_set_clip_current(0, XBYTES(0x28), (s16)(y - 0x50), y);
        gfx_clear_clip(0);
        blit_copy_clip_hot(v.carS, cx, y);
        if (anim) {
            s16 fi = DSS(DS_ss_frame);
            if (fi >= 0 && fi < v.nwin) blit_copy_clip_hot(v.win[fi], cx, y);  /* PORT: bounded */
        }
        blit_copy_clip_hot(v.front[w], cx, y);
        blit_copy_clip_hot(v.rear[w], cx, y);
        select_screen();
        gfx_set_clip_current(0, XBYTES(0x28), (s16)(y - 0x50), y);
        blit_copy_clip_raw(flow_page_sprite(), 0, 0);
        host_pump();                                 /* PORT: the original redrew at CPU speed */
        r = (s16)getkey();
        if (r != 0) break;
    }
out:
    mem_release_cache(v.a);
    timer_remove_routine(codeptr_far(FN_showroom_tick));
    return r;
}

/* ================================================================================================
 * Segment 019e: menus
 * ============================================================================================== */

/* 019e:0004 menu_random_key — game_flow.md §4.7 (verified) */
u16 menu_random_key(void)
{
    switch (rand8() & 7) {
    case 0:  return KEY_UP;
    case 1:  return KEY_DOWN;
    case 2:
    case 3:  return KEY_ENTER;
    case 4:  return KEY_RIGHT;
    case 5:  return KEY_LEFT;
    case 6:  return KEY_ESC;
    default: return 0;
    }
}

/* TD2CGA's car_slide (019e:009b) has no scroll routine: it stacks the old and the new picture in a
 * 320 x 176 buffer (the old one at to + 88, the new one at from + 88) and copies an 88-row window of
 * it to the screen at y = from, one row further each step. */
static void car_slide_cga(FarPtr a, FarPtr t, s16 from, s16 to)
{
    FarPtr buf = gfx_create_buffer(0x140, 0xB0, 0x0F);
    gfx_select_target(buf);
    gfx_set_clip_current(0, 0x50, (s16)(to + 0x58), (s16)(to + 0xB0));
    blit_copy_clip_raw(flow_page_sprite(), 0, (s16)(to + 0x58));
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    blit_copy_own(res_find(t, 0x73AA));              /* "blue" */
    blit_and_clip_hot(res_find(a, 0x73AF), 0xA0, 0x50);   /* "carM" */
    blit_or_clip_hot(res_find(a, 0x73B4), 0xA0, 0x50);    /* "carS" */
    blit_or_clip_own(res_find(a, 0x73B9));                /* "logo" */
    gfx_select_target(buf);
    gfx_set_clip_current(0, 0x50, (s16)(from + 0x58), (s16)(from + 0xB0));
    blit_copy_clip_raw(flow_page_sprite(), 0, (s16)(from + 0x58));
    select_screen();
    gfx_set_clip_current(0, 0x50, 0, 0x58);
    do {
        if (from > to) from--;
        else from++;
        blit_copy_clip_raw(gfx_desc_sprite(buf), 0, from);
        flow_pace(1);                                /* PORT: as in EGA */
    } while (from != to);
    blit_copy_own(res_find(a, 0x73BE));              /* "stat" */
    gfx_free_buffer(buf);
}

/* 019e:009b car_slide — game_flow.md §4.8 (verified against the disassembly) */
FarPtr car_slide(s16 car, s16 from, s16 to, FarPtr old)
{
    char name[26];
    s16 y0, delta, row;
    mem_release_cache(old);
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(car_rec(car)), DSTR(0x739E)), car_disk(car), 0) != 0)
        return far_make(0, 0);                       /* "st" */
    FarPtr a = load_shapes(DS_disk_path);
    FarPtr t = load_shapes(0x73A1);                  /* "testdrv2" */
    if (gfx_is_cga()) {
        car_slide_cga(a, t, from, to);
        mem_release_cache(t);
        return a;
    }
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    blit_copy_own(res_find(t, 0x73AA));              /* "blue" */
    blit_and_clip_hot(res_find(a, 0x73AF), 0xA0, 0x50);   /* "carM" */
    blit_or_clip_hot(res_find(a, 0x73B4), 0xA0, 0x50);    /* "carS" */
    blit_or_clip_own(res_find(a, 0x73B9));                /* "logo" */
    if (from > to) { y0 = 0x57; delta = -0x28; }     /* Up: new rows enter at the top */
    else           { y0 = 0;    delta = 0x28; }      /* Down: new rows enter at the bottom */
    select_screen();
    gfx_set_clip_current(0, 0x28, 0, 0x58);
    do {
        if (from > to) { from--; row = (s16)(from - to); }
        else           { from++; row = (s16)(from - to + 0x57); }
        gfx_scroll_window(0, y0, 0x28, 0x57, delta, flow_page_sprite(), row);
        flow_pace(1);                                /* PORT: unpaced in the original (§7) */
    } while (from != to);
    blit_copy_own(res_find(a, 0x73BE));              /* "stat" */
    mem_release_cache(t);
    return a;
}

/* PORT: the car choice in its Amiga form (duel $2dd30). The screen is two viewports: 84 lines at the
 * top with pics/bluestat, the car's side view ("gcar" of <car>.sideview.shp) and its "logo", in the
 * car's colours (<car>.st.p); under them 116 lines in high resolution with the car's data, rows 84 on
 * of <car>.sb (640 x 200, 4 colours). duel moves the viewports to change the car ($2e682): the first
 * comes in from the left (car 4, data 16 pixels a step, 115 steps, $2f064); the next car pushes the
 * old one down and comes down from above ($2ef1c, $2f006), the previous one the other way ($2efbc,
 * $2ef62), 2 lines a step, while the data goes out to the left and comes in from the left, 8 pixels
 * a step for each line. A step is a frame (a tick at the DOS pace). On the way out the data goes
 * ($2eab2). Not done: the fade of three colours before the pick's drive ($2ea12). */
#define CAR_H 84                                    /* the car viewport */

static bool amiga_car_page(s16 car, char *sb, size_t n)
{
    const char *pre = amiga_car_prefix(DSTR(car_rec(car)));
    char f[48];
    if (!pre || !gfx_amiga_screens()) return false;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (!gfx_amiga_picture("pics/bluestat", 0, 0)) return false;
    gfx_amiga_picture(flow_concat(f, sizeof f, pre, ".st.p"), 0, 0);
    if (!gfx_amiga_sprite(flow_concat(f, sizeof f, pre, ".sideview.shp"), "gcar", 0, 0, AMIGA_AT_OWN)) return false;
    gfx_amiga_sprite(f, "logo", 0, 0, AMIGA_AT_OWN);
    flow_concat(sb, n, pre, ".sb");
    return true;
}

/* Waits until ticks reach t, leaving keys for later; false for a pending graphics switch. */
static bool pace_until(u32 t)
{
    while (ticks_get() < t) {
        if (gfx_pending_backend()) return false;
        host_pump();
    }
    return true;
}

/* One slide: d from d0 to d1 by dd; the car viewport moved (cx * d, cy * d), the data dx * d. */
static bool amiga_car_slide(s16 d0, s16 d1, s16 dd, s16 cx, s16 cy, s16 dx)
{
    bool amiga = host_amiga_pace();
    u32 t0 = ticks_get(), n = 0;
    for (s16 d = d0; dd > 0 ? d <= d1 : d >= d1; d = (s16)(d + dd)) {
        gfx_amiga_show_view(flow_page_desc(), 0, CAR_H, (s16)(cx * d), (s16)(cy * d));
        gfx_amiga_hires_scroll((s16)(dx * d));
        n++;
        if (!pace_until(t0 + (amiga ? amiga_ticks(n) : n))) return false;
    }
    return true;
}

typedef enum { AMIGA_CHOICE_DONE, AMIGA_CHOICE_SWITCHED, AMIGA_CHOICE_DOS } AmigaChoice;

/* The car choice in *car: done, ended by a graphics switch (to go on in the new mode), or TD2's to do
 * (a car without its Amiga files). */
static AmigaChoice amiga_car_select(s16 *pcar)
{
    char sb[48];
    s16 car = *pcar;
    if (!amiga_car_page(car, sb, sizeof sb) || !gfx_amiga_hires_band(sb, CAR_H)) return AMIGA_CHOICE_DOS;
    bool ok = amiga_car_slide(114, 0, -1, -4, 0, -16);
    for (;;) {
        u16 k = ok ? getkey_timeout_switch(3000) : KEY_SWITCH;
        if (k == KEY_SWITCH) {
            gfx_amiga_hires_off();
            flow_switch_graphics();
            *pcar = car;
            return AMIGA_CHOICE_SWITCHED;
        }
        if (k == 0) k = KEY_ESC;
        if (k == KEY_ESC || k == KEY_ENTER || k == KEY_SPACE) break;
        if (k != KEY_UP && k != KEY_DOWN) continue;
        bool next = k == KEY_DOWN;
        ok = next ? amiga_car_slide(0, 92, 2, 0, 1, -8) : amiga_car_slide(0, 112, 2, 0, -1, -8);
        if (!ok) continue;
        car = (s16)(next ? car + 1 : car - 1);
        if (car < 0) car = (s16)(DSS(DS_ncars) - 1);
        if (car > DSS(DS_ncars) - 1) car = 0;
        if (!amiga_car_page(car, sb, sizeof sb) || !gfx_amiga_hires_band(sb, CAR_H)) {
            gfx_amiga_hires_off();
            *pcar = car;
            return AMIGA_CHOICE_DOS;
        }
        ok = next ? amiga_car_slide(114, 0, -2, 0, -1, -8) : amiga_car_slide(94, 0, -2, 0, 1, -8);
    }
    gfx_amiga_hires_off();
    gfx_amiga_show_view(flow_page_desc(), 0, CAR_H, 0, 0);
    *pcar = car;
    return AMIGA_CHOICE_DONE;
}

/* PORT: the player's car leaves the Amiga car choice (duel $2eb10): the starter at once, 120 frames,
 * then one window picture every 9 frames as the car's .ss lists them; from the drive-off picture on a
 * step is a frame, the car viewport moves left 2710h/10000h pixels more each step and the wheels turn
 * (picture (x + 7) / 5 mod 3), until it has moved 350 pixels. At the DOS pace the car stands 150
 * ticks, as TD2's. False without the Amiga files. */
static bool amiga_pick_drive(s16 car)
{
    const char *pre = amiga_car_prefix(DSTR(car_rec(car)));
    char anim[48], file[48];
    if (!pre || !gfx_amiga_screens()) return false;
    u32 len;
    u8 *ss = gfx_amiga_file(flow_concat(file, sizeof file, pre, ".ss"), &len);
    char names[32][5];
    int frames = 0, drive = 0;
    if (ss && len >= 2) {
        drive = ss[1];
        for (u32 p = 2; frames < ss[0] && frames < 32 && p + 4 <= len; p += 5, frames++) {
            memcpy(names[frames], ss + p, 4);
            names[frames][4] = 0;
        }
    }
    SDL_free(ss);
    if (frames == 0) return false;
    flow_concat(anim, sizeof anim, pre, ".anim.shp");
    host_sound_event(SOUND_SHOWROOM, 0, NULL);
    bool amiga = host_amiga_pace();
    u32 t0 = ticks_get() + (amiga ? amiga_ticks(120) : 150), g = 0;
    u16 k = wait_ticks(t0);
    s32 speed = 0;
    s16 x = 0, pic = 0, step = 9;
    bool moving = false, done = false;
    while (k == 0 && !done) {
        gfx_select_target(flow_page_desc());
        if (moving) {
            char wheel[5] = "frm0";
            wheel[3] = (char)('0' + (x + 7) / 5 % 3);
            gfx_amiga_sprite(anim, wheel, 0, 0, AMIGA_BOX_AT_OWN);
            wheel[0] = 'r';
            gfx_amiga_sprite(anim, wheel, 0, 0, AMIGA_BOX_AT_OWN);
        }
        s16 shown = (s16)-x;
        if (moving) {
            x = (s16)(x + (speed >> 16));
            speed += 0x2710;
            done = x >= 350;
            step = 1;
        }
        if (pic < frames) {
            gfx_amiga_sprite(anim, names[pic], 0, 0, AMIGA_BOX_AT_OWN);
            if (pic < frames - 1) pic++;
            if (pic >= drive) moving = true;
        }
        gfx_amiga_show_view(flow_page_desc(), 0, CAR_H, shown, 0);
        g += (u32)step;
        k = wait_ticks(t0 + amiga_ticks(g));
    }
    if (k == KEY_SWITCH) flow_switch_redraw(NULL, NULL);
    select_screen();
    gfx_clear_screen(0);
    return true;
}

/* 019e:027d car_select — game_flow.md §4.8 (verified against the disassembly) */
s16 car_select(s16 car)
{
    char name[26];
    u16 k;
    bool amiga = true;
redraw:
    if (amiga && gfx_amiga_screens()) {              /* PORT */
        AmigaChoice c = amiga_car_select(&car);
        if (c == AMIGA_CHOICE_DONE) return car;
        if (c == AMIGA_CHOICE_DOS) amiga = false;
        goto redraw;
    }
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (ensure_disk(0x73C3, DSS(DS_data_disk), 2) != 0) return car;    /* "testdrv2" */
    FarPtr t = load_shapes(DS_disk_path);
    blit_copy_own(res_find(t, 0x73CC));              /* "blue" */
    mem_release_cache(t);
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(car_rec(car)), DSTR(0x73D1)), car_disk(car), 0) != 0)
        return car;                                  /* "st" */
    FarPtr a = load_shapes(DS_disk_path);
    blit_and_clip_hot(res_find(a, 0x73D4), 0xA0, 0x50);   /* "carM" */
    blit_or_clip_hot(res_find(a, 0x73D9), 0xA0, 0x50);    /* "carS" */
    blit_or_clip_own(res_find(a, 0x73DE));                /* "logo" */
    blit_copy_clip_own(res_find(a, 0x73E3));              /* "stat" */
    select_screen();
    blit_copy_own(flow_page_sprite());
    for (;;) {
        k = getkey_timeout_switch(3000);
        if (k == KEY_SWITCH) {
            if (!far_is_null(a)) mem_release_cache_old(a);
            flow_switch_graphics();
            goto redraw;
        }
        if (k == 0) k = KEY_ESC;
        if (k == KEY_ESC || k == KEY_ENTER || k == KEY_SPACE) break;
        if (k == KEY_UP) {
            car--;
            if (car < 0) car = (s16)(DSS(DS_ncars) - 1);
            a = gfx_is_cga() ? car_slide(car, -0x58, 0, a) : car_slide(car, 0, -0x58, a);
        }
        if (k == KEY_DOWN) {
            car++;
            if (car > DSS(DS_ncars) - 1) car = 0;
            a = gfx_is_cga() ? car_slide(car, 0, -0x58, a) : car_slide(car, -0x58, 0, a);
        }
    }
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (!far_is_null(a)) {
        blit_copy_clip_hot(res_find(a, 0x73E8), 0xA0, 0x50);   /* "carS" */
        mem_release_cache_old(a);
    }
    select_screen();
    gfx_set_clip_current(0, XBYTES(0x28), 0, 0x58);
    blit_copy_clip_hot(flow_page_sprite(), 0, 0);   /* the top 88 rows show only the car on black */
    return car;
}

/* PORT: the Amiga game's folder of each scenery, by its DOS code, for the Amiga graphics. */
static const char *amiga_scenery_prefix(const char *code)
{
    static const struct { const char *code, *prefix; } sceneries[] = {
        { "TDS2", "scen/sc1_" }, { "CCC", "scen1/scen/rock_" }, { "ec_", "scen2/scen/euro_" },
        { "NGC", "scen3/scen/euro_" },
    };
    for (size_t i = 0; i < sizeof sceneries / sizeof sceneries[0]; i++) {
        const char *a = code, *b = sceneries[i].code;
        while (*a && (*a | 0x20) == (*b | 0x20)) a++, b++;
        if (!*a && !*b) return sceneries[i].prefix;
    }
    return NULL;
}

/* 019e:0527 scenery_select — game_flow.md §4.9 (verified) */
void scenery_select(void)
{
    char buf[48], name[26];
    for (;;) {
        gfx_select_target(flow_page_desc());
        gfx_clear_clip(0);
        if (DSS(DS_nscenes) - 1 < DSS(DS_scn_idx)) DSS(DS_scn_idx) = 0;
        if (DSS(DS_scn_idx) < 0) DSS(DS_scn_idx) = (s16)(DSS(DS_nscenes) - 1);
        strcpy(DSTR(DS_scn_code), DSTR(scn_rec(DSS(DS_scn_idx))));
        DSS(DS_scn_disk) = scn_disk(DSS(DS_scn_idx));
        /* PORT: with the Amiga graphics, the scenery's Amiga picture fills the page and the disk name
         * is written over it in pen 5, with no line at the bottom (duel $2d8c8). */
        const char *prefix = gfx_amiga_screens() ? amiga_scenery_prefix(DSTR(DS_scn_code)) : NULL;
        bool amiga = prefix && gfx_amiga_picture(flow_concat(buf, sizeof buf, prefix, "icon"), 0, 0);
        u16 fg = DSW(DS_text_fg), bg = DSW(DS_text_bg);
        if (amiga) gfx_set_text_colours(AMIGA_PEN(5), AMIGA_PEN(0));
        if (DSS(DS_nscenes) == 1) {
            draw_text_centered(0x73ED, 0);           /* "Additional Scenerydisks Available." */
        } else {
            /* sprintf(buf, "%s DISK", disk_type_names[scn_disk]) */
            snprintf(buf, sizeof buf, "%s DISK", DSTR(DSW(DS_disk_type_names + 2 * DSS(DS_scn_disk))));
            draw_text_centered_str(buf, 0);
        }
        if (amiga) gfx_set_text_colours(fg, bg);
        if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(scn_rec(DSS(DS_scn_idx))), DSTR(0x7418)),
                          DSS(DS_scn_disk), 0) != 0)
            return;                                  /* "icon" */
        if (!amiga) {
            FarPtr a = load_shapes(DS_disk_path);
            blit_copy_own(res_find(a, 0x741D));      /* "picl" */
            mem_release_cache(a);
            draw_text_centered(0x7422, 0xBE);        /* "Use Keyboard/Joystick to change scenery." */
        }
        /* PORT: duel wipes the scenery's picture in with a box from the centre ($2d938) */
        if (amiga) amiga_wipe(WIPE_BOX, true, 10, 0);
        else screen_reveal(3);
        s16 old;
        do {
            old = DSS(DS_scn_idx);
            u16 k = getkey_timeout_switch(3000);
            if (k == KEY_SWITCH) {
                flow_switch_graphics();
                break;
            }
            if (k == 0) k = KEY_ESC;
            if (k == KEY_ENTER || k == KEY_SPACE || k == 0 || k == KEY_ESC) return;
            if (k == KEY_UP || k == KEY_RIGHT) DSS(DS_scn_idx)++;
            if (k == KEY_DOWN || k == KEY_LEFT) DSS(DS_scn_idx)--;
        } while (DSS(DS_scn_idx) == old);
        if (amiga) amiga_wipe(WIPE_BARS, false, 10, 0);   /* PORT: and out with bars ($2d874) */
    }
}

/* PORT: the Amiga game's file prefix of each car, by its DOS code, for the Amiga graphics. */
const char *amiga_car_prefix(const char *code)
{
    static const struct { const char *code, *prefix; } cars[] = {
        { "F40", "cars/f40" }, { "P959", "cars/p959" }, { "CAMA", "cars1/cars/camo" },
        { "DODG", "cars1/cars/dodge" }, { "GT50", "cars1/cars/gt500" }, { "GOAT", "cars1/cars/gto" },
        { "STNG", "cars1/cars/stingray" }, { "COUN", "cars2/cars/coun" }, { "LOTU", "cars2/cars/lotu" },
        { "ROSS", "cars2/cars/ross" }, { "RUF", "cars2/cars/ruf" }, { "VETT", "cars2/cars/vett" },
    };
    for (size_t i = 0; i < sizeof cars / sizeof cars[0]; i++) {
        const char *a = code, *b = cars[i].code;
        while (*a && (*a | 0x20) == (*b | 0x20)) a++, b++;
        if (!*a && !*b) return cars[i].prefix;
    }
    return NULL;
}

/* PORT: the option screen in its Amiga form (duel $2e07c): its picture, each car's logo in its box and
 * the scenery's icon. False without the Amiga graphics. */
static bool amiga_menu_page(void)
{
    if (!gfx_amiga_screens() || !gfx_amiga_picture("pics/gameoptionscreen", 0, 0)) return false;
    gfx_set_text_colours(AMIGA_PEN(1), AMIGA_PEN(0));
    const char *cars[2] = { DSTR(DS_player_car_code), DSTR(DS_opp_car_code) };
    char file[48];
    for (int i = 0; i < 2; i++) {
        const char *car = amiga_car_prefix(cars[i]);
        s16 x = (s16)(i * 0x4E + 7);
        if (!car || !gfx_amiga_sprite(flow_concat(file, sizeof file, car, "logo.shp"), "rcar",
                                      (s16)(x + 0x22), 0xBE, AMIGA_AT_HOT))
            gfx_draw_text(i ? 0x7463 : 0x7455, i ? 0x6C : 0x1C, 0xAA);              /* "N/A" */
    }
    const char *scn = amiga_scenery_prefix(DSTR(DS_scn_code));
    bool icon = scn && gfx_amiga_sprite(flow_concat(file, sizeof file, scn, "gameoption.shp"), "scn0", 0, 0,
                                        AMIGA_AT_OWN);
    /* Northern Germany has no gameoption.shp: as for its DOS icons, the middle of the heath photo of
     * its title picture, in the 62 x 35 the other sceneries' icons fill at (167, 155) */
    if (!icon && scn && strcmp(scn, "scen3/scen/euro_") == 0)
        icon = gfx_amiga_picture_scaled(flow_concat(file, sizeof file, scn, "icon"), 126, 15, 75, 42, 167, 155, 62, 35);
    if (!icon) gfx_draw_text(0x7471, 0xBC, 0xAA);                                   /* "N/A" */
    gfx_set_text_colours(COL(0x0F, 3), 0);
    return true;
}

/* PORT: the Amiga highlight (duel $2dc40): three rectangles round the selected box (the boxes at
 * $24bb4, in the DOS order of the icons), in pen 14 in the top row and 16 in the bottom row. */
static void amiga_menu_highlight(void)
{
    static const s16 boxes[6][4] = {
        { 46, 30, 149, 110 }, { 166, 30, 269, 110 },
        { 5, 137, 78, 195 }, { 83, 137, 156, 195 }, { 161, 137, 234, 195 }, { 239, 137, 312, 195 },
    };
    const s16 *b = boxes[DSS(DS_menu_sel)];
    u16 pen = AMIGA_PEN(DSS(DS_menu_sel) < 2 ? 14 : 16);
    for (s16 k = 0; k < 3; k++) {
        s16 x0 = (s16)(b[0] - k), y0 = (s16)(b[1] - k), x1 = (s16)(b[2] + k), y1 = (s16)(b[3] + k);
        gfx_fill_rect(x0, y0, (s16)(x1 - x0 + 1), 1, pen);
        gfx_fill_rect(x0, y1, (s16)(x1 - x0 + 1), 1, pen);
        gfx_fill_rect(x0, y0, 1, (s16)(y1 - y0 + 1), pen);
        gfx_fill_rect(x1, y0, 1, (s16)(y1 - y0 + 1), pen);
    }
}

/* Highlight box of the selected GAMEOPT icon (019e:0a2f-0ad3). */
static void menu_draw_highlight(void)
{
    FarPtr s = ds_far((u16)(DS_gameopt_spr + 4 * DSS(DS_menu_sel)));
    s16 x = spr_x(s), y = spr_y(s), w = spr_w(s), h = spr_h(s);
    draw_rect_outline((s16)(x + 2), y, (s16)((s16)(w * gfx_px_per_byte()) + x - 3), (s16)(y + h - 1), 0xFFFF);
    s = ds_far((u16)(DS_gameopt_spr + 4 * DSS(DS_menu_sel)));
    x = spr_x(s); y = spr_y(s); w = spr_w(s); h = spr_h(s);
    draw_rect_outline((s16)(x + 1), (s16)(y - 1), (s16)((s16)(w * gfx_px_per_byte()) + x - 2), (s16)(y + h), 0xFFFF);
}

/* The car logos and the scenery icon of the DOS option screen, as main_menu draws them. */
static void dos_menu_icons(void)
{
    char name[26];
    FarPtr a;
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_player_car_code), DSTR(0x744B)),
                      DSS(DS_car_disk), 0) == 0) {                              /* "rear" */
        a = load_shapes(DS_disk_path);
        blit_copy_clip_hot(res_find(a, 0x7450), 0x28, 0xBF);                     /* "logS" */
        mem_release_cache(a);
    } else {
        gfx_draw_text(0x7455, 0x1C, 0xAA);                                      /* "N/A" */
    }
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_opp_car_code), DSTR(0x7459)),
                      DSS(DS_opp_disk), 0) == 0) {                              /* "rear" */
        a = load_shapes(DS_disk_path);
        blit_copy_clip_hot(res_find(a, 0x745E), 0x78, 0xBF);                     /* "logS" */
        mem_release_cache(a);
    } else {
        gfx_draw_text(0x7463, 0x6C, 0xAA);                                      /* "N/A" */
    }
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_scn_code), DSTR(0x7467)),
                      DSS(DS_scn_disk), 0) == 0) {                              /* "icon" */
        a = load_shapes(DS_disk_path);
        blit_copy_own(res_find(a, 0x746C));                                      /* "pics" */
        mem_release_cache(a);
    } else {
        gfx_draw_text(0x7471, 0xBC, 0xAA);                                      /* "N/A" */
    }
}

/* 019e:06c5 main_menu — game_flow.md §4.7 (verified against the disassembly) */
s16 main_menu(void)
{
    char name[26];
    bool from_box = false;                            /* PORT: back from a box of the bottom row */
    for (;;) {
        FarPtr g;
        flow_switch_graphics();
        DSS(DS_menu_prev_sel) = (s16)(DSS(DS_menu_sel) + 1);
        gfx_select_target(flow_page_desc());
        gfx_clear_clip(0);
        gfx_set_text_colours(COL(0x0F, 3), 0);
        bool amiga = amiga_menu_page();
        if (!amiga) dos_menu_icons();
        if (ensure_disk(0x7475, DSS(DS_data_disk), 0) != 0) return 1;                /* "gamediff" */
        mem_release_cache(load_shapes(DS_disk_path));                                /* preload */
        if (ensure_disk(0x747E, DSS(DS_data_disk), 0) != 0) return 1;                /* "gameopt" */
        g = load_shapes(DS_disk_path);
        {
            FarPtr spr[9];
            flow_find_list(g, DSTR(0x7486), spr, 9);         /* "cloccompycarocarsceninsttxt0txt1arrw" */
            for (int i = 0; i < 9; i++) ds_far_wr((u16)(DS_gameopt_spr + 4 * i), spr[i]);
        }
        if (!amiga)
            for (int i = 0; i < 9; i++) blit_or_own(ds_far((u16)(DS_gameopt_spr + 4 * i)));
        if (amiga) {
            /* PORT: duel draws the highlight into the page and wipes it in, with bands when it comes back
             * from a box of the bottom row ($2e47a), else with a circle ($2e326) */
            amiga_menu_highlight();
            if (from_box) amiga_wipe(WIPE_BANDS, true, 40, 40);
            else amiga_wipe(WIPE_CIRCLE, true, 6, 0);
            gfx_select_target(flow_page_desc());
            amiga_menu_page();                        /* the page again, without the highlight */
            select_screen();
            DSS(DS_menu_prev_sel) = DSS(DS_menu_sel);
        } else {
            screen_reveal(3);
        }
        kbd_flush();

        u16 k = 0xFFFF;
        for (;;) {
            if (k == KEY_SWITCH) break;
            if (k == KEY_ESC) {
                mem_release_cache(g);
                return 0;
            }
            if (k == KEY_ENTER || k == KEY_SPACE) break;
            if (k == KEY_LEFT)  DSS(DS_menu_sel)--;
            if (k == KEY_RIGHT) DSS(DS_menu_sel)++;
            if (k == KEY_UP && (DSS(DS_menu_sel) == 2 || DSS(DS_menu_sel) == 3)) DSS(DS_menu_sel) = 0;
            if (k == KEY_UP && (DSS(DS_menu_sel) == 4 || DSS(DS_menu_sel) == 5)) DSS(DS_menu_sel) = 1;
            if (k == KEY_DOWN && DSS(DS_menu_sel) == 0) DSS(DS_menu_sel) = 2;
            if (k == KEY_DOWN && DSS(DS_menu_sel) == 1) DSS(DS_menu_sel) = 5;
            if (DSS(DS_menu_sel) < 0) DSS(DS_menu_sel) = 5;
            if (DSS(DS_menu_sel) > 5) DSS(DS_menu_sel) = 0;
            if (DSS(DS_menu_prev_sel) != DSS(DS_menu_sel)) {
                blit_copy_own(flow_page_sprite());   /* erase the old highlight */
                if (amiga) amiga_menu_highlight();
                else menu_draw_highlight();
            }
            k = getkey_timeout_switch(DSW(DS_demo_mode) ? 100 : 3000);
            if (k == KEY_SWITCH) continue;
            if (k == 0 || k == KEY_F10) {
                DSW(DS_demo_mode) = 1;
                k = menu_random_key();
                if (k == KEY_ESC) k = 0;
            } else {
                DSW(DS_demo_mode) = 0;
            }
            DSS(DS_menu_prev_sel) = DSS(DS_menu_sel);
        }
        mem_release_cache(g);
        if (k == KEY_SWITCH) continue;                /* PORT: draw the menu again in the new mode */
        if (DSW(DS_demo_mode) != 0) DSS(DS_menu_sel) = 0;
        if (DSB(DS_protect_sabotage) != 0) return 0;
        from_box = DSS(DS_menu_sel) >= 2;
        if (amiga && from_box) amiga_wipe(WIPE_SWEEP, false, 40, 0);   /* PORT: duel $2e37e */

        s16 r = 0;
        switch (DSS(DS_menu_sel)) {
        case 0:
            r = run_game(0);
            break;
        case 1:
            r = run_game(1);
            break;
        case 2:
            DSS(DS_car_idx) = car_select(DSS(DS_car_idx));
            strcpy(DSTR(DS_player_car_code), DSTR(car_rec(DSS(DS_car_idx))));
            DSS(DS_car_disk) = car_disk(DSS(DS_car_idx));
            ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_player_car_code), DSTR(0x74AB)),
                          DSS(DS_car_disk), 0);                                      /* ".ss" */
            mem_release_cache(load_raw(DS_disk_path));
            if (!amiga_pick_drive(DSS(DS_car_idx)))   /* PORT: the Amiga form */
                showroom_drive(DSTR(DS_player_car_code), 0xA0, 0x50, 1, 0);
            break;
        case 3:
            DSS(DS_opp_idx) = car_select(DSS(DS_opp_idx));
            strcpy(DSTR(DS_opp_car_code), DSTR(car_rec(DSS(DS_opp_idx))));
            DSS(DS_opp_disk) = car_disk(DSS(DS_opp_idx));
            break;
        case 4:
            scenery_select();
            hisc_load();
            break;
        case 5:
            install_menu();
            if (DSS(DS_ncars) == 0 || DSS(DS_nscenes) == 0) return 1;
            break;
        default:
            break;
        }
        kbd_flush();
        if (DSW(DS_protect_failed) != 0) return 0;
        if (DSW(DS_demo_mode) != 0 && r != 0) return 0;
        DSW(DS_demo_mode) = 0;
    }
}
