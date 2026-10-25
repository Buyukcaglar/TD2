/* game_flow segment 0645: <scn>hisc.dat, name entry, top-score table — port/spec/game_flow.md §4.15, §5.4. */
#include <stdio.h>
#include <string.h>

#include "flow.h"
#include "../host.h"
#include "../platform/gfx.h"
#include "../platform/input.h"
#include "../platform/res.h"

/* Checksum of the record tables (inline in 0645:0000 and 0645:0186; verified): 32-bit sum of the six
 * scores, then per stage the time (sign-extended), average, score, cumulative time and score. */
u32 hisc_checksum(void)
{
    u32 sum = 0;
    for (s16 i = 0; i < 6; i++) sum += DSL(top_rec(i));
    for (s16 i = 0; i < 10; i++) {
        sum += (u32)(s32)DSS(DS_best_time + 2 * i);
        sum += DSL(DS_best_avg + 4 * i);
        sum += DSL(DS_best_score + 4 * i);
        sum += DSL(DS_best_cum_time + 4 * i);
        sum += DSL(DS_best_cum_score + 4 * i);
    }
    return sum;
}

/* 0645:0000 hisc_load — game_flow.md §4.15 (verified) */
s16 hisc_load(void)
{
    char name[26];
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_scn_code), DSTR(0x8200)), DSS(DS_scn_disk), 0) != 0)
        return KEY_ESC;                                                     /* "hisc.dat" */
    char *path = host_game_path(DSTR(DS_disk_path), false);
    FILE *fp = path ? fopen(path, "rb") : NULL;
    host_free(path);
    if (fp) {
        /* fclose; 06c9:6aa2(disk_path, DS:90B8) — PORT: reads at most the 0x154 bytes of the table
         * (the original loads the whole file without a size check) */
        size_t got = fread(mp(DGROUP, DS_hisc_block), 1, HISC_SIZE, fp);
        (void)got;
        fclose(fp);
        if (hisc_checksum() == DSL(DS_hisc_checksum)) return 0;
    }
    for (s16 i = 0; i < 6; i++) {
        DSL(top_rec(i)) = 0;
        DSB(top_car(i)) = 0;
        DSB(top_name(i)) = 0;
    }
    for (s16 i = 0; i < 10; i++) {
        DSW(DS_best_time + 2 * i) = 0;
        DSL(DS_best_avg + 4 * i) = 0;
        DSL(DS_best_score + 4 * i) = 0;
        DSL(DS_best_cum_time + 4 * i) = 0;
        DSL(DS_best_cum_score + 4 * i) = 0;
    }
    return 0;
}

/* 0645:0186 hisc_save — game_flow.md §4.15 (verified) */
void hisc_save(void)
{
    char name[26];
    DSL(DS_hisc_checksum) = hisc_checksum();
    if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_scn_code), DSTR(0x820B)), DSS(DS_scn_disk), 0) == 0)
        write_file_or_die(DS_disk_path, ds_ptr(DS_hisc_block), HISC_SIZE);  /* "hisc.dat", 06c9:7866 */
}

static s16 name_edit(s16 x, s16 y, bool again);

/* PORT: the name entry in its Amiga form (duel $2a000): the player's car from behind, the picture
 * <car>.rear, fills the screen, and a box in pen 15 from (69, 183) to (249, 194) holds the name field,
 * pen 1 on pen 0 from (71, 185), 22 letters wide. duel writes no words there. It draws them into the
 * page and brings it in with a box from the centre ($10fde, step 8), and when the name is in, closes
 * the screen with the frame from the edges ($11062, step 6); TD2's 15 letters and wait stay. -1 without
 * the Amiga files, else the edit's key. again: after a live switch, the page at once and the name as far
 * as it was typed. */
static s16 amiga_name_entry(bool again)
{
    const char *car = amiga_car_prefix(DSTR(DS_player_car_code));
    char file[48];
    if (!car || !gfx_amiga_screens()) return -1;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    if (!gfx_amiga_picture(flow_concat(file, sizeof file, car, ".rear"), 0, 0)) {
        select_screen();
        return -1;
    }
    gfx_fill_rect(0x45, 0xB7, 0xF9 - 0x45 + 1, 0xC2 - 0xB7 + 1, AMIGA_PEN(15));
    gfx_fill_rect(0x47, 0xB9, 22 * 8, 8, AMIGA_PEN(0));
    if (again) flow_show_page();
    else amiga_wipe(WIPE_BOX, true, 8, 0);
    select_screen();
    gfx_set_text_colours(AMIGA_PEN(1), AMIGA_PEN(0));
    s16 k = name_edit(0x47, 0xB9, again);
    if (k != (s16)KEY_SWITCH) amiga_wipe(WIPE_BARS, false, 6, 0);
    return k;
}

/* PORT: the name's edit, from the start or, after a live switch (again), from where it was: it ends with
 * KEY_SWITCH when a switch comes. */
static s16 name_edit(s16 x, s16 y, bool again)
{
    s16 pos = again ? (s16)DSW(DS_g_edit_pos) : 0;
    if (!again) for (s16 i = 0; i < 15; i++) DSB((u16)(DS_player_name + i)) = ' ';   /* input_text_line */
    return edit_text_line_switch(DS_player_name, 15, x, y, 12000, pos);
}

/* 0645:0271 name_entry_screen — game_flow.md §4.15 (verified). PORT: a live switch draws the screen again
 * in the new mode, and the name goes on from where it was. */
s16 name_entry_screen(void)
{
    char name[26];
    for (bool again = false;; again = true) {
        select_screen();
        gfx_clear_clip(0);
        s16 k = amiga_name_entry(again);             /* PORT */
        if (k == -1) {
            if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(DS_player_car_code), DSTR(0x8214)),
                              DSS(DS_car_disk), 0) != 0)
                return KEY_ESC;                                             /* "rear" */
            FarPtr a = load_shapes(DS_disk_path);
            blit_copy_own(res_find(a, 0x8219));                             /* "logL" */
            mem_release_cache(a);
            gfx_set_text_colours(COL(0x0F, 3), 0);
            draw_text_centered(0x821E, 0x96);      /* "You have qualified as one of" */
            draw_text_centered(0x823B, 0xA0);      /* "THE DUEL: Test Drive II's best drivers." */
            gfx_draw_text(0x8263, 0x14, 0xB4);     /* "Enter your name:" */
            draw_rect_outline(0xB2, 0xAF, 0x13C, 0xBE, 0xFFFF);
            k = name_edit(0xB8, 0xB4, again);      /* input_text_line; the result is ignored */
        }
        if (k != (s16)KEY_SWITCH) return 0;
        flow_switch_graphics();
    }
}

/* 0645:0389 hisc_insert — game_flow.md §4.15 (verified) */
s16 hisc_insert(void)
{
    s32 total = DSSL(DS_total_score);
    s16 i;
    for (i = 0; i < 6; i++)
        if ((s32)DSL(top_rec(i)) < total) break;
    if (i == 6) return (s16)(u16)total;            /* undefined in the original (AX = low word of the score) */
    if (name_entry_screen() != 0) return KEY_ESC;
    for (s16 j = 5; j > i; j--) {
        DSL(top_rec(j)) = DSL(top_rec(j - 1));
        strcpy(DSTR(top_car(j)), DSTR(top_car(j - 1)));
        strcpy(DSTR(top_name(j)), DSTR(top_name(j - 1)));
    }
    DSL(top_rec(i)) = DSL(DS_total_score);
    strcpy(DSTR(top_car(i)), DSTR(DS_player_car_code));
    strcpy(DSTR(top_name(i)), DSTR(DS_player_name));
    hisc_save();
    return 0;
}

/* PORT: the high scores in their Amiga form (duel $2a3b0) into the page: black, with colour 1 08Eh and
 * colour 2 F66h; "<scenery> Top Scores" centred at the top in pen 2 ($2a0b0 makes it from the scenery's
 * name in scen.dat); for each of the top four its car's logo ("logo" of <car>logo.shp, its hot point at
 * (40, i * 35 + 50)), with that car's colours 3 to 31 (<car>.rear.p) from two lines above the logo
 * down, a copper split, and "%7ld  %s" (score, name) at (74, i * 35 + 35) in pen 1; the fifth and
 * sixth at (74, i * 10 + 122). Entries without a score are left out. After a race "Your Score : %ld"
 * is at line 192 in pen 2. duel centres both lines on x = 170 ($11c8e, the centre set by $11c80). The
 * text is in TD2's font, as topaz is not in the files. False without the Amiga graphics. */
#define HISC_CENTRE 170

static bool amiga_hisc_page(s32 timeout)
{
    static const u16 colours[3] = { 0x000, 0x08E, 0xF66 };
    char t[72], file[48];
    if (!gfx_amiga_screens()) return false;
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    gfx_amiga_colours(colours, 3);
    snprintf(t, sizeof t, "%s", DSTR(scn_name(DSS(DS_scn_idx))));
    for (size_t k = strlen(t); k > 0 && t[k - 1] == ' '; k--) t[k - 1] = 0;
    strncat(t, " Top Scores", sizeof t - strlen(t) - 1);
    gfx_set_text_colours(AMIGA_PEN(2), AMIGA_PEN(0));
    gfx_draw_text_str(t, (u16)(HISC_CENTRE - (s16)strlen(t) * 4), 1);
    for (s16 i = 0; i < 6; i++) {
        if (DSL(top_rec(i)) == 0) continue;
        const char *pre = amiga_car_prefix(DSTR(top_car(i)));
        s16 hx, hy;
        if (i < 4 && pre && gfx_amiga_sprite_hot(flow_concat(file, sizeof file, pre, "logo.shp"), "logo", &hx, &hy)) {
            gfx_amiga_sprite(file, "logo", 40, (s16)(i * 35 + 50), AMIGA_AT_HOT);
            gfx_amiga_split_colours(flow_concat(file, sizeof file, pre, ".rear.p"), (u16)(i * 35 + 48 - hy), 3);
        }
        snprintf(t, sizeof t, "%7ld  %s", (long)(s32)DSL(top_rec(i)), DSTR(top_name(i)));
        gfx_set_text_colours(AMIGA_PEN(1), AMIGA_PEN(0));
        gfx_draw_text_str(t, 74, (u16)(i < 4 ? i * 35 + 35 : i * 10 + 122));
    }
    if (timeout == 1500 && DSSL(DS_total_score) > 0) {
        snprintf(t, sizeof t, "Your Score : %ld", (long)DSSL(DS_total_score));
        gfx_set_text_colours(AMIGA_PEN(2), AMIGA_PEN(0));
        gfx_draw_text_str(t, (u16)(HISC_CENTRE - (s16)strlen(t) * 4), 192);
    }
    return true;
}

/* The high scores into the page, as hisc_show draws them; KEY_ESC if a logo is missing. */
static s16 hisc_page(s32 timeout)
{
    char t[72], name[26];
    if (amiga_hisc_page(timeout)) return 0;      /* PORT */
    gfx_select_target(flow_page_desc());
    gfx_clear_clip(0);
    gfx_set_text_colours(COL(0x0F, 3), 0);
    draw_text_centered(0x8274, 0);                 /* "THE DUEL: TEST DRIVE II TOP SCORES" */
    snprintf(t, sizeof t, "%s", DSTR(scn_name(DSS(DS_scn_idx))));
    for (s16 k = 0x11; ; ) {                       /* trim trailing spaces from index 17 */
        if (t[k] != ' ') break;
        t[k] = 0;
        k--;
        if (k <= 0) break;
    }
    draw_text_centered_str(t, 10);
    for (s16 i = 0; i < 6; i++) {
        s16 c = -1;
        for (s16 j = 0; j < DSS(DS_ncars); j++) {
            if (flow_stricmp(car_rec(j), top_car(i)) == 0) { c = j; break; }
        }
        if (c != -1 && i < 4) {
            if (ensure_disk_c(flow_concat(name, sizeof name, DSTR(car_rec(c)), DSTR(0x8297)), car_disk(c), 0) != 0)
                return KEY_ESC;                                             /* "rear" */
            FarPtr a = load_shapes(DS_disk_path);
            blit_copy_raw(res_find(a, 0x829C), 0, (s16)(i * 0x26 + 0x17));  /* "logS" */
            mem_release_cache(a);
        }
        s16 y = (i < 4) ? (s16)(i * 0x26 + 0x21) : (s16)(i * 10 + 0x7D);
        snprintf(t, sizeof t, "%ld  ", (long)(s32)DSL(top_rec(i)));         /* DS:82A1 */
        gfx_draw_text_str(t, 0x50, (u16)y);
        gfx_draw_text(top_name(i), 0x90, (u16)y);
    }
    if (timeout == 1500) {
        snprintf(t, sizeof t, "Your Score:  %ld", (long)DSSL(DS_total_score));  /* DS:82A7 */
        draw_text_centered_str(t, 0xC0);
    }
    return 0;
}

/* PORT: the high scores again after a graphics switch. */
static void hisc_redraw(void *ctx)
{
    hisc_page(*(const s32 *)ctx);
    flow_show_page();
}

/* 0645:0470 hisc_show — game_flow.md §4.15 (verified against the disassembly) */
s16 hisc_show(s32 timeout)
{
    s16 r = hisc_page(timeout);
    if (r != 0) return r;
    if (gfx_amiga_screens()) {
        flow_show_page();                          /* PORT: duel swaps its screens: at once ($2a6de) */
    } else {
        r = screen_reveal(1);
        if (r != 0) return r;
    }
    r = (s16)getkey_timeout_redraw((u32)timeout, hisc_redraw, &timeout);
    amiga_fade_out(1);                             /* PORT: as duel */
    return r;
}

/* 0645:06a8 hisc_check — game_flow.md §4.15 (verified) */
s16 hisc_check(void)
{
    if ((s32)DSL(top_rec(5)) < DSSL(DS_total_score) && DSW(DS_demo_mode) == 0 && hisc_insert() != 0)
        return KEY_ESC;
    return hisc_show(1500);
}
