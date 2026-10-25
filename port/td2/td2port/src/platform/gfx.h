#pragma once
/* Graphics library — port of the TD2EGA.EXE assembly graphics library in segment 06c9
 * (port/spec/platform.md §2.1, §3.1, §4.1–4.5, §4.12; scene_render.md for 06c9:5c98 / 06c9:5ca6).
 * The pixel routines run on the active backend (gfx_backend.h; EGA today), the rest in gfx.c.
 *
 * Model (platform.md §4.1): a draw *target* is the original's 13-word descriptor, living in
 * code-segment memory (the CS row pool CS:B26B..CS:BA3A, or the screen descriptor CS:AF54):
 *   +00 hdr_off, +02..+08 plane_seg[4] (0 = absent, 0xA000 = EGA screen), +0A rowtab (CS offset),
 *   +0C clip_x0, +0E clip_x1 (byte columns, x1 exclusive), +10 clip_y0, +12 clip_y1 (rows, exclusive),
 *   +14 stride (bytes per row), +16 pad, +18 width in pixels (new in TD2), +1A row table.
 * The selected target is copied to CS:AF3A..CS:AF53 (game code reads/pokes it there, e.g. the clip).
 * (hdr_off, plane_seg[0]) is the far pointer to the buffer's 16-byte sprite header.
 * Plane segment 0xA000 addresses the four EGA planes held by this module (not in mem[]); any other
 * segment is RAM in mem[]. Sprites, off-screen buffers and descriptors are FarPtrs into mem[].
 *
 * Pointer conventions (PORTING.md): far pointers are FarPtr, near DGROUP pointers are u16 DS offsets.
 * Blitters take the sprite as a FarPtr (the original pushes offset, segment).
 */
#include "../mem.h"
#include "../symbols.h"

/* ---- code-segment layout (segment 06c9 = ASM_SEG) */
#define GFX_CUR_OFF        0xAF3A      /* CS_gfx_cur: live copy of the selected descriptor (13 words) */
#define GFX_CUR_PLANE0     0xAF3C      /* CS_gfx_cur_planes */
#define GFX_CUR_ROWTAB     0xAF44      /* CS_gfx_cur_rowtab */
#define GFX_CUR_CLIP_X0    0xAF46      /* CS_gfx_cur_clip[0] (byte columns) */
#define GFX_CUR_CLIP_X1    0xAF48
#define GFX_CUR_CLIP_Y0    0xAF4A
#define GFX_CUR_CLIP_Y1    0xAF4C
#define GFX_CUR_STRIDE     0xAF4E      /* CS_gfx_cur_stride */
#define GFX_CUR_PAD        0xAF50      /* CS_gfx_cur_pad */
#define GFX_CUR_WIDTH      0xAF52      /* CS_gfx_cur_width (pixels) */
#define GFX_SCREEN_DESC_OFF 0xAF54     /* CS_gfx_screen_desc */
#define GFX_DESC_WORDS     13
#define GFX_SAVE_WORDS     26          /* gfx_targets_save/restore: live copy + screen descriptor */
#define TEXT_STATE_WORDS   11          /* text_state_save/restore: DS:6820..DS:6835 */

/* Far pointer to the screen descriptor CS:AF54 (what select_screen() selects). */
static inline FarPtr gfx_screen_desc(void) { return far_make(ASM_SEG, GFX_SCREEN_DESC_OFF); }
/* Far pointer to the sprite header of a buffer descriptor: (desc.hdr_off, desc.plane_seg[0]). */
static inline FarPtr gfx_desc_sprite(FarPtr desc)
{
    return far_make(rd16(desc.seg, (u16)(desc.off + 2)), rd16(desc.seg, desc.off));
}

/* ---- adapter differences in the game code (docs/cga.md, "Colours")
 * TD2EGA and TD2CGA share the game code, except for constants that mean pixels or colours. */
typedef enum { GFX_EGA, GFX_CGA } GfxAdapter;
bool gfx_is_cga(void);
u16  gfx_px_per_byte(void);                                             /* 8 EGA, 4 CGA */
/* A colour constant: the EGA colour number, and the CGA value (a pattern word for fills and lines,
 * a 2-bit pixel value for text and plots). */
#define COL(ega, cga) ((u16)(gfx_is_cga() ? (cga) : (ega)))
/* A horizontal position or size in bytes of a 320-pixel row (clip columns, scroll widths): EGA has
 * 40 bytes per row, CGA 80. */
#define XBYTES(n) ((s16)(gfx_is_cga() ? (n) * 2 : (n)))

/* ---- port setup / presentation (no original counterpart) */

/* Resets the backend's video model (EGA: planes, registers, default mode-0Dh palette), checks the
 * statically initialised target state in CS and installs gfx_compose with host_set_frame_source at
 * the backend's frame size. Call once after mem_load_exe() and host_init(), before the game's main(). */
void gfx_init(void);
/* Fills xrgb from the backend's screen; returns true if the screen or the palette changed since the
 * last call. */
bool gfx_compose(u32 *xrgb);

/* ---- video mode, palette */
void gfx_video_hook(void);                                              /* 06c9:5d00 (empty retf in EGA) */
void herc_init(void);                                                   /* 06c9:5f64 PORT: no Hercules */
void video_shutdown(void);                                              /* 06c9:5fbc */
void gfx_shutdown(void);                                                /* 06c9:642e */
void gfx_init_ega(void);                                                /* 06c9:90e8 */
void gfx_set_palette(u16 ds_table);                                     /* 06c9:abfa 17 bytes at DS:table */

/* ---- targets and buffers */
void   gfx_set_clip(FarPtr desc, s16 x0, s16 x1, s16 y0, s16 y1);       /* 06c9:5d9e */
void   gfx_set_clip_current(s16 x0, s16 x1, s16 y0, s16 y1);            /* 06c9:5dfb (live copy only) */
void   gfx_select_target(FarPtr desc);                                  /* 06c9:7d5e */
void   select_screen(void);                                             /* 06c9:5c98 select_target(CS:AF54) */
FarPtr gfx_create_buffer(u16 width_px, u16 h, u16 plane_mask);          /* 06c9:b0fe -> descriptor */
/* 06c9:5ca6: buffer of the sprite's size (w*8 x h, planes 0Fh) with the sprite's x, y copied into the
 * buffer header. Returns the descriptor (DX:AX); *sprite_out (may be NULL) = the buffer's sprite
 * header (CX:BX). */
FarPtr create_buffer_like(FarPtr spr, FarPtr *sprite_out);              /* 06c9:5ca6 */
void   gfx_free_buffer(FarPtr desc);                                    /* 06c9:782c */
void   gfx_targets_save(u16 dst_ds);                                    /* 06c9:78f8 26 words CS:AF3A -> DS:dst */
void   gfx_targets_restore(u16 src_ds);                                 /* 06c9:7918 */

/* ---- fills, clears, lines, plot */
void gfx_clear_screen(u16 colour);                                      /* 06c9:840a (always A000h) */
void gfx_clear_clip(u16 colour);                                        /* 06c9:843e */
void gfx_draw_line(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour);         /* 06c9:8582 pixel = colour */
void gfx_fill_rect_clip(s16 x, s16 y, s16 w, s16 h, u16 colour);        /* 06c9:89a2 */
void gfx_fill_rect(s16 x, s16 y, s16 w, s16 h, u16 colour);             /* 06c9:8a0c */
void gfx_plot(s16 x, s16 y, u16 colour);                                /* 06c9:ba3c */
void gfx_draw_line_or(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour);      /* 06c9:c984 pixel |= colour */

/* ---- screen effects, grabs */
void gfx_dissolve4(FarPtr spr, u8 phase);                               /* 06c9:8cd8 */
void gfx_dissolve8(FarPtr spr, u8 phase);                               /* 06c9:8f12 */
/* x in pixels, w in bytes; spr.seg == 0: no sprite row */
void gfx_scroll_window(s16 x, s16 y, s16 w, s16 h, s16 step, FarPtr spr, s16 srow);  /* 06c9:ae62 */
void gfx_grab_screen(s16 sx, s16 sy, s16 dx, s16 dy, s16 w_px, s16 h);  /* 06c9:c784 */
void grab_into_sprite_hot(FarPtr spr, s16 x, s16 y);                    /* 06c9:ac1c */
void grab_into_sprite_raw(FarPtr spr, s16 x, s16 y);                    /* 06c9:ac40 (stores x, y) */
void grab_into_sprite_own(FarPtr spr);                                  /* 06c9:ac64 */

/* ---- 8x8 text (state block DS:6820) */
void gfx_set_text_colours(u16 fg, u16 bg);                              /* 06c9:7a82 */
void gfx_set_text_cursor(u16 x, u16 y);                                 /* 06c9:7a93 */
void text_state_save(u16 buf_ds);                                       /* 06c9:7aa4 11 words -> DS:buf */
void text_state_restore(u16 buf_ds);                                    /* 06c9:7abd */
void gfx_draw_text(u16 s_ds, u16 x, u16 y);                             /* 06c9:a530 string at DS:s */
void gfx_draw_text_at_cursor(u16 s_ds);                                 /* 06c9:a547 */
/* PORT: the same entry points for a string that is not in DGROUP (e.g. a C buffer). */
void gfx_draw_text_str(const char *s, u16 x, u16 y);
void gfx_draw_text_at_cursor_str(const char *s);
void draw_cursor_glyph(s16 x, s16 y, u16 idx);                          /* 06c9:c958 */
/* Small C helpers in their own segments (platform.md §2.2), implemented here. */
void draw_text_centered(u16 s_ds, u16 y);                               /* 16ab:000c */
void draw_text_centered_str(const char *s, u16 y);                      /* PORT: C-string variant */
void draw_rect_outline(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour);     /* 16af:0006 */

/* ---- the Amiga graphics (gfx_amiga.c; docs/amiga.md, "The Amiga graphics backend") */
void gfx_amiga_open(const char *dir);                                   /* the Amiga game's folder, or NULL */
bool gfx_amiga_screens(void);                   /* the Amiga backend is on and has the Amiga game's files */
bool gfx_amiga_ready(void);                     /* the Amiga game's files are known */
/* Draws a picture of the Amiga game (an ILBM, by its path in the Amiga folder) into the selected target
 * at (x, y), x a multiple of 8, and gives the target its colours. False if it is not there. */
bool gfx_amiga_picture(const char *file, s16 x, s16 y);
/* Where gfx_amiga_sprite puts a sprite: its hot spot at (x, y), its own position, its hot spot at x and
 * its own top row (duel's difficulty arrow); or as a whole box, with no mask: its top left corner at x
 * and its own top row (the bar that slides in on "Accolade presents"), or its own position moved by
 * (x, y) (the showroom's car); or XORed onto the target (duel's blit $1f426) with its top left corner at
 * (x, y) or at its own position (the race's roof digits and radar lights). */
typedef enum {
    AMIGA_AT_HOT, AMIGA_AT_OWN, AMIGA_AT_HOT_X, AMIGA_BOX_AT_X, AMIGA_BOX_AT_OWN, AMIGA_XOR_AT, AMIGA_XOR_OWN
} AmigaPlace;
/* Draws sprite name of an Amiga sprite archive into the selected target. False if it is not there. */
bool gfx_amiga_sprite(const char *file, const char *name, s16 x, s16 y, AmigaPlace at);
/* A sprite's own position and its size (any may be NULL). False if it is not there. */
bool gfx_amiga_sprite_rect(const char *file, const char *name, s16 *x, s16 *y, s16 *w, s16 *h);
/* A sprite's hot point. False if it is not there. */
bool gfx_amiga_sprite_hot(const char *file, const char *name, s16 *hot_x, s16 *hot_y);
/* Keeps the screen's lines y0 to y1 - 1 as they are now; puts the rectangle (x0, y0)-(x1, y1), corners
 * x1 and y1 excluded, of what was kept back on the screen (the race's dashboard under its needles). */
void gfx_amiga_keep_lines(s16 y0, s16 y1);
void gfx_amiga_restore_rect(s16 x0, s16 y0, s16 x1, s16 y1);
/* A line in pen on the selected target, drawn only where sprite mask of an Amiga sprite archive, at its
 * own position, is drawn (a gauge's needle, inside the part the steering wheel leaves visible). False if
 * the sprite is not there. */
bool gfx_amiga_line_in(const char *file, const char *mask, s16 x0, s16 y0, s16 x1, s16 y1, u8 pen);
/* TD2's sprites on a target with Amiga colours: those of DOS archive arc are drawn as the sprites of
 * the same names (as they are, in capitals or in small letters) of the Amiga sprite archive file, their
 * hot spots at the DOS sprites' and their masks their own (the DOS masks, AND blits, are left out); the
 * others with each colour the nearest of the target's, by way of the scratch buffer desc (320 wide, as
 * high as the tallest sprite). A NULL file forgets the archives, a null desc the buffer. */
void gfx_amiga_substitute(FarPtr arc, const char *file);
void gfx_amiga_scratch(FarPtr desc);
/* Of the Amiga sprite archives files names (paths in the Amiga folder, the file name part may hold * and
 * ?), the one with most of DOS archive arc's sprites, by name and size, stands in for it; the file, or
 * NULL if none has enough of them. */
const char *gfx_amiga_substitute_best(FarPtr arc, const char *const *files, int n);
/* A file of the Amiga game, unpacked if Rpck-packed (SDL_free), or NULL. */
void *gfx_amiga_file(const char *file, u32 *len);
/* Draws the part (sx, sy, sw, sh) of an Amiga picture scaled to w x h at (x, y) of the selected target,
 * each pixel the mean colour of its part of the picture, as the nearest of the target's colours for that
 * row. For an icon on a screen that already has its colours. False if the picture is not there. */
bool gfx_amiga_picture_scaled(const char *file, s16 sx, s16 sy, s16 sw, s16 sh, s16 x, s16 y, s16 w, s16 h);
/* From line down the selected target shows colours first to 31 of an Amiga picture instead (a copper
 * list's colour moves, as on duel's high scores); splits go in line order. False if the target has no
 * Amiga colours, the picture is not there, or there are too many splits. */
bool gfx_amiga_split_colours(const char *file, u16 line, int first);
/* The selected target's colours below its last split (a picture's CMP2) become an Amiga picture's (duel
 * loads a viewport's second palette, +9Ch, so: the car's colours on the gas station). */
bool gfx_amiga_second_colours(const char *file);
/* The selected target's colours (an Amiga picture's) move below line, a split before the others, and the
 * n colours given (Amiga colour words) take the lines above it: duel's race screen, the section's road
 * colours over the dashboard's. When the first split is already at line, only the colours above it
 * change (the crash's tint). False if the target has no Amiga colours or too many splits. */
bool gfx_amiga_colours_above(const u16 *colours, int n, u16 line);
/* The game's colour number colour draws pen of the selected target's Amiga colours (TD2's road grey as
 * duel's road). */
void gfx_amiga_map_colour(u8 colour, u8 pen);
/* Blits of buffer desc onto the screen leave the screen's colours as they are, until the buffer is made
 * again; desc stays selected. For the race's view, which has the screen's colours above the dashboard. */
void gfx_amiga_keep_screen_colours(FarPtr desc);
/* Target to gets target from's colours and stays selected (a buffer blitted onto the screen brings its
 * colours, so a buffer of text for an Amiga screen takes that screen's). */
void gfx_amiga_colours_from(FarPtr from, FarPtr to);
/* One step of duel's fade out ($1a0a8): every colour component of the screen, with its splits, at most
 * level (0 to 15, the Amiga's 4 bits). False if the screen was black already, or has no Amiga colours. */
bool gfx_amiga_fade_level(int level);
/* Gives the selected target n colours as Amiga colour words (0RGB, 4 bits each). */
void gfx_amiga_colours(const u16 *colours, int n);
/* Clears plane k of the selected target, or sets plane k along a line; duel draws in one plane by
 * giving a screen's bitmap that plane alone. */
void gfx_amiga_plane_clear(int k);
void gfx_amiga_plane_line(int k, s16 x0, s16 y0, s16 x1, s16 y1);
/* n bytes of the Amiga game's program duel at addr, as tools/amiga/hunk.py lays it out. */
bool gfx_amiga_duel_data(u32 addr, void *out, u32 n);
#define AMIGA_PEN(n) ((u16)(0x20 + (n)))        /* a colour argument: pen n of the target's Amiga colours */
/* The Amiga screen changes (duel $10bf6-$10d4c; game/amiga_wipe.c draws duel's shapes): a mask that
 * grows step by step, through which the screen shows the page (in), or black (out). An in change
 * clears the screen and gives it the page's colours first. Each show copies through the whole mask. */
void gfx_amiga_wipe_begin(FarPtr page, bool in);
void gfx_amiga_wipe_rect(s16 x0, s16 y0, s16 x1, s16 y1);        /* corners included */
void gfx_amiga_wipe_line(s16 x0, s16 y0, s16 x1, s16 y1);
void gfx_amiga_wipe_show(void);
/* Shows rows y0 to y0 + h - 1 of a page moved dx pixels to the right, black elsewhere, in the page's
 * colours: an Amiga viewport of that size scrolled sideways (duel's showroom). */
void gfx_amiga_show_scrolled(FarPtr page, s16 y0, s16 h, s16 dx);
void gfx_amiga_show_view(FarPtr page, s16 y0, s16 h, s16 dx, s16 dy);   /* and moved dy pixels down */
/* A high-resolution viewport under the screen's rows from y0 (duel's car choice): rows y0 to 199 of a
 * 640-pixel, 4-colour Amiga picture, in its colours, moved dx of its pixels to the right. While it is on
 * the frame is 640 wide. */
bool gfx_amiga_hires_band(const char *file, s16 y0);
void gfx_amiga_hires_scroll(s16 dx);
void gfx_amiga_hires_off(void);

/* ---- sprite blitters (platform.md §4.2)
 * hot = at (x - hot_x, y - hot_y), raw = at (x, y), own = at the header's (x, y) (not masked in TD2).
 * *_clip_* clip against the live clip rectangle; the others do not clip. */
void blit_copy_clip_hot(FarPtr spr, s16 x, s16 y);                      /* 06c9:916c REPLACE clipped */
void blit_copy_clip_raw(FarPtr spr, s16 x, s16 y);                      /* 06c9:91a4 */
void blit_copy_clip_own(FarPtr spr);                                    /* 06c9:91d6 */
void blit_or_clip_hot(FarPtr spr, s16 x, s16 y);                        /* 06c9:a6d8 OR clipped */
void blit_or_clip_raw(FarPtr spr, s16 x, s16 y);                        /* 06c9:a6f8 */
void blit_or_clip_own(FarPtr spr);                                      /* 06c9:a718 */
void blit_and_clip_hot(FarPtr spr, s16 x, s16 y);                       /* 06c9:7d7c AND clipped */
void blit_and_clip_raw(FarPtr spr, s16 x, s16 y);                       /* 06c9:7d9c */
void blit_and_clip_own(FarPtr spr);                                     /* 06c9:7dbc */
void blit_xor_clip_hot(FarPtr spr, s16 x, s16 y);                       /* 06c9:bac8 XOR clipped */
void blit_xor_clip_raw(FarPtr spr, s16 x, s16 y);                       /* 06c9:bae8 */
void blit_xor_clip_own(FarPtr spr);                                     /* 06c9:bb08 */
void blit_copy_hot(FarPtr spr, s16 x, s16 y);                           /* 06c9:9c58 REPLACE unclipped */
void blit_copy_raw(FarPtr spr, s16 x, s16 y);                           /* 06c9:9c90 */
void blit_copy_own(FarPtr spr);                                         /* 06c9:9cc2 */
void blit_or_hot(FarPtr spr, s16 x, s16 y);                             /* 06c9:a9d2 OR unclipped */
void blit_or_raw(FarPtr spr, s16 x, s16 y);                             /* 06c9:a9f2 */
void blit_or_own(FarPtr spr);                                           /* 06c9:aa12 */
void blit_and_hot(FarPtr spr, s16 x, s16 y);                            /* 06c9:808a AND unclipped */
void blit_and_raw(FarPtr spr, s16 x, s16 y);                            /* 06c9:80aa */
void blit_and_own(FarPtr spr);                                          /* 06c9:80ca */
void blit_xor_hot(FarPtr spr, s16 x, s16 y);                            /* 06c9:c132 XOR unclipped */
void blit_xor_raw(FarPtr spr, s16 x, s16 y);                            /* 06c9:c152 */
void blit_xor_own(FarPtr spr);                                          /* 06c9:c172 */
