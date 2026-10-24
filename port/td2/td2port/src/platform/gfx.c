/* Graphics library, shared half — port of the TD2EGA.EXE assembly graphics library in segment 06c9
 * (port/spec/platform.md §2.1, §4.1–4.5, §4.12; scene_render.md for 06c9:5c98 / 5ca6).
 *
 * The routines here are the same in TD2EGA and TD2CGA: target descriptors and clipping (code-segment
 * memory: CS:AF3A live copy, CS:AF54 screen descriptor, CS:AF6E screen row table, CS:B269 pool pointer,
 * CS:B26B pool, all statically initialised in the load image), the text state, sprite positioning and
 * the small C helpers. Everything that touches pixels goes to the active backend (gfx_backend.h; the
 * EGA one is gfx_ega.c and gfx_ega_blit.c). */
#include "gfx_lib.h"
#include "res.h"
#include "../host.h"

#include <string.h>

static const GfxBackend *be = &gfx_ega_backend;
static const GfxBackend *pending;
/* The load image's screen descriptor and screen row table, which the EGA backend uses as they are
 * and the CGA backends overwrite; kept for switching back to EGA. */
static u16 image_screen_desc[GFX_DESC_WORDS], image_screen_rows[200];

const GfxBackend *gfx_backend(void) { return be; }
void gfx_set_backend(const GfxBackend *b) { be = b; }

const GfxBackend *gfx_pending_backend(void) { return pending; }

void gfx_request_backend(const GfxBackend *b) { pending = b == be ? NULL : b; }

void gfx_request_next_backend(void)
{
    const GfxBackend *from = pending ? pending : be;
    gfx_request_backend(from == &gfx_ega_backend ? &gfx_cga_backend
                        : from == &gfx_cga_backend ? &gfx_herc_backend : &gfx_ega_backend);
}

/* The text colours are colour numbers of the adapter that set them (COL in gfx.h). These are the
 * (EGA, CGA) pairs the game's text uses; a switch to the other adapter translates by the first match. */
static const u16 text_colour_pairs[][2] = { { 0x0F, 3 }, { 0x0E, 3 }, { 0x0F, 2 }, { 1, 1 }, { 0, 0 } };

static u16 text_colour_for(u16 c, bool to_cga)
{
    for (size_t i = 0; i < sizeof text_colour_pairs / sizeof text_colour_pairs[0]; i++)
        if (text_colour_pairs[i][to_cga ? 0 : 1] == c) return text_colour_pairs[i][to_cga ? 1 : 0];
    return c;
}

void gfx_apply_pending_backend(void)
{
    if (!pending) return;
    if (pending->adapter != be->adapter) {
        bool to_cga = pending->adapter == GFX_CGA;
        DSW(DS_text_fg) = text_colour_for(DSW(DS_text_fg), to_cga);
        DSW(DS_text_bg) = text_colour_for(DSW(DS_text_bg), to_cga);
    }
    be = pending;
    pending = NULL;
    for (u16 i = 0; i < GFX_DESC_WORDS; i++) {
        CSW((u16)(GFX_SCREEN_DESC_OFF + 2 * i)) = image_screen_desc[i];
        CSW((u16)(GFX_CUR_OFF + 2 * i)) = image_screen_desc[i];
    }
    for (u16 y = 0; y < 200; y++) CSW((u16)(CS_gfx_screen_rows + 2 * y)) = image_screen_rows[y];
    DSB(DS_herc_mode) = 0;
    be->reset();
    be->set_mode();
    host_set_frame_source(gfx_compose, be->frame_w, be->frame_h);
    host_set_title_mode(be->name);
}

/* ------------------------------------------------------------------------------------------------ */
/* Port setup / presentation                                                                        */

void gfx_init(void)
{
    /* CS:AF3A (live copy = screen), CS:AF54 screen descriptor, CS:AF6E row table y*40, CS:B269 = B26B
     * are statically initialised in the load image; check that the image is the expected one. The
     * CGA backend's reset then writes its own screen descriptor there. */
    if (CSW(GFX_SCREEN_DESC_OFF + 2) != VRAM_SEG || CSW(GFX_SCREEN_DESC_OFF + 0x0A) != CS_gfx_screen_rows
        || CSW(CS_gfx_screen_rows + 2 * 199) != 199 * 40 || CSW(CS_gfx_rowpool_top) != CS_gfx_rowpool)
        host_fatal("gfx_init: unexpected graphics state in %s", TD_EXE_NAME);
    for (u16 i = 0; i < GFX_DESC_WORDS; i++) image_screen_desc[i] = CSW((u16)(GFX_SCREEN_DESC_OFF + 2 * i));
    for (u16 y = 0; y < 200; y++) image_screen_rows[y] = CSW((u16)(CS_gfx_screen_rows + 2 * y));
    be->reset();
    host_set_frame_source(gfx_compose, be->frame_w, be->frame_h);
    host_set_title_mode(be->name);
}

bool gfx_compose(u32 *xrgb) { return be->compose(xrgb); }

/* ------------------------------------------------------------------------------------------------ */
/* Video mode, palette                                                                              */

static void bios_equipment(u16 bits)
{
    /* PORT: BIOS data area 0040:0010 is not part of the port's memory model; the write is dropped. */
    (void)bits;
}

/* 06c9:5d00 gfx_video_hook: empty retf in the EGA build (TD2CGA restores its palette here). */
void gfx_video_hook(void) { be->video_hook(); }

/* 06c9:abfa gfx_set_palette */
void gfx_set_palette(u16 ds_table) { be->set_palette(ds_table); }

/* 06c9:90e8 gfx_init_ega */
void gfx_init_ega(void) { be->set_mode(); }

/* 06c9:642e gfx_shutdown */
void gfx_shutdown(void) { be->shutdown(); }

/* 06c9:5f64 herc_init. PORT: the Hercules hardware is dropped (TD2EGA never draws on it: all
 * primitives still write A000h, and DUEL.EXE starts Hercules through td2cga.exe). Only the flag that
 * video_shutdown tests is kept; the screen stays the EGA model. */
void herc_init(void)
{
    DSB(DS_herc_mode) = 1;
    bios_equipment(0x20);
}

/* 06c9:5fbc video_shutdown */
void video_shutdown(void)
{
    if (DSB(DS_herc_mode) == 0) {
        gfx_shutdown();
        return;
    }
    /* PORT: Hercules text mode restore (3BFh, 3B8h, 6845 from DS:5E7C, clear B800h, INT 10h mode 7)
     * dropped. */
    bios_equipment(0x30);
}

/* ------------------------------------------------------------------------------------------------ */
/* Targets and buffers                                                                              */

/* 06c9:5d9e gfx_set_clip: writes the descriptor, and the live copy when plane 0 matches */
void gfx_set_clip(FarPtr desc, s16 x0, s16 x1, s16 y0, s16 y1)
{
    bool cur = CUR_PLANE(0) == rd16(desc.seg, (u16)(desc.off + 2));
    wr16(desc.seg, (u16)(desc.off + 0x0C), (u16)x0);
    wr16(desc.seg, (u16)(desc.off + 0x0E), (u16)x1);
    wr16(desc.seg, (u16)(desc.off + 0x10), (u16)y0);
    wr16(desc.seg, (u16)(desc.off + 0x12), (u16)y1);
    if (cur) {
        CUR_X0 = (u16)x0;
        CUR_X1 = (u16)x1;
        CUR_Y0 = (u16)y0;
        CUR_Y1 = (u16)y1;
    }
}

/* 06c9:5dfb gfx_set_clip_current: live copy only */
void gfx_set_clip_current(s16 x0, s16 x1, s16 y0, s16 y1)
{
    CUR_X0 = (u16)x0;
    CUR_X1 = (u16)x1;
    CUR_Y0 = (u16)y0;
    CUR_Y1 = (u16)y1;
}

/* 06c9:7d5e gfx_select_target: 13 words -> CS:AF3A */
void gfx_select_target(FarPtr desc)
{
    for (u16 i = 0; i < GFX_DESC_WORDS; i++)
        CSW((u16)(GFX_CUR_OFF + 2 * i)) = rd16(desc.seg, (u16)(desc.off + 2 * i));
}

/* 06c9:5c98 select_screen */
void select_screen(void)
{
    gfx_select_target(gfx_screen_desc());
}

/* 06c9:78f8 / 06c9:7918: 26 words CS:AF3A.. <-> DS:buf */
void gfx_targets_save(u16 dst_ds)
{
    for (u16 i = 0; i < GFX_SAVE_WORDS; i++)
        DSW((u16)(dst_ds + 2 * i)) = CSW((u16)(GFX_CUR_OFF + 2 * i));
}

void gfx_targets_restore(u16 src_ds)
{
    for (u16 i = 0; i < GFX_SAVE_WORDS; i++)
        CSW((u16)(GFX_CUR_OFF + 2 * i)) = DSW((u16)(src_ds + 2 * i));
}

/* 06c9:b0fe gfx_create_buffer */
FarPtr gfx_create_buffer(u16 width_px, u16 h, u16 plane_mask) { return be->create_buffer(width_px, h, plane_mask); }

/* 06c9:5ca6 create_buffer_like */
FarPtr create_buffer_like(FarPtr spr, FarPtr *sprite_out)
{
    u16 w = rd16(spr.seg, spr.off);
    FarPtr desc = gfx_create_buffer((u16)(w * be->px_per_byte), rd16(spr.seg, (u16)(spr.off + 2)), 0x0F);
    FarPtr hdr = gfx_desc_sprite(desc);
    wr16(hdr.seg, (u16)(hdr.off + 8), rd16(spr.seg, (u16)(spr.off + 8)));
    wr16(hdr.seg, (u16)(hdr.off + 0x0A), rd16(spr.seg, (u16)(spr.off + 0x0A)));
    if (sprite_out) *sprite_out = hdr;
    return desc;
}

/* 06c9:782c gfx_free_buffer: pops the descriptor pool (must be the latest buffer), frees the block */
void gfx_free_buffer(FarPtr desc)
{
    FarPtr hdr = gfx_desc_sprite(desc);
    u16 h = rd16(hdr.seg, (u16)(hdr.off + 2));
    CSW(CS_gfx_rowpool_top) = (u16)(CSW(CS_gfx_rowpool_top) - (u16)((u16)(h + 0x0D) << 1));
    mem_free(hdr);
}

/* ------------------------------------------------------------------------------------------------ */
/* Clears, fills, lines, plot                                                                       */

bool gfx_is_cga(void) { return be->adapter == GFX_CGA; }
u16 gfx_px_per_byte(void) { return be->px_per_byte; }

void gfx_clear_screen(u16 colour) { be->clear_screen(colour); }   /* 06c9:840a */
void gfx_clear_clip(u16 colour) { be->clear_clip(colour); }       /* 06c9:843e */

/* 06c9:8a0c gfx_fill_rect */
void gfx_fill_rect(s16 x, s16 y, s16 w, s16 h, u16 colour)
{
    be->fill_rect(x, y, w, h, colour);
}

/* 06c9:89a2 gfx_fill_rect_clip: clip to [clip_x0*8, clip_x1*8) x [clip_y0, clip_y1) (CGA 06cf:83d2:
 * columns of 4 pixels), then 8a0c's body */
void gfx_fill_rect_clip(s16 x, s16 y, s16 w, s16 h, u16 colour)
{
    u16 X = (u16)x, Y = (u16)y, W = (u16)w, H = (u16)h;
    u16 cx0 = (u16)(CUR_X0 * be->px_per_byte);
    if (!sle(cx0, X)) {
        u16 ax = (u16)(cx0 - X);
        X = cx0;
        if (sle(W, ax)) return;
        W = (u16)(W - ax);
    }
    u16 cx1 = (u16)(CUR_X1 * be->px_per_byte);
    if (!sle((u16)(X + W), cx1)) {
        u16 ax = (u16)(X + W - cx1);
        if (sle(W, ax)) return;
        W = (u16)(W - ax);
    }
    if (!sle(CUR_Y0, Y)) {
        u16 ax = (u16)(CUR_Y0 - Y);
        Y = CUR_Y0;
        if (sle(H, ax)) return;
        H = (u16)(H - ax);
    }
    if (!sle((u16)(Y + H), CUR_Y1)) {
        u16 ax = (u16)(Y + H - CUR_Y1);
        if (sle(H, ax)) return;
        H = (u16)(H - ax);
    }
    be->fill_rect((s16)X, (s16)Y, (s16)W, (s16)H, colour);
}

/* 16af:0006 draw_rect_outline (note: the vertical sides are y1 - y0 rows, without the +1) */
void draw_rect_outline(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour)
{
    s16 w = (s16)(x1 - x0 + 1), h = (s16)(y1 - y0);
    if (w > 0) {
        gfx_fill_rect(x0, y0, w, 1, colour);
        gfx_fill_rect(x0, y1, w, 1, colour);
    }
    if (h > 0) {
        gfx_fill_rect(x0, y0, 1, h, colour);
        gfx_fill_rect(x1, y0, 1, h, colour);
    }
}

void gfx_plot(s16 x, s16 y, u16 colour) { be->plot(x, y, colour); }   /* 06c9:ba3c */

/* 06c9:8582 gfx_draw_line (pixel = colour) and 06c9:c984 gfx_draw_line_or (TD1 behaviour) */
void gfx_draw_line(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour)
{
    be->draw_line(x0, y0, x1, y1, colour, false);
}

void gfx_draw_line_or(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour)
{
    be->draw_line(x0, y0, x1, y1, colour, true);
}

/* ------------------------------------------------------------------------------------------------ */
/* 8x8 text: 06c9:a530 / a547 (body a54f in the backend), state block DS:6820                      */

void gfx_draw_text(u16 s_ds, u16 x, u16 y)
{
    DSW(DS_text_x) = x;
    DSW(DS_text_y) = y;
    be->draw_text(mp(DGROUP, s_ds));
}

void gfx_draw_text_at_cursor(u16 s_ds) { be->draw_text(mp(DGROUP, s_ds)); }

void gfx_draw_text_str(const char *s, u16 x, u16 y)
{
    DSW(DS_text_x) = x;
    DSW(DS_text_y) = y;
    be->draw_text((const u8 *)s);
}

void gfx_draw_text_at_cursor_str(const char *s) { be->draw_text((const u8 *)s); }

/* 06c9:7a82 */
void gfx_set_text_colours(u16 fg, u16 bg)
{
    DSW(DS_text_bg) = bg;
    DSW(DS_text_fg) = fg;
}

/* 06c9:7a93 (no callers) */
void gfx_set_text_cursor(u16 x, u16 y)
{
    DSW(DS_text_x) = x;
    DSW(DS_text_y) = y;
}

/* 06c9:7aa4 / 06c9:7abd: 11 words DS:6820.. <-> DS:buf */
void text_state_save(u16 buf_ds)
{
    for (u16 i = 0; i < TEXT_STATE_WORDS; i++) DSW((u16)(buf_ds + 2 * i)) = DSW((u16)(DS_text_fg + 2 * i));
}

void text_state_restore(u16 buf_ds)
{
    for (u16 i = 0; i < TEXT_STATE_WORDS; i++) DSW((u16)(DS_text_fg + 2 * i)) = DSW((u16)(buf_ds + 2 * i));
}

/* 16ab:000c draw_text_centered: x = (s16)target_width / 2 - strlen * 4 (width = CS:AF52) */
static void text_centered(const u8 *s, u16 y)
{
    u16 len = (u16)strlen((const char *)s);
    s16 half = (s16)((s16)CSW(GFX_CUR_WIDTH) / 2);                 /* cwd ; sub ax,dx ; sar ax,1 */
    DSW(DS_text_x) = (u16)(half - (s16)(u16)(len << 2));
    DSW(DS_text_y) = y;
    be->draw_text(s);
}

void draw_text_centered(u16 s_ds, u16 y) { text_centered(mp(DGROUP, s_ds), y); }
void draw_text_centered_str(const char *s, u16 y) { text_centered((const u8 *)s, y); }

/* ------------------------------------------------------------------------------------------------ */
/* Screen effects and grabs                                                                         */

void gfx_dissolve4(FarPtr spr, u8 phase) { be->dissolve(spr, phase, 4); }   /* 06c9:8cd8 */
void gfx_dissolve8(FarPtr spr, u8 phase) { be->dissolve(spr, phase, 8); }   /* 06c9:8f12 */

/* 06c9:ae62 */
void gfx_scroll_window(s16 x, s16 y, s16 w, s16 h, s16 step, FarPtr spr, s16 srow)
{
    be->scroll_window(x, y, w, h, step, spr, srow);
}

/* 06c9:c784 */
void gfx_grab_screen(s16 sx, s16 sy, s16 dx, s16 dy, s16 w_px, s16 h) { be->grab_screen(sx, sy, dx, dy, w_px, h); }

/* 06c9:ac1c / ac40 / ac64 grab_into_sprite: screen -> the sprite's stored planes */
void grab_into_sprite_hot(FarPtr spr, s16 x, s16 y)
{
    be->grab_into_sprite(spr, (u16)((u16)x - rd16(spr.seg, (u16)(spr.off + 4))),
                         (u16)((u16)y - rd16(spr.seg, (u16)(spr.off + 6))));
}

void grab_into_sprite_raw(FarPtr spr, s16 x, s16 y)
{
    wr16(spr.seg, (u16)(spr.off + 8), (u16)x);
    wr16(spr.seg, (u16)(spr.off + 0x0A), (u16)y);
    be->grab_into_sprite(spr, (u16)x, (u16)y);
}

void grab_into_sprite_own(FarPtr spr)
{
    be->grab_into_sprite(spr, (u16)(rd16(spr.seg, (u16)(spr.off + 8)) & (u16)~(be->px_per_byte - 1)),
                         rd16(spr.seg, (u16)(spr.off + 0x0A)));
}

/* ------------------------------------------------------------------------------------------------ */
/* Sprite blitters (platform.md §4.2): hot = at (x - hot_x, y - hot_y), raw = at (x, y), own = at the  */
/* header's (x, y); the body is the backend's.                                                      */

static inline u16 hdr_hot_x(FarPtr s) { return rd16(s.seg, (u16)(s.off + 4)); }
static inline u16 hdr_hot_y(FarPtr s) { return rd16(s.seg, (u16)(s.off + 6)); }
static inline u16 hdr_own_x(FarPtr s) { return rd16(s.seg, (u16)(s.off + 8)); }    /* TD2: not masked */
static inline u16 hdr_own_y(FarPtr s) { return rd16(s.seg, (u16)(s.off + 0x0A)); }

#define BLIT_FAMILY(name_hot, name_raw, name_own, op, clip)                                              \
    void name_hot(FarPtr spr, s16 x, s16 y)                                                              \
    { be->blit(spr, (u16)((u16)x - hdr_hot_x(spr)), (u16)((u16)y - hdr_hot_y(spr)), op, clip); }        \
    void name_raw(FarPtr spr, s16 x, s16 y) { be->blit(spr, (u16)x, (u16)y, op, clip); }                \
    void name_own(FarPtr spr)                                                                            \
    { be->blit(spr, (u16)(hdr_own_x(spr) & (clip ? 0xFFFF : be->own_x_mask)), hdr_own_y(spr), op, clip); }

/* 06c9:916c/91a4/91d6 */ BLIT_FAMILY(blit_copy_clip_hot, blit_copy_clip_raw, blit_copy_clip_own, BLIT_REPLACE, true)
/* 06c9:a6d8/a6f8/a718 */ BLIT_FAMILY(blit_or_clip_hot, blit_or_clip_raw, blit_or_clip_own, BLIT_OR, true)
/* 06c9:7d7c/7d9c/7dbc */ BLIT_FAMILY(blit_and_clip_hot, blit_and_clip_raw, blit_and_clip_own, BLIT_AND, true)
/* 06c9:bac8/bae8/bb08 */ BLIT_FAMILY(blit_xor_clip_hot, blit_xor_clip_raw, blit_xor_clip_own, BLIT_XOR, true)
/* 06c9:9c58/9c90/9cc2 */ BLIT_FAMILY(blit_copy_hot, blit_copy_raw, blit_copy_own, BLIT_REPLACE, false)
/* 06c9:a9d2/a9f2/aa12 */ BLIT_FAMILY(blit_or_hot, blit_or_raw, blit_or_own, BLIT_OR, false)
/* 06c9:808a/80aa/80ca */ BLIT_FAMILY(blit_and_hot, blit_and_raw, blit_and_own, BLIT_AND, false)
/* 06c9:c132/c152/c172 */ BLIT_FAMILY(blit_xor_hot, blit_xor_raw, blit_xor_own, BLIT_XOR, false)

/* 06c9:c958 draw_cursor_glyph: XOR hotspot blit of the backend's glyph idx at (x aligned to a byte, y) */
void draw_cursor_glyph(s16 x, s16 y, u16 idx)
{
    blit_xor_hot(be->cursor_glyph(idx), (s16)((u16)x & (u16)~(be->px_per_byte - 1)), y);
}
