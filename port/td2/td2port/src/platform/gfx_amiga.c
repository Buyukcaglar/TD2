/* Amiga graphics backend (docs/amiga.md, "The Amiga graphics backend"): the EGA backend's model run
 * with a fifth plane, so the screen and every off-screen buffer hold the Amiga's 32 colours.
 *
 * Each target has its colours: the EGA palette, or the 32 colours of the Amiga picture drawn into it.
 * A page drawn off-screen brings its colours to the screen when it is shown there (screen_reveal's
 * dissolve, or a blit of the buffer), as an Amiga screen brings its palette; clearing a whole target
 * gives it the EGA palette again. The game's colour numbers draw the nearest Amiga colour of the
 * target's palette, and AMIGA_PEN(n) draws pen n itself. */
#include <SDL3/SDL.h>
#include <string.h>

#include "gfx_ega.h"
#include "../amiga/hunk.h"
#include "../amiga/ilbm.h"
#include "../amiga/shp.h"

typedef struct {
    u16 seg;            /* the buffer's plane 0 segment */
    bool amiga;         /* an Amiga palette, else the EGA's */
    u32 rgb[32];
    u16 split;          /* from this line down, rgb2 (0: none) */
    u32 rgb2[32];
    u8 map[16];
} TargetColours;

#define MAX_BUFFERS 8

static char *amiga_dir;
static TargetColours screen, buffers[MAX_BUFFERS];
static int next_buffer;

/* The standard EGA colours, which the game's colour numbers mean. */
static const u8 ega_colours[16][3] = {
    { 0, 0, 0 }, { 0, 0, 170 }, { 0, 170, 0 }, { 0, 170, 170 }, { 170, 0, 0 }, { 170, 0, 170 },
    { 170, 85, 0 }, { 170, 170, 170 }, { 85, 85, 85 }, { 85, 85, 255 }, { 85, 255, 85 }, { 85, 255, 255 },
    { 255, 85, 85 }, { 255, 85, 255 }, { 255, 255, 85 }, { 255, 255, 255 },
};

static void ega_colours_of(TargetColours *t)
{
    t->amiga = false;
    t->split = 0;
    for (int i = 0; i < 16; i++) t->map[i] = (u8)i;
}

/* The screen's colours as the model composes them. */
static void show_screen_colours(void)
{
    gfx_ega.amiga_palette = screen.amiga;
    memcpy(gfx_ega.rgb, screen.rgb, sizeof gfx_ega.rgb);
    gfx_ega.split = screen.split;
    memcpy(gfx_ega.rgb2, screen.rgb2, sizeof gfx_ega.rgb2);
    memcpy(gfx_ega.colour_map, screen.map, sizeof gfx_ega.colour_map);
    gfx_ega.dirty = true;
}

void gfx_amiga_reset(void)
{
    gfx_ega_reset(5);
    memset(&screen, 0, sizeof screen);
    memset(buffers, 0, sizeof buffers);
    ega_colours_of(&screen);
    show_screen_colours();
}

static TargetColours *buffer_colours(u16 seg)
{
    for (int i = 0; i < MAX_BUFFERS; i++)
        if (buffers[i].seg == seg) return &buffers[i];
    return NULL;
}

/* The selected target's colours; NULL for a buffer this backend did not make. */
static TargetColours *target_colours(void)
{
    u16 seg = CSW(GFX_CUR_PLANE0);
    return seg == VRAM_SEG ? &screen : buffer_colours(seg);
}

u8 gfx_amiga_colour(u16 c)
{
    if (c >= AMIGA_PEN(0) && c < AMIGA_PEN(32)) return (u8)(c - AMIGA_PEN(0));
    const TargetColours *t = target_colours();
    return t ? t->map[c & 0x0F] : (u8)(c & 0x0F);
}

void gfx_amiga_buffer_created(u16 seg)
{
    TargetColours *t = buffer_colours(seg);
    if (!t) {
        t = &buffers[next_buffer];
        next_buffer = (next_buffer + 1) % MAX_BUFFERS;
    }
    memset(t, 0, sizeof *t);
    t->seg = seg;
    ega_colours_of(t);
}

void gfx_amiga_cleared(bool whole_screen)
{
    TargetColours *t = whole_screen ? &screen : target_colours();
    if (!t || !t->amiga) return;
    if (!whole_screen) {
        u16 seg = CSW(GFX_CUR_PLANE0);
        u16 rows = seg == VRAM_SEG ? 200 : rd16(seg, 2);
        if (CSW(GFX_CUR_CLIP_X0) != 0 || CSW(GFX_CUR_CLIP_Y0) != 0 || CSW(GFX_CUR_CLIP_X1) < CSW(GFX_CUR_STRIDE)
            || CSW(GFX_CUR_CLIP_Y1) < rows)
            return;
    }
    ega_colours_of(t);
    if (t == &screen) show_screen_colours();
}

void gfx_amiga_shown(FarPtr spr)
{
    const TargetColours *t = buffer_colours(spr.seg);
    if (t && t->amiga) {
        screen = *t;
        screen.seg = 0;
    } else if (screen.amiga) {
        ega_colours_of(&screen);
    } else {
        return;
    }
    show_screen_colours();
}

void gfx_amiga_open(const char *dir)
{
    SDL_free(amiga_dir);
    amiga_dir = dir ? SDL_strdup(dir) : NULL;
}

bool gfx_amiga_screens(void)
{
    return gfx_backend() == &gfx_amiga_backend && amiga_dir;
}

/* An ILBM colour as the Amiga shows it: the top 4 bits of each component. */
static u32 amiga_rgb(const u8 c[3])
{
    return (c[0] >> 4) * 17u << 16 | (c[1] >> 4) * 17u << 8 | (c[2] >> 4) * 17u;
}

/* Colours for the selected target: rgb (n of them used by the game's colour numbers), from line split
 * down rgb2. */
static void set_target_rgb(const u32 rgb[32], int n, u16 split, const u32 rgb2[32])
{
    TargetColours *t = target_colours();
    if (!t) return;
    t->amiga = true;
    memcpy(t->rgb, rgb, sizeof t->rgb);
    t->split = split;
    memcpy(t->rgb2, rgb2, sizeof t->rgb2);
    for (int c = 0; c < 16; c++) {
        int best = 0, dist = 0x7FFFFFFF;
        for (int i = 0; i < n && i < 32; i++) {
            int dr = (int)(t->rgb[i] >> 16) - ega_colours[c][0];
            int dg = (int)(t->rgb[i] >> 8 & 0xFF) - ega_colours[c][1];
            int db = (int)(t->rgb[i] & 0xFF) - ega_colours[c][2];
            int d = 3 * dr * dr + 4 * dg * dg + 2 * db * db;
            if (d < dist) { dist = d; best = i; }
        }
        t->map[c] = (u8)best;
    }
    if (t == &screen) show_screen_colours();
}

/* The picture's colours for the selected target. */
static void set_target_palette(const AmigaPicture *p)
{
    u32 rgb[32], rgb2[32];
    for (int i = 0; i < 32; i++) rgb[i] = amiga_rgb(p->pal[i]);
    for (int i = 0; i < 32; i++) rgb2[i] = amiga_rgb(p->pal2[i]);
    set_target_rgb(rgb, 1 << p->planes, p->split, rgb2);
}

void gfx_amiga_colours(const u16 *colours, int n)
{
    u32 rgb[32] = { 0 };
    for (int i = 0; i < n && i < 32; i++)
        rgb[i] = (colours[i] >> 8 & 15) * 17u << 16 | (colours[i] >> 4 & 15) * 17u << 8 | (colours[i] & 15) * 17u;
    set_target_rgb(rgb, n, 0, rgb);
}

/* Byte off of plane k of the selected target, or NULL. */
static u8 *plane_byte(int k, u16 off)
{
    if (CSW(GFX_CUR_PLANE0) == VRAM_SEG) return &gfx_ega.plane[k][off];
    return ram_plane(k) ? mp(ram_plane(k), off) : NULL;
}

void gfx_amiga_plane_clear(int k)
{
    for (u16 y = 0; y < 200; y++)
        for (u16 bx = 0; bx < 40; bx++) {
            u8 *b = plane_byte(k, (u16)(row_at(y) + bx));
            if (b) *b = 0;
        }
    if (CSW(GFX_CUR_PLANE0) == VRAM_SEG) gfx_ega.dirty = true;
}

void gfx_amiga_plane_line(int k, s16 x0, s16 y0, s16 x1, s16 y1)
{
    int dx = SDL_abs(x1 - x0), dy = -SDL_abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    for (;;) {
        if (x0 >= 0 && x0 < 320 && y0 >= 0 && y0 < 200) {
            u8 *b = plane_byte(k, (u16)(row_at((u16)y0) + (x0 >> 3)));
            if (b) *b |= (u8)(0x80 >> (x0 & 7));
        }
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 = (s16)(x0 + sx); }
        if (e2 <= dx) { err += dx; y0 = (s16)(y0 + sy); }
    }
    if (CSW(GFX_CUR_PLANE0) == VRAM_SEG) gfx_ega.dirty = true;
}

bool gfx_amiga_duel_data(u32 addr, void *out, u32 n)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/duel", amiga_dir);
    bool ok = path && hunk_read(path, addr, out, n);
    SDL_free(path);
    return ok;
}

bool gfx_amiga_picture(const char *file, s16 x, s16 y)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaPicture p;
    bool ok = path && ilbm_load(path, &p);
    SDL_free(path);
    if (!ok) return false;
    bool on_screen = CSW(GFX_CUR_PLANE0) == VRAM_SEG;
    u16 x0 = CSW(GFX_CUR_CLIP_X0), x1 = CSW(GFX_CUR_CLIP_X1);
    u16 y0 = CSW(GFX_CUR_CLIP_Y0), y1 = CSW(GFX_CUR_CLIP_Y1);
    for (int r = 0; r < p.h; r++) {
        s16 row = (s16)(y + r);
        if (row < (s16)y0 || row >= (s16)y1) continue;
        for (int bx = 0; bx < p.w / 8; bx++) {
            s16 col = (s16)(x / 8 + bx);
            if (col < (s16)x0 || col >= (s16)x1) continue;
            u16 off = (u16)(row_at((u16)row) + (u16)col);
            const u8 *src = p.pix + r * p.w + bx * 8;
            for (int k = 0; k < 5; k++) {
                u8 v = 0;
                for (int i = 0; i < 8; i++) v = (u8)(v << 1 | (src[i] >> k & 1));
                if (on_screen) gfx_ega.plane[k][off] = v;
                else if (ram_plane(k)) wr8(ram_plane(k), off, v);
            }
        }
    }
    if (on_screen) gfx_ega.dirty = true;
    set_target_palette(&p);
    ilbm_free(&p);
    return true;
}

/* One pixel of the selected target, within its clip. */
static void put_pixel(s16 x, s16 y, u8 v)
{
    if (x < (s16)(CSW(GFX_CUR_CLIP_X0) * 8) || x >= (s16)(CSW(GFX_CUR_CLIP_X1) * 8)) return;
    if (y < (s16)CSW(GFX_CUR_CLIP_Y0) || y >= (s16)CSW(GFX_CUR_CLIP_Y1)) return;
    u16 off = (u16)(row_at((u16)y) + (u16)(x >> 3));
    u8 bit = (u8)(0x80 >> (x & 7));
    bool on_screen = CSW(GFX_CUR_PLANE0) == VRAM_SEG;
    for (int k = 0; k < 5; k++) {
        u8 *b = on_screen ? &gfx_ega.plane[k][off] : ram_plane(k) ? mp(ram_plane(k), off) : NULL;
        if (b) *b = (u8)(v >> k & 1 ? *b | bit : *b & ~bit);
    }
    if (on_screen) gfx_ega.dirty = true;
}

bool gfx_amiga_sprite(const char *file, const char *name, s16 x, s16 y, AmigaPlace at)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s;
    bool ok = path && shp_load(path, name, &s);
    SDL_free(path);
    if (!ok) return false;
    bool box = at == AMIGA_BOX_AT_X;
    x = at == AMIGA_AT_OWN ? s.x : box ? x : (s16)(x - s.hot_x);
    y = at == AMIGA_AT_HOT ? (s16)(y - s.hot_y) : s.y;
    for (int r = 0; r < s.h; r++)
        for (int c = 0; c < s.w; c++)
            if (s.mask[r * s.w + c]) put_pixel((s16)(x + c), (s16)(y + r), s.pix[r * s.w + c]);
            else if (box) put_pixel((s16)(x + c), (s16)(y + r), s.set);
    shp_free(&s);
    return true;
}

bool gfx_amiga_sprite_own(const char *file, const char *name, s16 *x, s16 *y)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s;
    bool ok = path && shp_load(path, name, &s);
    SDL_free(path);
    if (!ok) return false;
    *x = s.x;
    *y = s.y;
    shp_free(&s);
    return true;
}

/* ---- the Amiga screen changes (gfx.h) */

static u8 wipe_from[5][200 * 40];      /* what the mask lets through: the page's planes, or black */
static u8 wipe_mask[200][320];

void gfx_amiga_wipe_begin(FarPtr page, bool in)
{
    memset(wipe_mask, 0, sizeof wipe_mask);
    memset(wipe_from, 0, sizeof wipe_from);
    if (in) {
        gfx_select_target(page);
        for (u16 y = 0; y < 200; y++)
            for (int k = 0; k < 5; k++)
                if (ram_plane(k)) memcpy(&wipe_from[k][y * 40], mp(ram_plane(k), row_at(y)), 40);
        const TargetColours *t = buffer_colours(CSW(GFX_CUR_PLANE0));
        select_screen();
        /* duel clears the screen and gives it the new picture's colours, and the picture grows over it */
        for (int k = 0; k < 5; k++) memset(gfx_ega.plane[k], 0, 200 * 40);
        if (t && t->amiga) {
            screen = *t;
            screen.seg = 0;
        } else {
            ega_colours_of(&screen);
        }
        show_screen_colours();
    }
}

void gfx_amiga_wipe_rect(s16 x0, s16 y0, s16 x1, s16 y1)
{
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > 319) x1 = 319;
    if (y1 > 199) y1 = 199;
    for (s16 y = y0; y <= y1; y++)
        if (x0 <= x1) memset(&wipe_mask[y][x0], 1, (size_t)(x1 - x0 + 1));
}

void gfx_amiga_wipe_line(s16 x0, s16 y0, s16 x1, s16 y1)
{
    int dx = SDL_abs(x1 - x0), dy = -SDL_abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    for (;;) {
        if (x0 >= 0 && x0 < 320 && y0 >= 0 && y0 < 200) wipe_mask[y0][x0] = 1;
        if (x0 == x1 && y0 == y1) return;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 = (s16)(x0 + sx); }
        if (e2 <= dx) { err += dx; y0 = (s16)(y0 + sy); }
    }
}

void gfx_amiga_wipe_show(void)
{
    for (int y = 0; y < 200; y++)
        for (int bx = 0; bx < 40; bx++) {
            u8 m = 0;
            for (int i = 0; i < 8; i++) m = (u8)(m << 1 | wipe_mask[y][bx * 8 + i]);
            if (!m) continue;
            int off = y * 40 + bx;
            for (int k = 0; k < 5; k++)
                gfx_ega.plane[k][off] = (u8)((gfx_ega.plane[k][off] & ~m) | (wipe_from[k][off] & m));
        }
    gfx_ega.dirty = true;
}

bool gfx_amiga_picture_scaled(const char *file, s16 sx, s16 sy, s16 sw, s16 sh, s16 x, s16 y, s16 w, s16 h)
{
    TargetColours *t = target_colours();
    if (!gfx_amiga_screens() || !t || !t->amiga || w <= 0 || h <= 0) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaPicture p;
    bool ok = path && ilbm_load(path, &p);
    SDL_free(path);
    if (!ok) return false;
    for (s16 j = 0; j < h; j++) {
        s16 row = (s16)(y + j);
        const u32 *pens = t->split && row >= (s16)t->split ? t->rgb2 : t->rgb;
        int y0 = sy + j * sh / h, y1 = sy + (j + 1) * sh / h;
        for (s16 i = 0; i < w; i++) {
            int x0 = sx + i * sw / w, x1 = sx + (i + 1) * sw / w;
            int sum[3] = { 0, 0, 0 }, n = 0;
            for (int yy = y0; yy < y1 && yy < p.h; yy++)
                for (int xx = x0; xx < x1 && xx < p.w; xx++) {
                    const u8 (*pal)[3] = p.split && yy >= p.split ? p.pal2 : p.pal;
                    u32 c = amiga_rgb(pal[p.pix[yy * p.w + xx] & 31]);
                    sum[0] += (int)(c >> 16);
                    sum[1] += (int)(c >> 8 & 0xFF);
                    sum[2] += (int)(c & 0xFF);
                    n++;
                }
            if (!n) continue;
            int best = 0, dist = 0x7FFFFFFF;
            for (int k = 0; k < 32; k++) {
                int dr = (int)(pens[k] >> 16) - sum[0] / n, dg = (int)(pens[k] >> 8 & 0xFF) - sum[1] / n;
                int db = (int)(pens[k] & 0xFF) - sum[2] / n;
                int d = 3 * dr * dr + 4 * dg * dg + 2 * db * db;
                if (d < dist) { dist = d; best = k; }
            }
            put_pixel((s16)(x + i), row, (u8)best);
        }
    }
    ilbm_free(&p);
    return true;
}
