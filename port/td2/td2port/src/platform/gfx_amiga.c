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
#include "../host.h"
#include "../amiga/hunk.h"
#include "../amiga/ilbm.h"
#include "../amiga/rpck.h"
#include "../amiga/shp.h"

typedef struct {
    u16 seg;            /* the buffer's plane 0 segment */
    bool amiga;         /* an Amiga palette, else the EGA's */
    u32 rgb[32];
    u8 splits;          /* from each split's line down, its colours */
    GfxSplit split[GFX_SPLITS];
    u8 map[16];
    bool keep_screen;   /* a buffer whose blits onto the screen leave the screen's colours */
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
    t->splits = 0;
    for (int i = 0; i < 16; i++) t->map[i] = (u8)i;
}

/* The screen's colours as the model composes them. */
static void show_screen_colours(void)
{
    gfx_ega.amiga_palette = screen.amiga;
    memcpy(gfx_ega.rgb, screen.rgb, sizeof gfx_ega.rgb);
    gfx_ega.splits = screen.splits;
    memcpy(gfx_ega.split, screen.split, sizeof gfx_ega.split);
    memcpy(gfx_ega.colour_map, screen.map, sizeof gfx_ega.colour_map);
    gfx_ega.dirty = true;
}

/* A high-resolution band at the bottom of the screen (gfx.h): 640 pixels a row, 4 colours. */
static struct {
    bool on, dirty;
    s16 y0, dx;
    u8 pix[200][640];
    u32 rgb[4];
} hires;

static void hires_frame(bool on)
{
    hires.on = on;
    hires.dirty = true;
    host_set_frame_source(gfx_compose, on ? 640 : 320, 200);
}

void gfx_amiga_reset(void)
{
    if (hires.on) hires_frame(false);
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
    if (t && t->keep_screen) return;
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

bool gfx_amiga_ready(void) { return amiga_dir != NULL; }

bool gfx_amiga_screens(void)
{
    return gfx_backend() == &gfx_amiga_backend && amiga_dir;
}

/* An ILBM colour as the Amiga shows it: the top 4 bits of each component. */
static u32 amiga_rgb(const u8 c[3])
{
    return (c[0] >> 4) * 17u << 16 | (c[1] >> 4) * 17u << 8 | (c[2] >> 4) * 17u;
}

/* For each EGA colour, the nearest of the first n colours rgb. */
static void nearest_map(const u32 *rgb, int n, u8 map[16])
{
    for (int c = 0; c < 16; c++) {
        int best = 0, dist = 0x7FFFFFFF;
        for (int i = 0; i < n && i < 32; i++) {
            int dr = (int)(rgb[i] >> 16) - ega_colours[c][0];
            int dg = (int)(rgb[i] >> 8 & 0xFF) - ega_colours[c][1];
            int db = (int)(rgb[i] & 0xFF) - ega_colours[c][2];
            int d = 3 * dr * dr + 4 * dg * dg + 2 * db * db;
            if (d < dist) { dist = d; best = i; }
        }
        map[c] = (u8)best;
    }
}

/* Colours for the selected target: rgb (n of them used by the game's colour numbers), from line split
 * down rgb2. */
static void set_target_rgb(const u32 rgb[32], int n, u16 split, const u32 rgb2[32])
{
    TargetColours *t = target_colours();
    if (!t) return;
    t->amiga = true;
    memcpy(t->rgb, rgb, sizeof t->rgb);
    t->splits = split ? 1 : 0;
    t->split[0].line = split;
    memcpy(t->split[0].rgb, rgb2, sizeof t->split[0].rgb);
    nearest_map(t->rgb, n, t->map);
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

void gfx_amiga_colours_from(FarPtr from, FarPtr to)
{
    gfx_select_target(from);
    const TargetColours *f = target_colours();
    TargetColours copy;
    bool ok = f != NULL;
    if (ok) copy = *f;
    gfx_select_target(to);
    TargetColours *t = target_colours();
    if (!ok || !t) return;
    u16 seg = t->seg;
    *t = copy;
    t->seg = seg;
    if (t == &screen) show_screen_colours();
}

bool gfx_amiga_colours_above(const u16 *colours, int n, u16 line)
{
    TargetColours *t = target_colours();
    if (!gfx_amiga_screens() || !t || !t->amiga || line == 0) return false;
    if (t->splits == 0 || t->split[0].line != line) {   /* a split there already: only the colours change */
        if (t->splits >= GFX_SPLITS) return false;
        memmove(&t->split[1], &t->split[0], t->splits * sizeof t->split[0]);
        t->splits++;
        t->split[0].line = line;
        memcpy(t->split[0].rgb, t->rgb, sizeof t->rgb);
    }
    for (int i = 0; i < 32; i++) {
        u16 c = i < n ? colours[i] : 0;
        t->rgb[i] = (c >> 8 & 15) * 17u << 16 | (c >> 4 & 15) * 17u << 8 | (c & 15) * 17u;
    }
    nearest_map(t->rgb, 32, t->map);
    if (t == &screen) show_screen_colours();
    return true;
}

void gfx_amiga_map_colour(u8 colour, u8 pen)
{
    TargetColours *t = target_colours();
    if (t && t->amiga) t->map[colour & 15] = (u8)(pen & 31);
}

void gfx_amiga_keep_screen_colours(FarPtr desc)
{
    gfx_select_target(desc);
    TargetColours *t = target_colours();
    if (t && t != &screen) t->keep_screen = true;
}

bool gfx_amiga_second_colours(const char *file)
{
    TargetColours *t = target_colours();
    if (!gfx_amiga_screens() || !t || !t->amiga || t->splits == 0) return false;
    return gfx_amiga_split_colours(file, t->split[t->splits - 1].line, 0);
}

bool gfx_amiga_split_colours(const char *file, u16 line, int first)
{
    TargetColours *t = target_colours();
    if (!gfx_amiga_screens() || !t || !t->amiga || t->splits >= GFX_SPLITS) return false;
    if (t->splits && line < t->split[t->splits - 1].line) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaPicture p;
    bool ok = path && ilbm_load(path, &p);
    SDL_free(path);
    if (!ok) return false;
    GfxSplit *s = &t->split[t->splits];
    memcpy(s->rgb, gfx_split_row(t->rgb, t->split, t->splits, line), sizeof s->rgb);
    for (int i = first; i < 32; i++) s->rgb[i] = amiga_rgb(p.pal[i]);
    s->line = line;
    t->splits++;
    ilbm_free(&p);
    if (t == &screen) show_screen_colours();
    return true;
}

bool gfx_amiga_fade_level(int level)
{
    if (!screen.amiga) return false;
    u32 cap = (u32)(level < 0 ? 0 : level > 15 ? 15 : level) * 17u;
    bool lit = false;
    for (int s = -1; s < screen.splits; s++) {
        u32 *rgb = s < 0 ? screen.rgb : screen.split[s].rgb;
        for (int i = 0; i < 32; i++) {
            u32 r = rgb[i] >> 16 & 0xFF, g = rgb[i] >> 8 & 0xFF, b = rgb[i] & 0xFF;
            lit = lit || r || g || b;
            rgb[i] = (r < cap ? r : cap) << 16 | (g < cap ? g : cap) << 8 | (b < cap ? b : cap);
        }
    }
    show_screen_colours();
    return lit;
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

/* One pixel of the selected target, within its clip: colour v, or XORed with v. */
static void draw_pixel(s16 x, s16 y, u8 v, bool xor)
{
    if (x < (s16)(CSW(GFX_CUR_CLIP_X0) * 8) || x >= (s16)(CSW(GFX_CUR_CLIP_X1) * 8)) return;
    if (y < (s16)CSW(GFX_CUR_CLIP_Y0) || y >= (s16)CSW(GFX_CUR_CLIP_Y1)) return;
    u16 off = (u16)(row_at((u16)y) + (u16)(x >> 3));
    u8 bit = (u8)(0x80 >> (x & 7));
    bool on_screen = CSW(GFX_CUR_PLANE0) == VRAM_SEG;
    for (int k = 0; k < 5; k++) {
        u8 *b = on_screen ? &gfx_ega.plane[k][off] : ram_plane(k) ? mp(ram_plane(k), off) : NULL;
        if (b && xor) *b = (u8)(v >> k & 1 ? *b ^ bit : *b);
        else if (b) *b = (u8)(v >> k & 1 ? *b | bit : *b & ~bit);
    }
    if (on_screen) gfx_ega.dirty = true;
}

static void put_pixel(s16 x, s16 y, u8 v) { draw_pixel(x, y, v, false); }

bool gfx_amiga_sprite(const char *file, const char *name, s16 x, s16 y, AmigaPlace at)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s;
    bool ok = path && shp_load(path, name, &s);
    SDL_free(path);
    if (!ok) return false;
    bool box = at == AMIGA_BOX_AT_X || at == AMIGA_BOX_AT_OWN, xor = at == AMIGA_XOR_AT || at == AMIGA_XOR_OWN;
    if (at == AMIGA_XOR_AT) {
    } else if (at == AMIGA_XOR_OWN) {
        x = s.x;
        y = s.y;
    } else {
        x = at == AMIGA_AT_OWN ? s.x : at == AMIGA_BOX_AT_OWN ? (s16)(s.x + x) : box ? x : (s16)(x - s.hot_x);
        y = at == AMIGA_AT_HOT ? (s16)(y - s.hot_y) : at == AMIGA_BOX_AT_OWN ? (s16)(s.y + y) : s.y;
    }
    for (int r = 0; r < s.h; r++)
        for (int c = 0; c < s.w; c++)
            if (s.mask[r * s.w + c]) draw_pixel((s16)(x + c), (s16)(y + r), s.pix[r * s.w + c], xor);
            else if (box) put_pixel((s16)(x + c), (s16)(y + r), s.set);
    shp_free(&s);
    return true;
}

bool gfx_amiga_sprite_rect(const char *file, const char *name, s16 *x, s16 *y, s16 *w, s16 *h)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s;
    bool ok = path && shp_load(path, name, &s);
    SDL_free(path);
    if (!ok) return false;
    if (x) *x = s.x;
    if (y) *y = s.y;
    if (w) *w = (s16)s.w;
    if (h) *h = (s16)s.h;
    shp_free(&s);
    return true;
}

bool gfx_amiga_sprite_hot(const char *file, const char *name, s16 *hot_x, s16 *hot_y)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s;
    bool ok = path && shp_load(path, name, &s);
    SDL_free(path);
    if (!ok) return false;
    *hot_x = s.hot_x;
    *hot_y = s.hot_y;
    shp_free(&s);
    return true;
}

static u8 kept[5][200 * 40];           /* the screen's lines as gfx_amiga_keep_lines took them */

void gfx_amiga_keep_lines(s16 y0, s16 y1)
{
    for (s16 y = y0 < 0 ? 0 : y0; y < y1 && y < 200; y++)
        for (int k = 0; k < 5; k++) memcpy(&kept[k][y * 40], &gfx_ega.plane[k][y * 40], 40);
}

void gfx_amiga_restore_rect(s16 x0, s16 y0, s16 x1, s16 y1)
{
    if (x0 < 0) x0 = 0;
    if (x1 > 320) x1 = 320;
    if (x0 >= x1) return;
    for (s16 y = y0 < 0 ? 0 : y0; y < y1 && y < 200; y++)
        if (!(x0 & 7) && !(x1 & 7)) {
            for (int k = 0; k < 5; k++)
                memcpy(&gfx_ega.plane[k][y * 40 + (x0 >> 3)], &kept[k][y * 40 + (x0 >> 3)], (size_t)((x1 - x0) >> 3));
        } else for (s16 x = x0; x < x1; x++) {
            u16 off = (u16)(y * 40 + (x >> 3));
            u8 bit = (u8)(0x80 >> (x & 7));
            for (int k = 0; k < 5; k++)
                gfx_ega.plane[k][off] = (u8)((gfx_ega.plane[k][off] & ~bit) | (kept[k][off] & bit));
        }
    gfx_ega.dirty = true;
}

bool gfx_amiga_sprite_xored(const char *file, const char *name, const char *xor_name, s16 x, s16 y)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s, o;
    bool ok = path && shp_load(path, name, &s);
    bool other = ok && shp_load(path, xor_name, &o);
    SDL_free(path);
    if (!ok) return false;
    x = (s16)(x - s.hot_x);
    y = (s16)(y - s.hot_y);
    for (int r = 0; r < s.h; r++)
        for (int c = 0; c < s.w; c++) {
            u8 v = s.mask[r * s.w + c] ? s.pix[r * s.w + c] : 0;
            if (other && r < o.h && c < o.w && o.mask[r * o.w + c]) v ^= o.pix[r * o.w + c];
            if (v) put_pixel((s16)(x + c), (s16)(y + r), v);
        }
    if (other) shp_free(&o);
    shp_free(&s);
    return true;
}

/* A line in pen into the target's planes, where mask (if any) is drawn. */
static void pen_line(s16 x0, s16 y0, s16 x1, s16 y1, u8 pen, const AmigaSprite *mask)
{
    int dx = SDL_abs(x1 - x0), dy = -SDL_abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    for (;;) {
        int c = mask ? x0 - mask->x : 0, r = mask ? y0 - mask->y : 0;
        if (!mask || (c >= 0 && c < mask->w && r >= 0 && r < mask->h && mask->mask[r * mask->w + c]))
            put_pixel(x0, y0, pen);
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 = (s16)(x0 + sx); }
        if (e2 <= dx) { err += dx; y0 = (s16)(y0 + sy); }
    }
}

bool gfx_amiga_line_in(const char *file, const char *mask, s16 x0, s16 y0, s16 x1, s16 y1, u8 pen)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaSprite s;
    bool ok = path && shp_load(path, mask, &s);
    SDL_free(path);
    if (!ok) return false;
    pen_line(x0, y0, x1, y1, pen, &s);
    shp_free(&s);
    return true;
}

void gfx_amiga_line(s16 x0, s16 y0, s16 x1, s16 y1, u8 pen) { pen_line(x0, y0, x1, y1, pen, NULL); }

/* ---- TD2's sprites on Amiga targets (gfx.h) */

#define MAX_SUBSTITUTES 12
static struct { FarPtr arc; char file[48]; } substitutes[MAX_SUBSTITUTES];
static int substitute_count;
static FarPtr scratch;                  /* a buffer TD2's sprites are drawn into to be translated */

void gfx_amiga_substitute(FarPtr arc, const char *file)
{
    if (!file) {
        substitute_count = 0;
        return;
    }
    if (substitute_count < MAX_SUBSTITUTES && (arc.seg || arc.off)) {
        substitutes[substitute_count].arc = arc;
        SDL_strlcpy(substitutes[substitute_count].file, file, sizeof substitutes[0].file);
        substitute_count++;
    }
}

void gfx_amiga_scratch(FarPtr desc) { scratch = desc; }

/* How many of DOS archive arc's sprites the Amiga archive path has, by name in any case and size. */
static int match_score(FarPtr arc, const char *path)
{
    u16 count = rd16(arc.seg, (u16)(arc.off + 4));
    u32 base = ((u32)arc.seg << 4) + (u16)((count << 3) + 6);
    int score = 0;
    for (u16 k = 0; k < count; k++) {
        char n[5];
        for (int j = 0; j < 4; j++) n[j] = (char)rd8(arc.seg, (u16)(arc.off + 6 + 4 * k + j));
        n[4] = 0;
        u32 lin = base + rd32(arc.seg, (u16)(arc.off + 6 + 4 * count + 4 * k));
        FarPtr spr = far_make((u16)(lin >> 4), (u16)(lin & 15));
        u16 dw = (u16)(rd16(spr.seg, spr.off) * 8), dh = rd16(spr.seg, (u16)(spr.off + 2)), w, h;
        for (int pass = 0; pass < 3; pass++) {
            char c[5];
            for (int j = 0; j < 5; j++)
                c[j] = pass == 0 ? n[j] : pass == 1 ? (char)SDL_toupper(n[j]) : (char)SDL_tolower(n[j]);
            if (shp_size(path, c, &w, &h)) {
                score += w == dw && h == dh ? 2 : 1;
                break;
            }
        }
    }
    return score;
}

const char *gfx_amiga_substitute_best(FarPtr arc, const char *const *files, int n)
{
    static char best[48];
    int best_score = 0;
    if (!gfx_amiga_screens() || !(arc.seg || arc.off)) return NULL;
    for (int i = 0; i < n; i++) {
        if (!files[i]) continue;
        char *pattern = NULL, *dir = NULL;
        const char *slash = SDL_strrchr(files[i], '/');
        SDL_asprintf(&dir, "%s/%.*s", amiga_dir, slash ? (int)(slash - files[i]) : 0, files[i]);
        SDL_asprintf(&pattern, "%s", slash ? slash + 1 : files[i]);
        int found = 0;
        char **names = dir && pattern ? SDL_GlobDirectory(dir, pattern, SDL_GLOB_CASEINSENSITIVE, &found) : NULL;
        for (int k = 0; k < found; k++) {
            char rel[48], *path = NULL;
            SDL_snprintf(rel, sizeof rel, "%.*s%s", slash ? (int)(slash - files[i] + 1) : 0, files[i], names[k]);
            SDL_asprintf(&path, "%s/%s", amiga_dir, rel);
            int s = path ? match_score(arc, path) : 0;
            SDL_free(path);
            if (s > best_score) {
                best_score = s;
                SDL_strlcpy(best, rel, sizeof best);
            }
        }
        SDL_free(names);
        SDL_free(dir);
        SDL_free(pattern);
    }
    if (best_score < 4) return NULL;
    gfx_amiga_substitute(arc, best);
    return best;
}

/* The Amiga file standing in for the archive spr is an entry of, and the entry's name. */
static const char *substitute_of(FarPtr spr, char name[5])
{
    u32 lin = ((u32)spr.seg << 4) + spr.off;
    for (int i = 0; i < substitute_count; i++) {
        FarPtr a = substitutes[i].arc;
        u16 count = rd16(a.seg, (u16)(a.off + 4));
        u32 base = ((u32)a.seg << 4) + (u16)((count << 3) + 6);   /* as res_find_core adds it */
        for (u16 k = 0; k < count; k++)
            if (base + rd32(a.seg, (u16)(a.off + 6 + 4 * count + 4 * k)) == lin) {
                for (int j = 0; j < 4; j++) name[j] = (char)rd8(a.seg, (u16)(a.off + 6 + 4 * k + j));
                name[4] = 0;
                return substitutes[i].file;
            }
    }
    return NULL;
}

/* The Amiga sprite of a DOS name: as it is, in capitals, or in small letters. */
static bool sprite_any_case(const char *file, const char *name, s16 x, s16 y, AmigaPlace at)
{
    char n[5];
    for (int pass = 0; pass < 3; pass++) {
        for (int j = 0; j < 5; j++)
            n[j] = pass == 0 ? name[j] : pass == 1 ? (char)SDL_toupper(name[j]) : (char)SDL_tolower(name[j]);
        if ((pass == 0 || SDL_strcmp(n, name) != 0) && gfx_amiga_sprite(file, n, x, y, at)) return true;
    }
    return false;
}

/* A DOS sprite on the selected target, each colour the nearest of the target's: drawn as it is into the
 * scratch buffer, then pixel by pixel as the operation would leave it (AND with a mask clears where the
 * mask is 0, OR and XOR set where the sprite is not 0, a copy sets the whole box). */
static bool blit_translated(const TargetColours *t, FarPtr spr, u16 px, u16 py, BlitOp op)
{
    static u8 pix[320 * 200];
    u16 w = (u16)(rd16(spr.seg, spr.off) * 8), h = rd16(spr.seg, (u16)(spr.off + 2));
    if (!scratch.seg || w == 0 || w > 320 || h == 0) return false;
    u16 cur[GFX_DESC_WORDS];
    for (int i = 0; i < GFX_DESC_WORDS; i++) cur[i] = CSW((u16)(GFX_CUR_OFF + 2 * i));
    gfx_select_target(scratch);
    u16 rows = CSW(GFX_CUR_CLIP_Y1);
    if (h > rows) h = rows;
    for (u16 y = 0; y < h; y++)
        for (int k = 0; k < 5; k++)
            if (ram_plane(k)) for (u16 b = 0; b < w / 8 && b < 40; b++) wr8(ram_plane(k), (u16)(row_at(y) + b), 0);
    ega_blit(spr, 0, 0, BLIT_REPLACE, true);
    for (u16 y = 0; y < h; y++)
        for (u16 x = 0; x < w; x++) {
            u8 v = 0;
            for (int k = 0; k < 4; k++)
                if (ram_plane(k) && rd8(ram_plane(k), (u16)(row_at(y) + (x >> 3))) & (0x80 >> (x & 7))) v |= (u8)(1 << k);
            pix[y * w + x] = v;
        }
    for (int i = 0; i < GFX_DESC_WORDS; i++) CSW((u16)(GFX_CUR_OFF + 2 * i)) = cur[i];
    for (u16 y = 0; y < h; y++)
        for (u16 x = 0; x < w; x++) {
            u8 v = pix[y * w + x];
            s16 dx = (s16)(px + x), dy = (s16)(py + y);
            if (op == BLIT_AND) { if (v == 0) put_pixel(dx, dy, t->map[0]); }
            else if (op == BLIT_REPLACE || v) put_pixel(dx, dy, t->map[v]);
        }
    return true;
}

void gfx_amiga_blit(FarPtr spr, u16 px, u16 py, BlitOp op, bool clip)
{
    const TargetColours *t = target_colours();
    if (!amiga_dir || gfx_backend() != &gfx_amiga_backend || !t || !t->amiga || ega_buffer_sprite(spr)) {
        ega_blit(spr, px, py, op, clip);
        return;
    }
    char name[5];
    const char *file = substitute_of(spr, name);
    if (file) {
        if (op == BLIT_AND) return;                     /* duel's sprites carry their masks */
        s16 hx = (s16)(px + rd16(spr.seg, (u16)(spr.off + 4))), hy = (s16)(py + rd16(spr.seg, (u16)(spr.off + 6)));
        if (sprite_any_case(file, name, hx, hy, AMIGA_AT_HOT)) return;
    }
    if (!blit_translated(t, spr, px, py, op)) ega_blit(spr, px, py, op, clip);
}

void *gfx_amiga_file(const char *file, u32 *len)
{
    if (!gfx_amiga_screens()) return NULL;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    u8 *f = path ? rpck_load(path, len) : NULL;
    SDL_free(path);
    return f;
}

/* ---- the Amiga screen changes (gfx.h) */

static u8 wipe_from[5][200 * 40];      /* what the mask lets through: the page's planes, or black */
static u8 wipe_mask[200][320];

void gfx_amiga_wipe_begin(FarPtr page, bool in, bool clear)
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
        /* the screen gets the new picture's colours, and the picture grows over it */
        if (clear)
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

void gfx_amiga_show_scrolled(FarPtr page, s16 y0, s16 h, s16 dx) { gfx_amiga_show_view(page, y0, h, dx, 0); }

void gfx_amiga_show_view(FarPtr page, s16 y0, s16 h, s16 dx, s16 dy)
{
    static u8 rows[5][200 * 40];
    gfx_select_target(page);
    const TargetColours *t = buffer_colours(CSW(GFX_CUR_PLANE0));
    for (s16 y = y0; y < y0 + h && y < 200; y++)
        for (int k = 0; k < 5; k++)
            if (y >= 0 && ram_plane(k)) memcpy(&rows[k][y * 40], mp(ram_plane(k), row_at((u16)y)), 40);
    select_screen();
    for (int k = 0; k < 5; k++) memset(gfx_ega.plane[k], 0, 200 * 40);
    for (s16 y = y0 < 0 ? 0 : y0; y < y0 + h && y < 200; y++) {
        s16 sy = (s16)(y - dy);
        if (sy < y0 || sy >= y0 + h) continue;
        for (int x = 0; x < 320; x++) {
            int src = x - dx;
            if (src < 0 || src >= 320) continue;
            u8 from = (u8)(0x80 >> (src & 7)), to = (u8)(0x80 >> (x & 7));
            for (int k = 0; k < 5; k++)
                if (rows[k][sy * 40 + (src >> 3)] & from) gfx_ega.plane[k][y * 40 + (x >> 3)] |= to;
        }
    }
    if (t && t->amiga) {
        screen = *t;
        screen.seg = 0;
        show_screen_colours();
    }
    gfx_ega.dirty = true;
}

bool gfx_amiga_hires_band(const char *file, s16 y0)
{
    if (!gfx_amiga_screens()) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", amiga_dir, file);
    AmigaPicture p;
    bool ok = path && ilbm_load(path, &p);
    SDL_free(path);
    if (!ok) return false;
    memset(hires.pix, 0, sizeof hires.pix);
    for (int y = y0; y < 200 && y < p.h; y++)
        for (int x = 0; x < 640 && x < p.w; x++) hires.pix[y][x] = (u8)(p.pix[y * p.w + x] & 3);
    for (int i = 0; i < 4; i++) hires.rgb[i] = amiga_rgb(p.pal[i]);
    ilbm_free(&p);
    hires.y0 = y0;
    hires.dx = 0;
    hires_frame(true);
    return true;
}

void gfx_amiga_hires_scroll(s16 dx)
{
    hires.dx = dx;
    hires.dirty = true;
}

void gfx_amiga_hires_off(void)
{
    if (hires.on) hires_frame(false);
}

/* With a high-resolution band the frame is 640 wide: the rows above it show each pixel twice. */
bool gfx_amiga_compose(u32 *xrgb)
{
    static u32 lores[320 * 200];
    if (!hires.on) return gfx_ega_compose(xrgb);
    bool changed = gfx_ega_compose(lores);
    if (!changed && !hires.dirty) return false;
    hires.dirty = false;
    for (int y = 0; y < 200; y++) {
        u32 *row = xrgb + y * 640;
        if (y < hires.y0) {
            for (int x = 0; x < 640; x++) row[x] = lores[y * 320 + x / 2];
            continue;
        }
        for (int x = 0; x < 640; x++) {
            int src = x - hires.dx;
            row[x] = src >= 0 && src < 640 ? hires.rgb[hires.pix[y][src]] : hires.rgb[0];
        }
    }
    return true;
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
        const u32 *pens = gfx_split_row(t->rgb, t->split, t->splits, row);
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
