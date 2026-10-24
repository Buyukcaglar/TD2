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
#include "../amiga/ilbm.h"

typedef struct {
    u16 seg;            /* the buffer's plane 0 segment */
    bool amiga;         /* an Amiga palette, else the EGA's */
    u32 rgb[32];
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
    for (int i = 0; i < 16; i++) t->map[i] = (u8)i;
}

/* The screen's colours as the model composes them. */
static void show_screen_colours(void)
{
    gfx_ega.amiga_palette = screen.amiga;
    memcpy(gfx_ega.rgb, screen.rgb, sizeof gfx_ega.rgb);
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

/* The picture's colours for the selected target: the Amiga shows the top 4 bits of each component. */
static void set_target_palette(const AmigaPicture *p)
{
    TargetColours *t = target_colours();
    if (!t) return;
    t->amiga = true;
    for (int i = 0; i < 32; i++) {
        u32 r = (p->pal[i][0] >> 4) * 17u, g = (p->pal[i][1] >> 4) * 17u, b = (p->pal[i][2] >> 4) * 17u;
        t->rgb[i] = r << 16 | g << 8 | b;
    }
    for (int c = 0; c < 16; c++) {
        int best = 0, dist = 0x7FFFFFFF;
        for (int i = 0; i < (1 << p->planes) && i < 32; i++) {
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
