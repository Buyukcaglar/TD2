/* The Amiga sprite archives (shp.h). */
#include <SDL3/SDL.h>
#include <string.h>

#include "rpck.h"
#include "shp.h"

static u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static u32 be32(const u8 *p) { return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }

static bool decode(const u8 *d, u32 len, AmigaSprite *s)
{
    if (len < 20) return false;
    u16 wb = be16(d);
    s->w = (u16)(wb * 8);
    s->h = be16(d + 2);
    s->hot_x = (s16)be16(d + 4);
    s->hot_y = (s16)be16(d + 6);
    s->x = (s16)be16(d + 8);
    s->y = (s16)be16(d + 10);
    s->set = d[13];                     /* duel's blit ($1f0f6) clears the planes of +12, sets those of +13 */
    int planes = 0;
    while (planes < 6 && d[14 + planes]) planes++;
    u32 n = (u32)wb * s->h;
    if (20 + n * planes > len) return false;
    s->pix = SDL_calloc(s->w, s->h);
    s->mask = SDL_calloc(s->w, s->h);
    if (!s->pix || !s->mask) return false;
    for (int k = 0; k < planes; k++)
        for (u32 i = 0; i < n; i++) {
            u8 b = d[20 + k * n + i];
            u32 base = i / wb * s->w + i % wb * 8;
            for (int bit = 0; bit < 8; bit++)
                if (b & (0x80 >> bit)) {
                    s->pix[base + bit] |= d[14 + k];
                    s->mask[base + bit] = 1;
                }
        }
    for (u32 i = 0; i < (u32)s->w * s->h; i++)
        if (s->mask[i]) s->pix[i] |= s->set;
    return true;
}

/* The last few archives unpacked, as the race draws its cockpit's sprites every frame. */
#define CACHED 4
static struct { char *path; u8 *arc; u32 len; } cache[CACHED];
static int cache_next;

static const u8 *archive(const char *path, u32 *len)
{
    for (int i = 0; i < CACHED; i++)
        if (cache[i].path && SDL_strcmp(cache[i].path, path) == 0) {
            *len = cache[i].len;
            return cache[i].arc;
        }
    u8 *arc = rpck_load(path, len);
    if (!arc) return NULL;
    int i = cache_next;
    cache_next = (cache_next + 1) % CACHED;
    SDL_free(cache[i].path);
    SDL_free(cache[i].arc);
    cache[i].path = SDL_strdup(path);
    cache[i].arc = arc;
    cache[i].len = *len;
    return arc;
}

bool shp_load(const char *path, const char *name, AmigaSprite *s)
{
    memset(s, 0, sizeof *s);
    u32 len;
    const u8 *arc = archive(path, &len);
    bool ok = false;
    if (arc && len >= 6) {
        u16 count = be16(arc + 4);
        u32 base = 6 + 8u * count;
        for (u16 i = 0; i < count && base <= len; i++) {
            if (memcmp(arc + 6 + 4 * i, name, 4) != 0) continue;
            u32 at = base + be32(arc + 6 + 4 * count + 4 * i);
            ok = at < len && decode(arc + at, len - at, s);
            break;
        }
    }
    if (!ok) shp_free(s);
    return ok;
}

bool shp_size(const char *path, const char *name, u16 *w, u16 *h)
{
    u32 len;
    const u8 *arc = archive(path, &len);
    if (!arc || len < 6) return false;
    u16 count = be16(arc + 4);
    u32 base = 6 + 8u * count;
    for (u16 i = 0; i < count && base <= len; i++) {
        if (memcmp(arc + 6 + 4 * i, name, 4) != 0) continue;
        u32 at = base + be32(arc + 6 + 4 * count + 4 * i);
        if (at + 4 > len) return false;
        *w = (u16)(be16(arc + at) * 8);
        *h = be16(arc + at + 2);
        return true;
    }
    return false;
}

void shp_free(AmigaSprite *s)
{
    SDL_free(s->pix);
    SDL_free(s->mask);
    s->pix = s->mask = NULL;
}
