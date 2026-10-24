/* IFF ILBM pictures (ilbm.h). */
#include <SDL3/SDL.h>
#include <string.h>

#include "ilbm.h"
#include "rpck.h"

static u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static u32 be32(const u8 *p) { return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }

bool ilbm_read(const u8 *f, u32 len, AmigaPicture *p)
{
    memset(p, 0, sizeof *p);
    if (len < 12 || memcmp(f, "FORM", 4) != 0 || memcmp(f + 8, "ILBM", 4) != 0) return false;
    int masking = 0, packed = 0;
    const u8 *body = NULL;
    u32 body_len = 0;
    for (u32 at = 12; at + 8 <= len;) {
        u32 n = be32(f + at + 4);
        const u8 *c = f + at + 8;
        if (n > len - at - 8) return false;
        if (memcmp(f + at, "BMHD", 4) == 0 && n >= 11) {
            p->w = be16(c);
            p->h = be16(c + 2);
            p->planes = c[8];
            masking = c[9];
            packed = c[10];
        } else if (memcmp(f + at, "CMAP", 4) == 0) {
            memcpy(p->pal, c, n < sizeof p->pal ? n : sizeof p->pal);
        } else if (memcmp(f + at, "BODY", 4) == 0) {
            body = c;
            body_len = n;
        }
        at += 8 + n + (n & 1);
    }
    if (!body || p->w == 0 || p->h == 0 || p->planes < 1 || p->planes > 5) return false;
    u32 stored = p->planes + (masking == 1);            /* a mask plane follows the colour planes */
    u32 row = (p->w + 15u) / 16 * 2, total = row * p->h * stored;
    u8 *raw = SDL_malloc(total);
    p->pix = SDL_calloc(p->w, p->h);
    if (!raw || !p->pix) {
        SDL_free(raw);
        ilbm_free(p);
        return false;
    }
    u32 o = 0, i = 0;
    while (o < total && i < body_len) {
        if (!packed) {
            raw[o++] = body[i++];
            continue;
        }
        u8 k = body[i++];
        if (k < 128) {
            for (int r = 0; r <= k && i < body_len && o < total; r++) raw[o++] = body[i++];
        } else if (k > 128 && i < body_len) {
            for (int r = 0; r < 257 - k && o < total; r++) raw[o++] = body[i];
            i++;
        }
    }
    for (u32 y = 0; y < p->h; y++)
        for (u32 k = 0; k < p->planes; k++) {
            const u8 *line = raw + (y * stored + k) * row;
            for (u32 x = 0; x < p->w; x++)
                p->pix[y * p->w + x] |= (u8)((line[x >> 3] >> (7 - (x & 7)) & 1) << k);
        }
    SDL_free(raw);
    if (o != total) ilbm_free(p);
    return p->pix != NULL;
}

bool ilbm_load(const char *path, AmigaPicture *p)
{
    u32 len;
    u8 *f = rpck_load(path, &len);
    bool ok = f && ilbm_read(f, len, p);
    SDL_free(f);
    return ok;
}

void ilbm_free(AmigaPicture *p)
{
    SDL_free(p->pix);
    p->pix = NULL;
}
