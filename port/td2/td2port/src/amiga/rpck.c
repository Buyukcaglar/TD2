/* duel's Rpck unpacker (rpck.h). */
#include <SDL3/SDL.h>
#include <string.h>

#include "amiga/rpck.h"

u32 rpck_unpack(const u8 *in, u32 len, u8 *out, u32 max)
{
    if (len < 8) return 0;
    u32 size = (u32)in[4] << 24 | (u32)in[5] << 16 | (u32)in[6] << 8 | in[7];
    if (size > max) return 0;
    u32 o = 0;
    for (u32 i = 8; i < len && o < size;) {
        u8 n = in[i++];
        if (n < 0x80) {
            if (i >= len) break;
            for (u32 k = 0; k <= n && o < size; k++) out[o++] = in[i];
            i++;
        } else {
            for (u32 k = 0; k < 256u - n && i < len && o < size; k++) out[o++] = in[i++];
        }
    }
    return o == size ? size : 0;
}

u8 *rpck_load(const char *path, u32 *len)
{
    size_t n;
    u8 *raw = SDL_LoadFile(path, &n);
    if (!raw) return NULL;
    if (n < 8 || memcmp(raw, "Rpck", 4) != 0) {
        *len = (u32)n;
        return raw;
    }
    u32 size = (u32)raw[4] << 24 | (u32)raw[5] << 16 | (u32)raw[6] << 8 | raw[7];
    u8 *out = size <= 0x1000000 ? SDL_malloc(size ? size : 1) : NULL;
    if (out && rpck_unpack(raw, (u32)n, out, size) != size) {
        SDL_free(out);
        out = NULL;
    }
    SDL_free(raw);
    if (out) *len = size;
    return out;
}
