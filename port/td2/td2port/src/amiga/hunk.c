/* AmigaDOS load files (hunk.h). */
#include <SDL3/SDL.h>
#include <string.h>

#include "hunk.h"

#define HUNK_NAME 0x3E8
#define HUNK_CODE 0x3E9
#define HUNK_DATA 0x3EA
#define HUNK_BSS 0x3EB
#define HUNK_RELOC32 0x3EC
#define HUNK_SYMBOL 0x3F0
#define HUNK_DEBUG 0x3F1
#define HUNK_END 0x3F2
#define HUNK_HEADER 0x3F3
#define HUNK_DREL32 0x3F7
#define HUNK_RELOC32SHORT 0x3FC
#define MAX_HUNKS 64

static u32 be32(const u8 *p) { return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }

/* Adds the base of hunk `target` to each relocated long at `offset` of hunk `index` that lies within
 * the bytes copied out. */
static void relocate(u8 *out, u32 from, u32 n, u32 offset, u32 target_base)
{
    if (offset < from || offset + 4 > from + n) return;
    u8 *p = out + (offset - from);
    u32 v = be32(p) + target_base;
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}

static bool read_hunks(const u8 *f, size_t len, u32 addr, u8 *out, u32 n)
{
    size_t pos = 0;
#define LONG(v) do { if (pos + 4 > len) return false; (v) = be32(f + pos); pos += 4; } while (0)
    u32 v, count, first, last;
    LONG(v);
    if (v != HUNK_HEADER) return false;
    do LONG(v); while (v);                      /* resident library names */
    LONG(count);
    LONG(first);
    LONG(last);
    (void)count;
    if (last < first || last - first >= MAX_HUNKS) return false;
    u32 base[MAX_HUNKS], at = 0x10000, hunks = last - first + 1;
    for (u32 i = 0; i < hunks; i++) {
        LONG(v);
        if (v >> 30 == 3) pos += 4;
        base[i] = at;
        at = (at + (v & 0x3FFFFFFF) * 4 + 8 + 15) & ~15u;
    }
    bool found = false;                         /* copied out of this hunk; now its relocations */
    u32 from = 0;
    for (u32 index = 0; index < hunks && pos + 4 <= len;) {
        LONG(v);
        switch (v & 0x3FFFFFFF) {
        case HUNK_CODE:
        case HUNK_DATA: {
            u32 words;
            LONG(words);
            u32 size = (words & 0x3FFFFFFF) * 4;
            if (pos + size > len) return false;
            if (addr >= base[index] && addr - base[index] + n <= size) {
                from = addr - base[index];
                memcpy(out, f + pos + from, n);
                found = true;
            }
            pos += size;
            break;
        }
        case HUNK_BSS:
            pos += 4;
            break;
        case HUNK_RELOC32:
            for (;;) {
                u32 k, target;
                LONG(k);
                if (!k) break;
                LONG(target);
                if (found && target >= hunks) return false;
                for (u32 j = 0; j < k; j++) {
                    LONG(v);
                    if (found) relocate(out, from, n, v, base[target]);
                }
            }
            break;
        case HUNK_RELOC32SHORT:
        case HUNK_DREL32:
            for (;;) {
                if (pos + 4 > len) return false;
                u32 k = (u32)(f[pos] << 8 | f[pos + 1]), target = (u32)(f[pos + 2] << 8 | f[pos + 3]);
                if (!k) { pos += 2; break; }
                pos += 4;
                if (found && target >= hunks) return false;
                for (u32 j = 0; j < k; j++) {
                    if (pos + 2 > len) return false;
                    if (found) relocate(out, from, n, (u32)(f[pos] << 8 | f[pos + 1]), base[target]);
                    pos += 2;
                }
            }
            pos = (pos + 3) & ~(size_t)3;
            break;
        case HUNK_SYMBOL:
            for (;;) {
                u32 k;
                LONG(k);
                if (!k) break;
                pos += 4 * (size_t)k + 4;
            }
            break;
        case HUNK_NAME:
        case HUNK_DEBUG:
            LONG(v);
            pos += 4 * (size_t)v;
            break;
        case HUNK_END:
            if (found) return true;
            index++;
            break;
        default:                                /* the overlay table, or a hunk this reader does not know */
            return found;
        }
    }
#undef LONG
    return found;
}

bool hunk_read(const char *path, u32 addr, void *out, u32 n)
{
    size_t len;
    u8 *f = SDL_LoadFile(path, &len);
    if (!f) return false;
    bool ok = read_hunks(f, len, addr, out, n);
    SDL_free(f);
    return ok;
}
