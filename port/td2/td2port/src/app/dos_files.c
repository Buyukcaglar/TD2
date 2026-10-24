/* The DOS game's packed files outside the game's memory (dos_files.h). */
#include <SDL3/SDL.h>

#include "dos_files.h"

typedef struct { const u8 *p; size_t n; } Src;

static u32 rd24(const u8 *p) { return p[0] | p[1] << 8 | (u32)p[2] << 16; }
static u32 rd32(const u8 *p) { return p[0] | p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24; }

/* A Huffman pass (huff_decode, 06c9:7c16): canonical codes read LSB first, optionally delta coded. */
static u8 *huffman(Src s, size_t *out_len)
{
    if (s.n < 5) return NULL;
    u32 size = rd24(s.p + 1);
    u8 nb = s.p[4];
    int nlen = nb & 0x7F;
    size_t pos = 5;
    int offs[128], lims[128];
    int cx = 0, dx = 0, di = 0;
    for (int i = 0; i < nlen; i++) {
        if (pos >= s.n) return NULL;
        dx <<= 1;
        offs[i] = cx - dx;
        int c = s.p[pos++];
        dx += c;
        cx += c;
        if (c) di = dx;
        lims[i] = di;
    }
    const u8 *alpha = s.p + pos;
    pos += (size_t)cx;
    if (pos > s.n) return NULL;
    u8 *out = SDL_malloc(size ? size : 1);
    if (!out) return NULL;
    u8 prev = 0, bits = 0;
    int nbits = 0;
    for (u32 o = 0; o < size; o++) {
        int code = 0, level = 0;
        for (;;) {
            if (nbits == 0) {
                if (pos >= s.n) { SDL_free(out); return NULL; }
                bits = s.p[pos++];
                nbits = 8;
            }
            code = code << 1 | (bits & 1);
            bits >>= 1;
            nbits--;
            if (code < lims[level]) break;
            if (++level >= nlen) { SDL_free(out); return NULL; }
        }
        int k = code + offs[level];
        if (k < 0 || k >= cx) { SDL_free(out); return NULL; }
        u8 v = alpha[k];
        if (nb & 0x80) v = prev = (u8)(v + prev);
        out[o] = v;
    }
    *out_len = size;
    return out;
}

/* The sequence pass of an RLE pass: bytes between two markers, then a count, repeat as a block. */
static u8 *sequences(Src s, u32 count, u8 seq, size_t cap, size_t *out_len)
{
    u8 *out = SDL_malloc(cap ? cap : 1);
    size_t o = 0, i = 0;
    while (out && count > 0 && i < s.n) {
        u8 b = s.p[i++];
        if (b != seq) {
            if (o < cap) out[o++] = b;
            count--;
            continue;
        }
        size_t start = o;
        while (i < s.n && s.p[i] != seq) {
            if (o < cap) out[o++] = s.p[i];
            i++;
            count--;
        }
        if (i + 1 >= s.n) break;
        u8 n = s.p[i + 1];
        i += 2;
        size_t body = o - start;
        for (int r = (u8)(n - 1) ? (u8)(n - 1) : 256; r > 0 && body; r--)
            for (size_t k = 0; k < body && o < cap; k++) out[o++] = out[start + k];
        count -= 3;
    }
    *out_len = o;
    return out;
}

/* An RLE pass (rle_decode, 06c9:6b02). */
static u8 *rle(Src s, size_t *out_len)
{
    if (s.n < 9) return NULL;
    u32 size = rd24(s.p + 1), count = rd32(s.p + 4);
    u8 ec = s.p[8];
    int nesc = ec & 0x7F;
    if ((size_t)9 + nesc > s.n) return NULL;
    const u8 *esc = s.p + 9;
    Src src = { s.p + 9 + nesc, s.n - 9 - nesc };
    u8 *seq = NULL;
    if (ec <= 0x80) {
        if (nesc < 2) return NULL;
        size_t n;
        seq = sequences(src, count, esc[1], 4 * (size_t)size + 0x10000, &n);
        if (!seq) return NULL;
        src.p = seq;
        src.n = n;
        count = (u32)n;
    }
    u8 tab[256] = { 0 };
    for (int i = 0; i < nesc; i++) tab[esc[i]] = (u8)(i + 1);
    u8 *out = SDL_malloc(size ? size : 1);
    size_t o = 0, i = 0;
    while (out && (s32)count > 0 && i < src.n) {
        u8 b = src.p[i++];
        int cl = tab[b];
        u32 n;
        u8 v;
        if (cl == 0) {
            if (o < size) out[o++] = b;
            count--;
            continue;
        }
        if (cl == 1) {
            if (i + 2 > src.n) break;
            n = src.p[i];
            v = src.p[i + 1];
            i += 2;
            count -= 3;
        } else if (cl == 3) {
            if (i + 3 > src.n) break;
            n = src.p[i] | src.p[i + 1] << 8;
            v = src.p[i + 2];
            i += 3;
            count -= 4;
        } else {
            if (i + 1 > src.n) break;
            n = (u32)cl - 1;
            v = src.p[i++];
            count -= 2;
        }
        for (; n > 0 && o < size; n--) out[o++] = v;
    }
    SDL_free(seq);
    if (out && o != size) {
        SDL_free(out);
        return NULL;
    }
    *out_len = size;
    return out;
}

u8 *dos_unpack(const u8 *in, size_t len, size_t *out_len)
{
    if (len < 1) return NULL;
    int passes = 1;
    Src s = { in, len };
    if (in[0] & 0x80) {
        passes = in[0] & 0x7F;
        s.p += 4;
        s.n = len >= 4 ? len - 4 : 0;
    }
    u8 *data = NULL;
    for (; passes > 0; passes--) {
        size_t n = 0;
        u8 *next = s.n && s.p[0] == 1 ? rle(s, &n) : s.n && s.p[0] == 2 ? huffman(s, &n) : NULL;
        SDL_free(data);
        if (!next) return NULL;
        data = next;
        s.p = data;
        s.n = n;
        *out_len = n;
    }
    return data;
}

u8 *dos_pack_rle(const u8 *in, size_t len, size_t *out_len)
{
    size_t freq[256] = { 0 };
    for (size_t i = 0; i < len; i++) freq[in[i]]++;
    int e = 0;                                          /* the escape: the rarest byte */
    for (int b = 1; b < 256; b++)
        if (freq[b] < freq[e]) e = b;
    u8 *out = SDL_malloc(10 + 3 * len);
    if (!out) return NULL;
    size_t o = 10;
    for (size_t i = 0; i < len;) {
        size_t n = 1;
        while (i + n < len && in[i + n] == in[i] && n < 255) n++;
        if (n >= 4 || in[i] == e) {                     /* escape, count, value */
            out[o++] = (u8)e;
            out[o++] = (u8)n;
            out[o++] = in[i];
            i += n;
        } else {
            out[o++] = in[i++];
        }
    }
    u32 count = (u32)(o - 10);
    out[0] = 1;                                         /* one RLE pass */
    out[1] = (u8)len;
    out[2] = (u8)(len >> 8);
    out[3] = (u8)(len >> 16);
    out[4] = (u8)count;
    out[5] = (u8)(count >> 8);
    out[6] = (u8)(count >> 16);
    out[7] = (u8)(count >> 24);
    out[8] = 0x81;                                      /* one escape, no sequence pass */
    out[9] = (u8)e;
    /* unpack_file loads the file at the end of the block it unpacks into (one paragraph more than
     * the data), so the output must never reach input not yet read. */
    if ((o + 15) / 16 > (len + 15) / 16 + 1) {
        SDL_free(out);
        return NULL;
    }
    size_t start = ((len + 15) / 16 + 1 - (o + 15) / 16) * 16, w = 0;
    for (size_t i = 10; i < o;) {
        if (out[i] == e) {
            w += out[i + 1];
            i += 3;
        } else {
            w++;
            i++;
        }
        if (i < o && w > start + i) {
            SDL_free(out);
            return NULL;
        }
    }
    *out_len = o;
    return out;
}
