/* CGA backend: the 24 sprite blitters of TD2CGA.EXE (segment 06cf). They share one body per operation
 * and clipping: copy 06cf:8b1e / clipped 88cc, OR 8f78 / 8d3c, AND 7f26 / 7ce0, XOR 9e60 / 9c24; the
 * hot / raw / own entries in gfx.c only compute the position.
 *
 * A CGA sprite is one block of 2-bit pixels, w bytes by h rows, row-major after the loader's fix-up.
 * A position that is not a multiple of 4 pixels shifts every source byte right by 2, 4 or 6 bits; the
 * bits pushed out carry into the next byte, and the first and last byte of each row keep the target's
 * pixels outside the sprite (copy), or are filled to leave them alone (AND). The clipped blitters clip
 * whole bytes against the clip columns; a flag per edge says whether that edge byte is drawn. */
#include "gfx_cga.h"

static inline void put(u8 *p, u8 v, BlitOp op)
{
    switch (op) {
    case BLIT_REPLACE: *p = v; break;
    case BLIT_OR:      *p |= v; break;
    case BLIT_AND:     *p &= v; break;
    case BLIT_XOR:     *p ^= v; break;
    }
}

/* The first byte's carry when the left edge is drawn: copy keeps the target's first pixels, AND
 * leaves them (all ones), OR and XOR add nothing. */
static inline u8 first_carry(const u8 *p, u8 hi, BlitOp op)
{
    return op == BLIT_REPLACE ? (u8)(*p & hi) : op == BLIT_AND ? hi : 0;
}

/* The last byte: the carry, with the target's pixels after the sprite kept (copy) or left (AND). */
static inline void put_last(u8 *p, u8 carry, u8 lo, BlitOp op)
{
    switch (op) {
    case BLIT_REPLACE: *p = (u8)((*p & lo) | carry); break;
    case BLIT_OR:      *p |= carry; break;
    case BLIT_AND:     *p &= (u8)(carry | lo); break;
    case BLIT_XOR:     *p ^= carry; break;
    }
}

static void blit_unclipped(FarPtr spr, u16 px, u16 py, BlitOp op)
{
    u16 seg = CUR_PLANE(0);
    u16 w = rd16(spr.seg, spr.off);                                /* bp-0C */
    u16 rows = rd16(spr.seg, (u16)(spr.off + 2));
    u16 rt = (u16)(py * 2 + CUR_ROWTAB);
    u16 col = (u16)((s16)px >> 2);
    u16 si = (u16)(spr.off + 0x10);
    unsigned bits = ((unsigned)px & 3) * 2;
    if (bits == 0) {
        do {
            u16 di = (u16)(CSW(rt) + col);
            u16 n = w;
            do {                                                   /* loop: w == 0 -> 65536 */
                put(mp(seg, di++), rd8(spr.seg, si++), op);
            } while (--n);
            rt = (u16)(rt + 2);
        } while (dec_jg(&rows));
        return;
    }
    u8 hi = (u8)~(0xFF >> bits), lo = (u8)(0xFF >> bits);
    do {
        u16 di = (u16)(CSW(rt) + col);
        u8 carry = first_carry(mp(seg, di), hi, op);
        u16 n = w;
        do {
            u8 s = rd8(spr.seg, si++);
            u8 v = (u8)((s >> bits) | carry);
            carry = (u8)(s << (8 - bits));
            put(mp(seg, di++), v, op);
        } while (--n);
        put_last(mp(seg, di), carry, lo, op);
        rt = (u16)(rt + 2);
    } while (dec_jg(&rows));
}

static void blit_clipped(FarPtr spr, u16 px, u16 py, BlitOp op)
{
    u16 w = rd16(spr.seg, spr.off);
    /* rows against [clip_y0, clip_y1) */
    u16 y = py, cnt = rd16(spr.seg, (u16)(spr.off + 2));
    u16 src = (u16)(spr.off + 0x10);
    if (!slt(y, CUR_Y0)) {
        u16 over = (u16)(y + cnt - CUR_Y1);
        if ((s16)over > 0) {
            cnt = (u16)(cnt - over);
            if ((s16)cnt <= 0) return;
        }
    } else {
        u16 vis = (u16)(y + cnt - CUR_Y0);
        if ((s16)vis <= 0) return;
        u16 skipped = (u16)(cnt - vis);
        src = (u16)(src + (u16)((u8)skipped * (u8)w));            /* mul byte ptr [si] */
        y = CUR_Y0;
        cnt = vis;
        u16 over = (u16)(y + cnt - CUR_Y1);
        if ((s16)over > 0) {
            cnt = (u16)(cnt - over);
            if ((s16)cnt <= 0) return;
        }
    }
    /* byte columns against [clip_x0, clip_x1); flags: 2 = left edge drawn, 1 = right edge drawn */
    u8 flags = 3;
    u16 count = w, skip = 0;
    unsigned bits = ((unsigned)px & 3) * 2;
    u16 col = (u16)((s16)px >> 2);
    if (!slt(col, CUR_X0)) {
        u16 over = (u16)(col + count - CUR_X1);
        if ((s16)over >= 0) {
            flags = 2;
            count = (u16)(count - over);
            if ((s16)count <= 0) return;
            skip = over;
        }
    } else {
        u16 vis = (u16)(col + count - CUR_X0);
        if ((s16)vis < 0) return;
        src = (u16)(src + (u16)(count - vis));
        flags = 1;
        col = CUR_X0;
        u16 room = (u16)(CUR_X1 - CUR_X0);
        if (!slt(vis, room)) { vis = room; flags = 0; }
        skip = (u16)(w - vis);
        count = vis;
    }
    u16 seg = CUR_PLANE(0);
    u16 rt = (u16)(y * 2 + CUR_ROWTAB);
    u16 si = src;
    if (bits == 0) {
        if (count == 0) return;
        do {
            u16 di = (u16)(CSW(rt) + col);
            for (u16 n = 0; n < count; n++) put(mp(seg, di++), rd8(spr.seg, si++), op);
            si = (u16)(si + skip);
            rt = (u16)(rt + 2);
        } while (dec_jg(&cnt));
        return;
    }
    u8 hi = (u8)~(0xFF >> bits), lo = (u8)(0xFF >> bits);
    do {
        u16 di = (u16)(CSW(rt) + col);
        u8 carry;
        bool last = (flags & 1) != 0;
        if (flags & 2) {
            carry = first_carry(mp(seg, di), hi, op);
        } else {                                                   /* the clipped source byte's tail */
            carry = (u8)(rd8(spr.seg, (u16)(si - 1)) << (8 - bits));
            if (count == 0) last = true;
        }
        for (u16 n = 0; n < count; n++) {
            u8 s = rd8(spr.seg, si++);
            u8 v = (u8)((s >> bits) | carry);
            carry = (u8)(s << (8 - bits));
            put(mp(seg, di++), v, op);
        }
        if (last) put_last(mp(seg, di), carry, lo, op);
        si = (u16)(si + skip);
        rt = (u16)(rt + 2);
    } while (dec_jg(&cnt));
}

void cga_blit(FarPtr spr, u16 px, u16 py, BlitOp op, bool clip)
{
    if (clip) blit_clipped(spr, px, py, op);
    else blit_unclipped(spr, px, py, op);
}
