/* Amiga memory and the load file reader (amiga_mem.h). */
#include <stdio.h>
#include <string.h>

#include "amiga/amiga_mem.h"

u8 amiga_mem[AMIGA_MEM_SIZE];

static AmigaRegHook reg_hook;

void amiga_set_reg_hook(AmigaRegHook hook) { reg_hook = hook; }

static bool is_reg(u32 a) { return (a & 0xFFF000u) == 0xDFF000u || (a & 0xFF0000u) == 0xBF0000u; }

void awr8(u32 a, u8 v)
{
    if (is_reg(a)) {
        if (reg_hook) reg_hook(a, v, 1);
        return;
    }
    amiga_mem[a & (AMIGA_MEM_SIZE - 1)] = v;
}

void awr16(u32 a, u16 v)
{
    if (is_reg(a)) {
        if (reg_hook) reg_hook(a, v, 2);
        return;
    }
    awr8(a, (u8)(v >> 8));
    awr8(a + 1, (u8)v);
}

void awr32(u32 a, u32 v)
{
    if (is_reg(a)) {                                /* a long write is two word cycles, high word first */
        if (reg_hook) {
            reg_hook(a, (u16)(v >> 16), 2);
            reg_hook(a + 2, (u16)v, 2);
        }
        return;
    }
    awr16(a, (u16)(v >> 16));
    awr16(a + 2, (u16)v);
}

/* ------------------------------------------------------------------------------------------ load files */

enum {
    HUNK_NAME = 0x3E8, HUNK_CODE = 0x3E9, HUNK_DATA = 0x3EA, HUNK_BSS = 0x3EB, HUNK_RELOC32 = 0x3EC,
    HUNK_SYMBOL = 0x3F0, HUNK_DEBUG = 0x3F1, HUNK_END = 0x3F2, HUNK_HEADER = 0x3F3, HUNK_OVERLAY = 0x3F5,
    HUNK_BREAK = 0x3F6,
};

typedef struct { const u8 *p; u32 len, pos; bool bad; } Reader;

static u32 rd_long(Reader *r)
{
    if (r->pos + 4 > r->len) {
        r->bad = true;
        return 0;
    }
    const u8 *b = r->p + r->pos;
    r->pos += 4;
    return (u32)b[0] << 24 | (u32)b[1] << 16 | (u32)b[2] << 8 | b[3];
}

bool amiga_load_seg(const u8 *file, u32 len, u32 base, AmigaSeg *seg, char *err, size_t errlen)
{
    Reader r = { file, len, 0, false };
    memset(seg, 0, sizeof *seg);
    if (rd_long(&r) != HUNK_HEADER) {
        snprintf(err, errlen, "not an Amiga load file");
        return false;
    }
    while (rd_long(&r) != 0 && !r.bad) {}              /* resident library names */
    rd_long(&r);
    u32 first = rd_long(&r), last = rd_long(&r);
    if (r.bad || last < first || last - first >= 8) {
        snprintf(err, errlen, "bad load file header");
        return false;
    }
    seg->nsec = (int)(last - first + 1);
    u32 at = base;
    for (int i = 0; i < seg->nsec; i++) {
        u32 v = rd_long(&r);
        if ((v >> 30) == 3) rd_long(&r);
        seg->size[i] = (v & 0x3FFFFFFFu) * 4;
        seg->base[i] = at;
        at = (at + seg->size[i] + 8 + 15) & ~15u;
    }
    if (at > AMIGA_MEM_SIZE) {
        snprintf(err, errlen, "load file too large");
        return false;
    }
    memset(amiga_mem + base, 0, at - base);
    int cur = -1, index = 0;
    while (!r.bad && r.pos + 4 <= len) {
        u32 kind = rd_long(&r) & 0x3FFFFFFFu;
        if (kind == HUNK_CODE || kind == HUNK_DATA || kind == HUNK_BSS) {
            if (index >= seg->nsec) break;
            cur = index;
            u32 n = (rd_long(&r) & 0x3FFFFFFFu) * 4;
            if (kind != HUNK_BSS) {
                if (r.pos + n > len || n > seg->size[cur] + 8) { r.bad = true; break; }
                memcpy(amiga_mem + seg->base[cur], file + r.pos, n);
                r.pos += n;
            }
        } else if (kind == HUNK_RELOC32) {
            for (;;) {
                u32 n = rd_long(&r);
                if (!n || r.bad) break;
                u32 target = rd_long(&r);
                if ((int)target >= seg->nsec || cur < 0) { r.bad = true; break; }
                for (u32 k = 0; k < n && !r.bad; k++) {
                    u32 a = seg->base[cur] + rd_long(&r);
                    if (a + 4 > AMIGA_MEM_SIZE) { r.bad = true; break; }
                    u32 v = ard32(a) + seg->base[target];
                    amiga_mem[a] = (u8)(v >> 24);
                    amiga_mem[a + 1] = (u8)(v >> 16);
                    amiga_mem[a + 2] = (u8)(v >> 8);
                    amiga_mem[a + 3] = (u8)v;
                }
            }
        } else if (kind == HUNK_SYMBOL) {
            for (;;) {
                u32 n = rd_long(&r) * 4;
                if (!n || r.bad || r.pos + n > len) break;
                const char *name = (const char *)file + r.pos;
                r.pos += n;
                u32 off = rd_long(&r);
                if (seg->nsym < (int)(sizeof seg->sym / sizeof seg->sym[0]) && cur >= 0) {
                    size_t l = strnlen(name, n);
                    if (l >= sizeof seg->sym[0].name) l = sizeof seg->sym[0].name - 1;
                    memcpy(seg->sym[seg->nsym].name, name, l);
                    seg->sym[seg->nsym].name[l] = 0;
                    seg->sym[seg->nsym++].addr = seg->base[cur] + off;
                }
            }
        } else if (kind == HUNK_DEBUG || kind == HUNK_NAME) {
            r.pos += rd_long(&r) * 4;
        } else if (kind == HUNK_END) {
            index++;
        } else if (kind == HUNK_OVERLAY || kind == HUNK_BREAK) {
            break;                                  /* the root is all the port uses */
        } else {
            snprintf(err, errlen, "unknown hunk %03Xh", (unsigned)kind);
            return false;
        }
    }
    if (r.bad) {
        snprintf(err, errlen, "load file is cut short or damaged");
        return false;
    }
    return true;
}

u32 amiga_seg_symbol(const AmigaSeg *seg, const char *name)
{
    for (int i = 0; i < seg->nsym; i++)
        if (strcmp(seg->sym[i].name, name) == 0) return seg->sym[i].addr;
    return 0;
}
