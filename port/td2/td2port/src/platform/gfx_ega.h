#pragma once
/* Private to the EGA graphics backend (gfx_ega.c, gfx_ega_blit.c): the EGA hardware model.
 *
 * VRAM and adapter registers are host-side (not part of mem[]). The model implements the sequencer map
 * mask, the graphics controller set/reset, enable set/reset, function (replace/AND/OR/XOR), read map,
 * write modes 0/1/2 and bit mask, so the screen-path register tricks and their quirks (constant-plane
 * helpers, bit mask left at 0 after the line routines, GC function left set by an empty clipped blit,
 * inherited registers in the text renderer, ...) fall out of the transcription. Each plane holds the full
 * 64 KB the CPU can address, so 16-bit offset overruns land in invisible VRAM exactly like on the card. */
#include "gfx_lib.h"

#define EGA_PLANE_BYTES 0x10000u
/* The Amiga backend runs this model with a fifth plane (gfx_amiga.c): the screen, every off-screen
 * buffer and the colour numbers then have five bits, and the frame shows 32 colours. */
#define EGA_MAX_PLANES 5

typedef struct {
    u8 plane[EGA_MAX_PLANES][EGA_PLANE_BYTES];
    u8 latch[EGA_MAX_PLANES];      /* last CPU read of all planes (write mode 1 source) */
    u8 map_mask;      /* sequencer index 2 */
    u8 set_reset;     /* GC index 0 */
    u8 enable_sr;     /* GC index 1 */
    u8 func;          /* GC index 3 (bits 3-4: 0 replace, 1 AND, 2 OR, 3 XOR) */
    u8 read_map;      /* GC index 4 */
    u8 mode;          /* GC index 5 (write mode in bits 0-1) */
    u8 bit_mask;      /* GC index 8 */
    u8 palette[17];   /* attribute controller palette registers + overscan (INT 10h AX=1002h) */
    u8 planes;        /* 4, or 5 for the Amiga backend */
    /* Five planes: the screen's colours (gfx_amiga.c). With an Amiga palette all 32 are rgb[];
     * without, 0-15 are the palette registers' and colour_map is the identity. */
    bool amiga_palette;
    u32 rgb[32];
    u16 split;           /* an Amiga palette: from this line down the screen shows rgb2 (0: none) */
    u32 rgb2[32];
    u8 colour_map[16];   /* the colour each EGA colour number draws on the screen */
    bool dirty;
} EgaState;

extern EgaState gfx_ega;

void gfx_ega_reset_registers(void);
void gfx_ega_reset(int planes);
/* gfx_amiga.c: the colours of the selected target, and the hooks the model calls with five planes. */
void gfx_amiga_reset(void);
u8   gfx_amiga_colour(u16 c);
void gfx_amiga_buffer_created(u16 seg);         /* a new off-screen buffer, plane 0 at seg */
void gfx_amiga_cleared(bool screen);            /* the screen, or the selected target, was cleared */
void gfx_amiga_shown(FarPtr spr);               /* a buffer sprite is drawn onto the screen */
bool gfx_ega_compose(u32 *xrgb);
bool gfx_amiga_compose(u32 *xrgb);             /* the model, and a high-resolution band if on */

/* A colour the game passes. With four planes it is used as it is. With five, it is an EGA colour
 * number (the game also passes FFh or FFFFh for white, which four planes read as 15) and the colour
 * map of the selected target says what it draws, or an Amiga pen (AMIGA_PEN, gfx.h). */
static inline u8 ega_colour(u16 c)
{
    return gfx_ega.planes == 5 ? gfx_amiga_colour(c) : (u8)c;
}

/* Every plane of the model: the map mask the game's "all planes" (0Fh) means. */
static inline u8 ega_all_planes(void) { return (u8)((1u << gfx_ega.planes) - 1); }

/* The segment of plane k of the selected RAM target. A fifth plane follows the fourth by the same
 * step (ega_create_buffer). */
static inline u16 ram_plane(int k)
{
    u16 p0 = CSW(GFX_CUR_PLANE0), p3 = CSW(GFX_CUR_PLANE0 + 6);
    if (k < 4) return CSW((u16)(GFX_CUR_PLANE0 + 2 * k));
    return p0 && p3 ? (u16)(p3 + (u16)(CSW(GFX_CUR_PLANE0 + 2) - p0)) : 0;
}

/* Five planes: whether spr is the sprite header of a live off-screen buffer, whose fifth plane block
 * follows its four (the other sprites have four planes at most). */
bool ega_buffer_sprite(FarPtr spr);

static inline void gc_out(u8 index, u8 value)      /* out 3CEh,index ; out 3CFh,value */
{
    switch (index) {
    case 0: gfx_ega.set_reset = value; break;
    case 1: gfx_ega.enable_sr = value; break;
    case 3: gfx_ega.func = value; break;
    case 4: gfx_ega.read_map = value; break;
    case 5: gfx_ega.mode = value; break;
    case 8: gfx_ega.bit_mask = value; break;
    default: break;
    }
}

static inline void seq_map_mask(u8 value) { gfx_ega.map_mask = value; }   /* out 3C4h,2 ; out 3C5h,value */

static inline u8 ega_read(u16 off)
{
    for (int k = 0; k < gfx_ega.planes; k++) gfx_ega.latch[k] = gfx_ega.plane[k][off];
    return gfx_ega.plane[gfx_ega.read_map == 4 && gfx_ega.planes == 5 ? 4 : gfx_ega.read_map & 3][off];
}

static inline void ega_write(u16 off, u8 v)
{
    for (int k = 0; k < gfx_ega.planes; k++) {
        if (!(gfx_ega.map_mask >> k & 1)) continue;
        u8 d = gfx_ega.plane[k][off];
        u8 x;
        switch (gfx_ega.mode & 3) {
        case 1:
            gfx_ega.plane[k][off] = gfx_ega.latch[k];      /* write mode 1 ignores function and bit mask */
            continue;
        case 2:
            x = (v >> k & 1) ? 0xFF : 0x00;
            break;
        default:
            x = (gfx_ega.enable_sr >> k & 1) ? ((gfx_ega.set_reset >> k & 1) ? 0xFF : 0x00) : v;
            break;
        }
        switch (gfx_ega.func >> 3 & 3) {
        case 1: x &= d; break;
        case 2: x |= d; break;
        case 3: x ^= d; break;
        default: break;
        }
        gfx_ega.plane[k][off] = (u8)((x & gfx_ega.bit_mask) | (d & (u8)~gfx_ega.bit_mask));
    }
    gfx_ega.dirty = true;
}

/* Byte access through a segment: 0xA000 = the EGA model, anything else = mem[]. */
static inline u8 vrd(u16 seg, u16 off) { return seg == VRAM_SEG ? ega_read(off) : rd8(seg, off); }
static inline void vwr(u16 seg, u16 off, u8 v)
{
    if (seg == VRAM_SEG) ega_write(off, v);
    else wr8(seg, off, v);
}
