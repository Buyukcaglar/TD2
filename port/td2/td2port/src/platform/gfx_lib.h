#pragma once
/* Private to the graphics library (gfx.c and the backends): the live descriptor copy and small helpers
 * for transcribing the assembly. */
#include "gfx.h"
#include "gfx_backend.h"

/* ---- flag helpers for the asm's signed branches */
static inline bool slt(u16 a, u16 b) { return (s16)a < (s16)b; }   /* cmp a,b ; jl  */
static inline bool sle(u16 a, u16 b) { return (s16)a <= (s16)b; }  /* cmp a,b ; jle */
static inline bool sgt(u16 a, u16 b) { return (s16)a > (s16)b; }   /* cmp a,b ; jg  */
/* dec r ; jg — taken while the true value old-1 is > 0 */
static inline bool dec_jg(u16 *r) { s16 old = (s16)*r; *r = (u16)(*r - 1); return old > 1; }
static inline u8 ror8(u8 v, unsigned n) { n &= 7; return n ? (u8)(v >> n | v << (8 - n)) : v; }

/* ---- live descriptor copy CS:AF3A */
#define CUR_PLANE(k) CSW(GFX_CUR_PLANE0 + 2 * (k))
#define CUR_ROWTAB   CSW(GFX_CUR_ROWTAB)
#define CUR_STRIDE   CSW(GFX_CUR_STRIDE)
#define CUR_X0       CSW(GFX_CUR_CLIP_X0)
#define CUR_X1       CSW(GFX_CUR_CLIP_X1)
#define CUR_Y0       CSW(GFX_CUR_CLIP_Y0)
#define CUR_Y1       CSW(GFX_CUR_CLIP_Y1)

/* Row table lookup through the live copy: CS:[CS:AF44 + y*2]. */
static inline u16 row_at(u16 y) { return CSW((u16)(y * 2 + CUR_ROWTAB)); }
