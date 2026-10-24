#pragma once
/* Private to the CGA graphics backend (gfx_cga.c, gfx_cga_blit.c, gfx_cga_scene.c): the CGA model.
 *
 * Unlike the EGA planes, CGA video memory is ordinary RAM at B800:0000, so it lives in mem[] and the
 * routines read and write it like any buffer. Pixels are 2 bits, 4 per byte, leftmost pixel in the
 * top bits. The screen interleaves its rows (even rows from offset 0, odd rows from 2000h, 80 bytes
 * each); off-screen buffers are linear. Only the two registers the game writes are modelled: mode
 * control (3D8h) and colour select (3D9h). */
#include "gfx_lib.h"

#define CGA_SEG       0xB800
#define CGA_BYTES     0x4000u

typedef struct {
    u8 mode_ctrl;     /* 3D8h: bit 2 black-and-white (third palette on RGB), bit 3 video enable */
    u8 colour_sel;    /* 3D9h: bits 0-3 background, bit 4 intensity, bit 5 palette */
    u8 shown[CGA_BYTES];   /* video memory as last composed */
    bool dirty;
} CgaState;

extern CgaState gfx_cga;

void cga_blit(FarPtr spr, u16 px, u16 py, BlitOp op, bool clip);   /* gfx_cga_blit.c */
extern const SceneRaster cga_scene_raster;                         /* gfx_cga_scene.c */
