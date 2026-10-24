#pragma once
/* IFF ILBM pictures of the Amiga game (tools/amiga/ilbm.py): BMHD, CMAP and a BODY in ByteRun1 or
 * plain, after Rpck, and duel's own CMP2. The full screens are 320 x 200 in 5 bitplanes. A file that is
 * a CMAP chunk alone reads as a picture of no pixels with those 32 colours. */
#include "../types.h"

typedef struct {
    u16 w, h;
    u8 planes;
    u8 *pix;            /* one colour index per pixel, w x h (SDL_free) */
    u8 pal[32][3];      /* the CMAP, 8 bits per component */
    /* duel's CMP2: from line split down the screen shows pal2 (0: none). The option screen's picture
     * has one, for its row of car and scenery icons. */
    u16 split;
    u8 pal2[32][3];
} AmigaPicture;

bool ilbm_read(const u8 *f, u32 len, AmigaPicture *p);
/* The picture in a file of the Amiga game, Rpck-packed or not. */
bool ilbm_load(const char *path, AmigaPicture *p);
void ilbm_free(AmigaPicture *p);
