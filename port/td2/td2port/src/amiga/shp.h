#pragma once
/* The Amiga sprite archives (.shp, tools/amiga/shp.py): the DOS archive layout in big-endian, Rpck
 * packed. A sprite is a 20-byte header (width in bytes, height, hot spot, position, the planes set to
 * one wherever it is drawn, the screen planes of each stored plane) and its stored planes. It is
 * drawn where any stored plane is set; elsewhere it is transparent. */
#include "../types.h"

typedef struct {
    u16 w, h;           /* in pixels */
    s16 hot_x, hot_y, x, y;
    u8 *pix;            /* one colour index per pixel (SDL_free) */
    u8 *mask;           /* 1 where the sprite is drawn */
} AmigaSprite;

/* Sprite name (4 characters) of the archive in a file of the Amiga game. */
bool shp_load(const char *path, const char *name, AmigaSprite *s);
void shp_free(AmigaSprite *s);
