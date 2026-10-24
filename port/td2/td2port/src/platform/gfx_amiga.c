/* Amiga graphics backend (docs/amiga.md, "Amiga graphics"): the EGA backend's model run with a fifth
 * plane, so the screen and every off-screen buffer hold the Amiga's 32 colours. Colours 0-15 stay the
 * EGA palette's, which the game's own drawing uses; 16-31 are the Amiga's. Until the Amiga pictures
 * and sprites draw into the fifth plane, this backend shows the EGA frames. */
#include "gfx_ega.h"

void gfx_amiga_reset(void)
{
    gfx_ega_reset(5);
    for (int i = 16; i < 32; i++) gfx_ega.rgb[i] = 0;
}
