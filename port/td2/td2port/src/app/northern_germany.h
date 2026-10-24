#pragma once
/* The Amiga version's Northern Germany Challenge, built as a DOS scenery (docs/amiga.md, "Northern
 * Germany"). It is a scenery made in 2012 for the Amiga game from the other three: each of its seven
 * roads is a road of the Master, California or European scenery and each of its sprite files a copy
 * of theirs, under other names. So each stage here is the DOS twin of its road, drawn with the DOS
 * sprite archive of its Amiga sprite file; its signs are its own, converted from its vector sign files.
 * The font, the traffic and the icon are the European Challenge's.
 *
 * Needs the Amiga game and the DOS California and European Challenges; find returns the path of a DOS
 * game file (SDL_free it) or NULL. Writes the scenery's files and its SCENES.DAT to out_dir. */
#include <stddef.h>

#include "../types.h"

bool northern_germany_build(const char *amiga_dir, const char *out_dir, char *(*find)(const char *name),
                            char *err, size_t err_size);
