#pragma once
/* The DOS game's packed files, outside the game's memory (the app builds files from them): unpacking
 * (the Huffman and RLE passes of unpack_file, as tools/dos_unpack.py does them) and packing as one RLE
 * pass, which unpack_file reads like the game's own files. Buffers are SDL_malloc'ed; SDL_free them. */
#include <stddef.h>

#include "../types.h"

u8 *dos_unpack(const u8 *in, size_t len, size_t *out_len);     /* NULL if the data is not a packed file */
u8 *dos_pack_rle(const u8 *in, size_t len, size_t *out_len);
