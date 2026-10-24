#pragma once
/* duel's Rpck unpacker ($1e518, tools/amiga/rpck.py): 'Rpck', the size, then count bytes n, n >= 0
 * repeating the next byte n + 1 times, n < 0 copying -n bytes. */
#include "../types.h"

/* Unpacks at most max bytes into out; returns the size, or 0 when the stream does not give it (some
 * streams write one byte more, which is dropped). */
u32 rpck_unpack(const u8 *in, u32 len, u8 *out, u32 max);
/* A file of the Amiga game, unpacked if it is packed (SDL_free it); NULL if missing or broken. */
u8 *rpck_load(const char *path, u32 *len);
