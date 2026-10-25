#pragma once
/* AmigaDOS load files (tools/amiga/hunk.py): reads the root's hunks at the addresses hunk.py gives them,
 * the first from 10000h and each next one at the 16-byte boundary 8 bytes past the last. */
#include "../types.h"

/* n bytes at addr of the load file at path, from its code and data with the relocations applied (as
 * hunk.py loads it). False if the file is missing or the bytes are not stored in one hunk. */
bool hunk_read(const char *path, u32 addr, void *out, u32 n);
