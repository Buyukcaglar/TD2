#pragma once
/* Amiga memory for the parts of the Amiga game the port runs translated: a flat big-endian address
 * space (chip memory from 0) that a load file is laid out in with its relocations, as AmigaDOS would.
 *
 * Writes to the custom chips ($DFF000) and the CIAs ($BFxxxx) go to the hooks below instead of memory,
 * so the Paula model (paula.c) sees them, and a log can record them for the differential tests. */
#include "types.h"

#define AMIGA_MEM_SIZE 0x80000u                     /* 512 KB of chip memory */

extern u8 amiga_mem[AMIGA_MEM_SIZE];

static inline u8  ard8(u32 a)  { return amiga_mem[a & (AMIGA_MEM_SIZE - 1)]; }
static inline u16 ard16(u32 a) { return (u16)(ard8(a) << 8 | ard8(a + 1)); }
static inline u32 ard32(u32 a) { return (u32)ard16(a) << 16 | ard16(a + 2); }

void awr8(u32 a, u8 v);
void awr16(u32 a, u16 v);
void awr32(u32 a, u32 v);

/* Custom chip and CIA writes (the address as the 68000 puts it on the bus). */
typedef void (*AmigaRegHook)(u32 addr, u16 value, int size);
void amiga_set_reg_hook(AmigaRegHook hook);

/* A loaded load file: its sections in amiga_mem and its symbols. */
typedef struct {
    int nsec;
    u32 base[8], size[8];
    int nsym;
    struct { char name[24]; u32 addr; } sym[96];
} AmigaSeg;

/* Lays the file out from base the way tools/amiga/hunk.py does (sections 16-byte aligned with 8 bytes
 * between them), so addresses agree with the Python tools. Returns false with a reason. */
bool amiga_load_seg(const u8 *file, u32 len, u32 base, AmigaSeg *seg, char *err, size_t errlen);
u32  amiga_seg_symbol(const AmigaSeg *seg, const char *name);   /* 0 when absent */
