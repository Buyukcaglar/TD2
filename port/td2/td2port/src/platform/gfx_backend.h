#pragma once
/* Graphics backends: the adapter-specific half of the graphics library.
 *
 * gfx.c keeps what every adapter shares: the target descriptors in code-segment memory, clipping
 * bookkeeping, the text state, sprite positioning (hot / raw / own) and the small C helpers. A backend
 * owns the pixels: its video memory model, how buffers are laid out in mem[], every routine that reads
 * or writes pixels, and turning its screen into a host frame. The split follows TD2EGA against TD2CGA:
 * the routines in this table are the ones TD2CGA implements differently; the rest of gfx.h is the
 * same code in both.
 *
 * One backend is active at a time (EGA today). gfx_set_backend() must be called before gfx_init();
 * switching during play is a later milestone. */
#include "../mem.h"

typedef enum { BLIT_REPLACE, BLIT_OR, BLIT_AND, BLIT_XOR } BlitOp;

typedef struct GfxBackend {
    const char *name;
    int frame_w, frame_h;                       /* host frame size */
    void (*reset)(void);                        /* power-on state of the video model */
    bool (*compose)(u32 *xrgb);                 /* screen -> host frame; true if it changed */

    void (*video_hook)(void);                   /* 06c9:5d00 */
    void (*set_mode)(void);                     /* 06c9:90e8 game graphics mode and palette */
    void (*shutdown)(void);                     /* 06c9:642e back to text mode */
    void (*set_palette)(u16 ds_table);          /* 06c9:abfa */
    FarPtr (*create_buffer)(u16 width_px, u16 h, u16 plane_mask);  /* 06c9:b0fe -> descriptor */

    void (*clear_screen)(u8 colour);                                /* 06c9:840a */
    void (*clear_clip)(u8 colour);                                  /* 06c9:843e */
    void (*fill_rect)(s16 x, s16 y, s16 w, s16 h, u8 colour);       /* 06c9:8a0c, no clipping */
    void (*plot)(s16 x, s16 y, u8 colour);                          /* 06c9:ba3c */
    void (*draw_line)(s16 x0, s16 y0, s16 x1, s16 y1, u8 colour, bool or_mode);  /* 06c9:8582 / c984 */
    void (*draw_text)(const u8 *s);                                 /* 06c9:a54f at the text cursor */
    void (*dissolve)(FarPtr spr, u8 phase, int phases);             /* 06c9:8cd8 (4) / 8f12 (8) */
    void (*scroll_window)(s16 x, s16 y, s16 w, s16 h, s16 step, FarPtr spr, s16 srow);  /* 06c9:ae62 */
    void (*grab_screen)(s16 sx, s16 sy, s16 dx, s16 dy, s16 w_px, s16 h);              /* 06c9:c784 */
    void (*grab_into_sprite)(FarPtr spr, u16 px, u16 py);           /* 06c9:ac64 body */
    void (*blit)(FarPtr spr, u16 px, u16 py, BlitOp op, bool clip); /* the 24 sprite blitters' body */
} GfxBackend;

extern const GfxBackend gfx_ega_backend;        /* gfx_ega.c, gfx_ega_blit.c */

const GfxBackend *gfx_backend(void);
void gfx_set_backend(const GfxBackend *b);

/* EGA backend internals used by its two files. */
void ega_blit(FarPtr spr, u16 px, u16 py, BlitOp op, bool clip);   /* gfx_ega_blit.c */
/* Read access to the emulated EGA planes (debugging): plane k (0..3), 64 KB each. */
const u8 *gfx_vram_plane(int k);
