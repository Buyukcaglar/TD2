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

/* The scene renderer's own pixel writers (docs/cga.md, "CGA backend design"): the places where the
 * scene code of TD2EGA and TD2CGA writes into the view buffer itself instead of calling the library.
 * They draw into the view selected by draw_front / draw_mirror. A colour is whatever the backend's
 * routines take (EGA: a colour number, CGA: a pattern word). */
typedef struct SceneRaster {
    /* draw_front / draw_mirror, after selecting the view's buffer (EGA: cache its plane segments). */
    void (*view_begin)(void);
    /* 06c9:0c17 span_fill_to: fills the ground row at *row (byte address, advanced) from DS_span_x to
     * end - 1. true when the row is full, where the original jumps to [DS:0702] for the next row. */
    bool (*span_to)(u16 *row, s16 end, u16 colour, bool odd_row);
    /* 06c9:0d01 hline: row y from x0 to x1 - 1 (tunnel walls, the white band across the road). */
    void (*hline)(s16 x0, s16 x1, s16 y, u16 colour);
    /* A road marking pixel at x of the row at byte address row: the centre dot or a lane line. */
    void (*marking)(u16 row, s16 x, bool centre);
    /* crash_sequence: one frame of the crash flash (flash) or back to normal. */
    void (*crash_flash)(bool flash);
} SceneRaster;

typedef struct GfxBackend {
    const char *name;
    int frame_w, frame_h;                       /* host frame size */
    u8 px_per_byte;                             /* pixels in one buffer byte (EGA 8 per plane, CGA 4) */
    const SceneRaster *scene;
    void (*reset)(void);                        /* power-on state of the video model */
    bool (*compose)(u32 *xrgb);                 /* screen -> host frame; true if it changed */

    void (*video_hook)(void);                   /* 06c9:5d00 */
    void (*set_mode)(void);                     /* 06c9:90e8 game graphics mode and palette */
    void (*shutdown)(void);                     /* 06c9:642e back to text mode */
    void (*set_palette)(u16 ds_table);          /* 06c9:abfa */
    FarPtr (*create_buffer)(u16 width_px, u16 h, u16 plane_mask);  /* 06c9:b0fe -> descriptor */

    void (*clear_screen)(u16 colour);                               /* 06c9:840a */
    void (*clear_clip)(u16 colour);                                 /* 06c9:843e */
    void (*fill_rect)(s16 x, s16 y, s16 w, s16 h, u16 colour);      /* 06c9:8a0c, no clipping */
    void (*plot)(s16 x, s16 y, u16 colour);                         /* 06c9:ba3c */
    void (*draw_line)(s16 x0, s16 y0, s16 x1, s16 y1, u16 colour, bool or_mode);  /* 06c9:8582 / c984 */
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

/* EGA backend internals used by its files. */
void ega_blit(FarPtr spr, u16 px, u16 py, BlitOp op, bool clip);   /* gfx_ega_blit.c */
extern const SceneRaster ega_scene_raster;                         /* gfx_ega_scene.c */
/* Read access to the emulated EGA planes (debugging): plane k (0..3), 64 KB each. */
const u8 *gfx_vram_plane(int k);
