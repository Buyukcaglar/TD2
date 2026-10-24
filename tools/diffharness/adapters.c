/* Differential-test entry points: run one port function on mem[] with the original's register and
 * stack inputs, and put its results where the original leaves them. One adapter per function. */
#include <string.h>

#include "dh.h"
#include "mem.h"
#include "speaker.h"
#include "game/game.h"
#include "game/sim.h"
#include "platform/gfx.h"
#include "platform/gfx_backend.h"
#include "platform/res.h"

/* i-th word argument of a cdecl call (far: 4-byte return address, near: 2-byte). */
static u16 arg(const DhRegs *r, bool far, int i) { return rd16(r->ss, (u16)(r->sp + (far ? 4 : 2) + 2 * i)); }

static void a_rand8(DhRegs *r) { r->ax = rand8(); }                         /* xor ah,ah: AX = AL */
static void a_curve_sum(DhRegs *r) { (void)r; curve_sum(); }
static void a_free_rev(DhRegs *r) { (void)r; free_rev(); }
static void a_drag_apply(DhRegs *r) { drag_apply(r->dx); }
static void a_brake(DhRegs *r) { brake(r->dx); }
static void a_overrev_check(DhRegs *r) { (void)r; overrev_check(); }
static void a_update_rpm(DhRegs *r) { update_rpm(&r->cx, &r->dx); }         /* CX = old rpm, DX = new */

/* Routines that read or leave the stale BP (sim_stale_bp) take it from and return it in BP. */
#define WITH_BP(call) do { sim_stale_bp = r->bp; call; r->bp = sim_stale_bp; } while (0)
static void a_roadside_hit(DhRegs *r) { WITH_BP(roadside_hit()); }
static void a_road_edges(DhRegs *r) { WITH_BP(road_edges()); }
static void a_obj_place_roadside(DhRegs *r) { WITH_BP(obj_place_roadside(r->bx)); }
/* decode_controls reads the leftover CX too (sim_stale_cx); sound_tick leaves it. */
static void a_decode_controls(DhRegs *r) { sim_stale_cx = r->cx; WITH_BP(decode_controls()); }
static void a_sound_tick(DhRegs *r) { sim_stale_cx = r->cx; sound_tick(); r->cx = sim_stale_cx; }

/* Traffic. traffic() reports the CX the port assumes it leaves for pass_collisions (same_count8). */
static void a_traffic(DhRegs *r) { traffic(); r->cx = DSW(DS_same_count8); }
static void a_pass_collisions(DhRegs *r) { (void)r; pass_collisions(); }
static void a_traffic_resync(DhRegs *r) { (void)r; traffic_resync(); }
static void a_nearest_ahead(DhRegs *r) { r->si = nearest_ahead(r->si, r->cx, r->ax, r->dx); }

/* A whole sim timer call (06c9:403b), with the leftover BP and CX carried in and out. */
static void a_sim_tick(DhRegs *r)
{
    sim_stale_cx = r->cx;
    WITH_BP(sim_timer_routine());
    r->cx = sim_stale_cx;
}

static void a_rle_decode(DhRegs *r)
{
    FarPtr q = rle_decode(far_make(arg(r, true, 1), arg(r, true, 0)), far_make(arg(r, true, 3), arg(r, true, 2)),
                          arg(r, true, 4));
    r->dx = q.seg;
    r->ax = q.off;
}

static void a_huff_decode(DhRegs *r)
{
    u32 n = huff_decode(far_make(arg(r, true, 1), arg(r, true, 0)), far_make(arg(r, true, 3), arg(r, true, 2)),
                        arg(r, true, 4));
    r->dx = (u16)(n >> 16);
    r->ax = (u16)n;
}

/* CGA graphics library (tools/diffharness/cga.py): the front routines of gfx.c on the CGA backend,
 * with far cdecl arguments as TD2CGA's entry points take them. */
static FarPtr arg_far(const DhRegs *r, int i) { return far_make(arg(r, true, i + 1), arg(r, true, i)); }
static s16 sarg(const DhRegs *r, int i) { return (s16)arg(r, true, i); }
#define ON_CGA(call) do { gfx_set_backend(&gfx_cga_backend); call; gfx_set_backend(&gfx_ega_backend); } while (0)
#define CGA_BLIT(fn)                                                                                     \
    static void a_cga_##fn##_hot(DhRegs *r) { ON_CGA(fn##_hot(arg_far(r, 0), sarg(r, 2), sarg(r, 3))); } \
    static void a_cga_##fn##_raw(DhRegs *r) { ON_CGA(fn##_raw(arg_far(r, 0), sarg(r, 2), sarg(r, 3))); } \
    static void a_cga_##fn##_own(DhRegs *r) { ON_CGA(fn##_own(arg_far(r, 0))); }
CGA_BLIT(blit_copy_clip) CGA_BLIT(blit_or_clip) CGA_BLIT(blit_and_clip) CGA_BLIT(blit_xor_clip)
CGA_BLIT(blit_copy) CGA_BLIT(blit_or) CGA_BLIT(blit_and) CGA_BLIT(blit_xor)
CGA_BLIT(grab_into_sprite)
static void a_cga_fill_rect(DhRegs *r) { ON_CGA(gfx_fill_rect(sarg(r, 0), sarg(r, 1), sarg(r, 2), sarg(r, 3), arg(r, true, 4))); }
static void a_cga_fill_rect_clip(DhRegs *r)
{
    ON_CGA(gfx_fill_rect_clip(sarg(r, 0), sarg(r, 1), sarg(r, 2), sarg(r, 3), arg(r, true, 4)));
}
static void a_cga_clear_clip(DhRegs *r) { ON_CGA(gfx_clear_clip(arg(r, true, 0))); }
static void a_cga_plot(DhRegs *r) { ON_CGA(gfx_plot(sarg(r, 0), sarg(r, 1), arg(r, true, 2))); }
static void a_cga_draw_line(DhRegs *r) { ON_CGA(gfx_draw_line(sarg(r, 0), sarg(r, 1), sarg(r, 2), sarg(r, 3), arg(r, true, 4))); }
static void a_cga_draw_line_or(DhRegs *r)
{
    ON_CGA(gfx_draw_line_or(sarg(r, 0), sarg(r, 1), sarg(r, 2), sarg(r, 3), arg(r, true, 4)));
}
#define CGA_ADAPTER(fn) { "cga_" #fn, a_cga_##fn }
#define CGA_BLIT_ADAPTERS(fn) CGA_ADAPTER(fn##_hot), CGA_ADAPTER(fn##_raw), CGA_ADAPTER(fn##_own)

static const struct { const char *name; void (*fn)(DhRegs *); } adapters[] = {
    { "rand8", a_rand8 },
    { "curve_sum", a_curve_sum },
    { "free_rev", a_free_rev },
    { "drag_apply", a_drag_apply },
    { "brake", a_brake },
    { "update_rpm", a_update_rpm },
    { "overrev_check", a_overrev_check },
    { "roadside_hit", a_roadside_hit },
    { "road_edges", a_road_edges },
    { "obj_place_roadside", a_obj_place_roadside },
    { "decode_controls", a_decode_controls },
    { "sound_tick", a_sound_tick },
    { "traffic", a_traffic },
    { "pass_collisions", a_pass_collisions },
    { "traffic_resync", a_traffic_resync },
    { "nearest_ahead", a_nearest_ahead },
    { "sim_tick", a_sim_tick },
    { "rle_decode", a_rle_decode },
    { "huff_decode", a_huff_decode },
    CGA_BLIT_ADAPTERS(blit_copy_clip), CGA_BLIT_ADAPTERS(blit_or_clip), CGA_BLIT_ADAPTERS(blit_and_clip),
    CGA_BLIT_ADAPTERS(blit_xor_clip), CGA_BLIT_ADAPTERS(blit_copy), CGA_BLIT_ADAPTERS(blit_or),
    CGA_BLIT_ADAPTERS(blit_and), CGA_BLIT_ADAPTERS(blit_xor), CGA_BLIT_ADAPTERS(grab_into_sprite),
    CGA_ADAPTER(fill_rect), CGA_ADAPTER(fill_rect_clip), CGA_ADAPTER(clear_clip), CGA_ADAPTER(plot),
    CGA_ADAPTER(draw_line), CGA_ADAPTER(draw_line_or),
};

DH_EXPORT u8 *dh_mem(void) { return mem; }
DH_EXPORT u32 dh_mem_size(void) { return MEM_SIZE; }
DH_EXPORT const char *dh_fatal_message(void) { return dh_fatal_msg; }

DH_EXPORT bool dh_load_exe(const char *path, char *err, size_t errlen) { return mem_load_exe(path, err, errlen); }

DH_EXPORT int dh_count(void) { return (int)(sizeof adapters / sizeof adapters[0]); }
DH_EXPORT const char *dh_name(int i) { return i >= 0 && i < dh_count() ? adapters[i].name : NULL; }

/* PC-speaker synthesis (speaker.c), for tests/test_speaker.py. */
static Speaker dh_spk;
DH_EXPORT void dh_speaker_reset(int rate) { speaker_init(&dh_spk, rate); }
DH_EXPORT void dh_speaker_play(u16 divisor, u8 port61_bits, s16 *out, int n, int amplitude)
{
    speaker_set(&dh_spk, port61_bits);
    speaker_render(&dh_spk, divisor, out, n, amplitude);
}

/* 0 = ran, 1 = the port called fatal (message in dh_fatal_message), -1 = no adapter of that name. */
DH_EXPORT int dh_call(const char *name, DhRegs *r)
{
    for (int i = 0; i < dh_count(); i++) {
        if (strcmp(adapters[i].name, name) != 0) continue;
        jmp_buf jb;
        dh_fatal_msg[0] = 0;
        if (setjmp(jb)) { dh_fatal_jmp = NULL; return 1; }
        dh_fatal_jmp = &jb;
        adapters[i].fn(r);
        dh_fatal_jmp = NULL;
        return 0;
    }
    return -1;
}
