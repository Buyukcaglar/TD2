/* Differential-test entry points: run one port function on mem[] with the original's register and
 * stack inputs, and put its results where the original leaves them. One adapter per function. */
#include <string.h>

#include "dh.h"
#include "mem.h"
#include "speaker.h"
#include "game/sim.h"
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
static void a_decode_controls(DhRegs *r) { WITH_BP(decode_controls()); }

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
    { "rle_decode", a_rle_decode },
    { "huff_decode", a_huff_decode },
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
