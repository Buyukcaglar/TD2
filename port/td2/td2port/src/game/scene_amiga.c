/* PORT: the race screen in its Amiga form (docs/amiga.md, "The race"): duel's cockpit over TD2's road.
 *
 * duel's car loader ($1b96c) draws the car's dashboard picture <car>dash, whose colours start at line
 * 116 (the viewport's second palette, +9Ch, split at +92h), and the lines above it take the section's
 * road colours, 32 words at 0A6h of <scenery>roaddata<section> ($1beae). Each frame ($18f40) it draws
 * the road, then over it the hood ("hdcr" once crashed), the roof, the windscreen pillar and the mirror
 * of <car>dash.shp at their own places; the radar detector's lights, the distance and the time XORed
 * onto the roof; and the progress dots on line 0. On the dashboard the steering wheel turns by XORing
 * "whl0" or "whl1" onto it ($19244), and the speedometer's and the tachometer's needles are lines from
 * the gauge's centre to a point of a table in <car>.b ($1ad0a, $1973c), drawn where the gauge's mask for
 * the wheel's pose ("spm0", "spm1", "spmC"; "tcm..." for the tachometer) lets them, in pen 1: the mask
 * clears planes 1 to 4 and sets plane 0. The gear gate is XORed onto the dashboard ("gbox", $18c56)
 * when TD2 shows its gate, with the knob ("gnob", a hardware sprite in duel) at TD2's knob position
 * carried over to duel's gate: <car>.b's table at 28h has each gear's place, neutral first.
 *
 * TD2's view (320 x 92 at line 19) and mirror are drawn by TD2 in the road colours: its colour numbers
 * draw the nearest of them, its sprites are duel's sprites of the same names from the Amiga archive
 * that has most of each DOS archive's (the scenery's, the traffic's, the police's, the opponent's and
 * ROAD's), and the rest are drawn with the nearest colours (gfx_amiga_substitute). The mirror's
 * picture moves into duel's mirror frame. */
#include "scene.h"
#include "flow.h"

#include <SDL3/SDL.h>
#include <stdio.h>
#include <string.h>

#define DASH_LINE   116                 /* where the dashboard's colours start */
#define VIEW_TOP    0x13                /* TD2's view, lines 19 to 110 */
#define VIEW_END    (VIEW_TOP + 0x5C)
#define HOOD_END    116                 /* the hood covers lines 108 to 117; the view's last lines fill the gap */

static struct {
    bool on;
    bool crashed;                       /* the crumpled hood */
    char dash[48];                      /* <car>dash.shp */
    s16 digit_y, digit_x[6];            /* the roof's digits (<car>.b at 0CAh): miles, tenths, m, m, s, s */
    u8 car[0x686];                      /* <car>.b, as duel copies it to A4-4334h */
    int pose;                           /* the steering wheel: whl0, whl1, or 2 straight */
    int speed_tip, tach_tip;            /* the needles' table entries drawn, -1 for none */
    s16 marker_x, marker_y;             /* the wheel's marker */
    FarPtr scratch;                     /* for TD2's sprites drawn with the road colours */
    bool gate, gate_drawn;              /* the gear gate is shown, and as drawn */
    s16 knob_x, knob_y;                 /* the knob's hot spot on it */
} ac;

/* <scenery>roaddata<n>: the pens duel draws the scenery's parts in ($1678e, $1844e, $1876a), words */
#define ROAD_PENS       0x17
#define ROAD_LEFT       (0x0E / 2)      /* the ground left of the road */
#define ROAD_RIGHT      (0x18 / 2)      /* and right of it */
#define ROAD_SKY        (0x1A / 2)
#define ROAD_FAR        (0x1C / 2)      /* the band beyond the right ground */
#define ROAD_EDGE       (0x1E / 2)      /* the road's edges */
#define ROAD_SURFACE    (0x26 / 2)      /* the road (duel alternates it with 28h in bands) */

#define CAR_MIN_SPEED   0x018           /* <car>.b: the speed of the speedometer's first table entry */
#define CAR_SPEED_HUB   0x2EE           /* the speedometer's centre, x and y bytes */
#define CAR_TACH_HUB    0x2F0
#define CAR_SPEED_TIPS  0x32A           /* x and y bytes for each mph */
#define CAR_TACH_TIPS   0x4D8           /* x and y bytes for each 64 rpm */
#define CAR_MARKER      0x012           /* the wheel marker's circle: centre x, y and radius, words */
#define CAR_KNOB        0x028           /* each gear's knob place, x and y words, neutral first */
#define DASH_CLEAN      118             /* the dashboard below the hood */

static u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }

bool amiga_cockpit_on(void) { return ac.on; }

void amiga_cockpit_crashed(bool crashed) { ac.crashed = crashed; }

void amiga_cockpit_gate(bool open) { ac.gate = open; }

/* v on TD2's gate, between its places d0 and d1, carried to duel's a0 and a1. */
static s16 knob_map(s16 v, s16 d0, s16 d1, s16 a0, s16 a1)
{
    return d1 == d0 ? (s16)(a0 + v - d0) : (s16)(a0 + (v - d0) * (a1 - a0) / (d1 - d0));
}

bool amiga_cockpit_load(void)
{
    ac.on = false;
    ac.crashed = false;
    const char *car = amiga_car_prefix(DSTR(DS_player_car_code));
    const char *scn = amiga_scenery_prefix(DSTR(DS_scn_code));
    if (!gfx_amiga_screens() || !car || !scn) return false;
    char file[48];
    s16 section = (s16)(DSS(DS_stage) - 1);
    snprintf(file, sizeof file, "%sroaddata%d", scn, section < 0 ? 0 : section > 5 ? 5 : section);
    u32 len;
    u8 *road = gfx_amiga_file(file, &len);
    u16 top[32], pens[ROAD_PENS];
    bool ok = road && len >= 0xA6 + 64;
    for (int i = 0; ok && i < 32; i++) top[i] = be16(road + 0xA6 + 2 * i);
    for (int i = 0; ok && i < ROAD_PENS; i++) pens[i] = be16(road + 2 * i);
    SDL_free(road);
    snprintf(file, sizeof file, "%s.b", car);
    u8 *b = gfx_amiga_file(file, &len);
    ok = ok && b && len >= sizeof ac.car;
    if (ok) {
        memcpy(ac.car, b, sizeof ac.car);
        ac.digit_y = (s16)be16(b + 0xCA);
        for (int i = 0; i < 6; i++) ac.digit_x[i] = (s16)be16(b + 0xCC + 2 * i);
    }
    SDL_free(b);
    if (!ok) return false;
    select_screen();
    gfx_clear_clip(0);
    if (!gfx_amiga_picture(flow_concat(file, sizeof file, car, "dash"), 0, 0)) return false;
    gfx_amiga_colours_above(top, 32, DASH_LINE);
    DSW(DS_scene_words) = AMIGA_PEN(pens[ROAD_LEFT]);   /* TD2's colour words for the scenery's parts */
    DSW(DS_col_right) = AMIGA_PEN(pens[ROAD_RIGHT]);
    DSW(DS_col_sky) = AMIGA_PEN(pens[ROAD_SKY]);
    DSW(DS_col_far) = AMIGA_PEN(pens[ROAD_FAR]);
    DSW(DS_col_shoulder) = AMIGA_PEN(pens[ROAD_EDGE]);
    gfx_amiga_keep_lines(DASH_LINE, 200);
    ac.pose = -1;
    ac.gate = ac.gate_drawn = false;
    gfx_fill_rect_clip(0, 0, 0x140, VIEW_TOP, DSW(DS_col_sky));   /* behind the roof's open edge */
    flow_concat(ac.dash, sizeof ac.dash, car, "dash.shp");
    gfx_amiga_colours_from(gfx_screen_desc(), ds_far(DS_drive_buf_desc));
    gfx_amiga_map_colour(7, (u8)pens[ROAD_SURFACE]);    /* the road, COL(7, 0) in draw_ground */
    gfx_amiga_keep_screen_colours(ds_far(DS_drive_buf_desc));
    gfx_amiga_colours_from(gfx_screen_desc(), ds_far(DS_mirror_desc));
    gfx_amiga_map_colour(7, (u8)pens[ROAD_SURFACE]);
    ac.scratch = gfx_create_buffer(0x140, 100, 0x0F);
    gfx_amiga_scratch(ac.scratch);
    gfx_amiga_substitute(far_make(0, 0), NULL);
    char scenery[48], opponent[48];
    const char *opp = amiga_car_prefix(DSTR(DS_opp_car_code));
    const char *files[] = { flow_concat(scenery, sizeof scenery, scn, "*.shp"), "pics/road.shp",
                            opp ? flow_concat(opponent, sizeof opponent, opp, "road.shp") : NULL };
    static const u16 archives[] = { DS_scenery_arc, DS_road_arc, DS_scn_car1_arc, DS_scn_car2_arc,
                                    DS_scn_car3_arc, DS_cop_arc, DS_opp_road_arc };
    for (int i = 0; i < (int)(sizeof archives / sizeof archives[0]); i++)
        gfx_amiga_substitute_best(ds_far(archives[i]), files, 3);
    FarPtr mirror = ds_far(DS_mirror_sprite);
    wr16(mirror.seg, (u16)(mirror.off + 0x0A), 1);     /* into duel's mirror frame, line 20 */
    select_screen();
    ac.on = true;
    return true;
}

/* The progress dot of a road position ($1fd1e): x = 319 * distance / the section's length. */
static void progress_dot(u16 pos, u8 pen)
{
    if (pos < 0x3B51) return;
    u32 d = (u32)(u16)(pos - 0x3B51), n = DSW(DS_stage_length);
    if (n == 0) return;
    if (d > n) d = n;
    gfx_plot((s16)(d * 319 / n), 0, AMIGA_PEN(pen));
}

static void roof_digit(int slot, u16 digit)
{
    char name[5] = { 'd', 'g', 't', (char)('0' + digit % 10), 0 };
    gfx_amiga_sprite("pics/road.shp", name, ac.digit_x[slot], ac.digit_y, AMIGA_XOR_AT);
}

/* A gauge's needle inside the mask of kind ("spm" or "tcm") for the wheel's pose, or the straight
 * wheel's if the car has none for it. */
static void needle(const char *kind, u16 hub, u16 tip)
{
    char mask[5] = { kind[0], kind[1], kind[2], (char)(ac.pose == 2 ? 'C' : '0' + ac.pose), 0 };
    if (!gfx_amiga_line_in(ac.dash, mask, ac.car[hub], ac.car[hub + 1], ac.car[tip], ac.car[tip + 1], 1)) {
        mask[3] = 'C';
        gfx_amiga_line_in(ac.dash, mask, ac.car[hub], ac.car[hub + 1], ac.car[tip], ac.car[tip + 1], 1);
    }
}

/* The steering wheel ($19244: turned past a quarter of TD2's lock, as TD2's draw_steering turns it),
 * its marker ("swhl" on the rim, $1b1ca: at -steer / 64 degrees, at most 45, on a circle of <car>.b's
 * 12h-16h) and the needles. When any of them moves, the dashboard below the hood is drawn again from
 * the picture, then all of them. */
static void dashboard(void)
{
    s16 steer = DSS(DS_steer_angle);
    s8 ah = (s8)(steer >> 8);
    int pose = ah >= 4 ? 0 : ah <= -4 ? 1 : 2;
    int s = (int)DSB(0x52CF) - (s16)be16(ac.car + CAR_MIN_SPEED);     /* mph */
    int s_max = (CAR_TACH_TIPS - CAR_SPEED_TIPS) / 2 - 1;
    s = s < 0 ? 0 : s > s_max ? s_max : s;
    u16 rpm = DSW(DS_rpm) < 800 ? 800 : DSW(DS_rpm);
    int r = rpm >> 6, r_max = ((int)sizeof ac.car - CAR_TACH_TIPS) / 2 - 1;
    r = r > r_max ? r_max : r;
    int deg = -(steer >> 6);
    deg = deg < -45 ? -45 : deg > 45 ? 45 : deg;
    double a = deg * 3.14159265358979 / 180;
    s16 radius = (s16)be16(ac.car + CAR_MARKER + 4);
    s16 mx = (s16)((s16)be16(ac.car + CAR_MARKER) + (s16)SDL_lround(SDL_sin(a) * radius));
    s16 my = (s16)((s16)be16(ac.car + CAR_MARKER + 2) - (s16)SDL_lround(SDL_cos(a) * radius));
    /* the knob: x between neutral and second gear, y between neutral and first gear */
    s16 kx = knob_map(DSS(DS_knob_x), DSS(DS_car_knob_xy), DSS(DS_car_knob_xy + 8),
                      (s16)be16(ac.car + CAR_KNOB), (s16)be16(ac.car + CAR_KNOB + 8));
    s16 ky = knob_map(DSS(DS_knob_y), DSS(DS_car_knob_xy + 2), DSS(DS_car_knob_xy + 6),
                      (s16)be16(ac.car + CAR_KNOB + 2), (s16)be16(ac.car + CAR_KNOB + 6));
    if (pose == ac.pose && s == ac.speed_tip && r == ac.tach_tip && mx == ac.marker_x && my == ac.marker_y
        && ac.gate == ac.gate_drawn && (!ac.gate || (kx == ac.knob_x && ky == ac.knob_y)))
        return;
    ac.gate_drawn = ac.gate;
    ac.knob_x = kx;
    ac.knob_y = ky;
    ac.pose = pose;
    ac.speed_tip = s;
    ac.tach_tip = r;
    ac.marker_x = mx;
    ac.marker_y = my;
    gfx_amiga_restore_rect(0, DASH_CLEAN, 0x140, 200);
    if (pose != 2) {
        char whl[5] = { 'w', 'h', 'l', (char)('0' + pose), 0 };
        gfx_amiga_sprite(ac.dash, whl, 0, 0, AMIGA_XOR_OWN);
    }
    needle("spm", CAR_SPEED_HUB, (u16)(CAR_SPEED_TIPS + 2 * s));
    needle("tcm", CAR_TACH_HUB, (u16)(CAR_TACH_TIPS + 2 * r));
    gfx_amiga_sprite(ac.dash, "swhl", mx, my, AMIGA_AT_HOT);
    if (ac.gate) {
        gfx_amiga_sprite(ac.dash, "gbox", 0, 0, AMIGA_XOR_OWN);
        gfx_amiga_sprite(ac.dash, "gnob", kx, ky, AMIGA_AT_HOT);
    }
}

void amiga_cockpit_free(void)
{
    if (!ac.scratch.seg) return;
    gfx_amiga_substitute(far_make(0, 0), NULL);
    gfx_amiga_scratch(far_make(0, 0));
    gfx_free_buffer(ac.scratch);
    ac.scratch = far_make(0, 0);
    ac.on = false;
}

void amiga_cockpit_frame(void)
{
    if (!ac.on) return;
    select_screen();
    gfx_set_clip_current(0, XBYTES(0x28), VIEW_END, HOOD_END);
    blit_copy_clip_raw(ds_far(DS_main_sprite), 0, (s16)(VIEW_TOP + HOOD_END - VIEW_END));
    gfx_set_clip_current(0, XBYTES(0x28), 0, 0xC8);
    gfx_amiga_sprite(ac.dash, ac.crashed ? "hdcr" : "hood", 0, 0, AMIGA_AT_OWN);
    gfx_amiga_sprite(ac.dash, "roof", 0, 0, AMIGA_AT_OWN);
    gfx_amiga_sprite(ac.dash, "post", 0, 0, AMIGA_AT_OWN);
    gfx_amiga_sprite(ac.dash, "mirr", 0, 0, AMIGA_AT_OWN);
    if (DSW(DS_sim_tick10) & 4) {                       /* the radar detector's lights, as TD2 blinks them */
        u16 level = DSW(DS_radar_level);
        char name[5] = { 'r', 'a', 'd', (char)('0' + (level > 5 ? 5 : level)), 0 };
        gfx_amiga_sprite(ac.dash, name, 0, 0, AMIGA_XOR_OWN);
    }
    s16 left = DSS(DS_distance_left);                   /* in tenths of a mile (42 road units each) */
    u16 tenths = left <= 0 ? 0 : (u16)(left / 42);
    roof_digit(0, tenths / 10 > 9 ? 9 : tenths / 10);
    roof_digit(1, tenths % 10);
    u16 m = (u16)(DSS(DS_stage_time) / 60), s = (u16)(DSS(DS_stage_time) % 60);
    if (m / 10 % 10) roof_digit(2, m / 10);
    roof_digit(3, m % 10);
    roof_digit(4, s / 10);
    roof_digit(5, s % 10);
    progress_dot(DSW(DS_opp_pos), 4);
    progress_dot(DSW(DS_cop_pos), 5);
    progress_dot(DSW(DS_player_pos), 16);
    dashboard();
}
