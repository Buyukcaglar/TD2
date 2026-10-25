/* scene_render: background drawing — sky, mountains, clouds, ground scanlines, tunnel walls, tunnel
 * ribs for the front view (06c9:0919..0d12, 1ad6) and the mirror (06c9:26d8..2957, 34dc).
 * port/spec/scene_render.md §4.6, §4.8.1. */
#include "scene.h"

static void fill(s16 x, s16 y, s16 w, s16 h, u16 colour)       /* 06c9:89a2 */
{
    gfx_fill_rect_clip(x, y, w, h, colour);
}

/* 06c9:0919 draw_sky_front / 06c9:26d8 draw_sky_mirror — §4.6 */
void draw_sky(const SceneView *v)
{
    s16 ax = VS(v, top_sy);
    s16 wd = v->width;
    u16 sky = DSW(DS_col_sky);
    if (DSB(DS_toggle_37f7) == 0) {
        u8 bl = VB(v, r0_any);
        if (bl & 0x80) {                                  /* tunnel in view */
            s16 di = VS(v, tunnel_out_l), bp = VS(v, tunnel_out_r);
            if (VB(v, r0_state) & 0x80) {
                fill(di, VS(v, tunnel_in_top), (s16)(bp - di),
                     (s16)(VS(v, tunnel_out_top) - VS(v, tunnel_in_top)), amiga_cockpit_tunnel_colour(0));
                return;
            }
            s16 top = VS(v, tunnel_in_top), ceil = VS(v, tunnel_ceiling);
            if (bl & 0x40) {
                s16 lc = VS(v, left_cut_x);
                fill(lc, ceil, (s16)(bp - lc), (s16)(VS(v, top_sy) - ceil), sky);
            } else {
                fill(di, ceil, (s16)(VS(v, right_cut_x) - di), (s16)(VS(v, top_sy) - ceil), sky);
            }
            fill(di, top, (s16)(bp - di), (s16)(ceil - top), amiga_cockpit_tunnel_colour(0));
            return;
        }
        if (bl & 0x40) {
            s16 lc = VS(v, left_cut_x);
            if (bl & 0x08) fill(lc, 0, (s16)(VS(v, right_cut_x) - lc), ax, sky);
            else           fill(lc, 0, (s16)(wd - lc), ax, sky);
            return;
        }
        if (bl & 0x08) {
            fill(0, 0, VS(v, right_cut_x), ax, sky);
            return;
        }
    }
    fill(0, 0, wd, ax, sky);
    if (DSB(DS_backdrop_off) != 0) return;
    s16 heading = (s16)(s8)(u8)((u16)(DSW(DS_view_yaw) << 3) >> 8);
    if (v->front && amiga_cockpit_backdrop(VS(v, top_sy), (u16)-(u16)(DSW(DS_heading) - (u16)heading)))
        return;                                           /* PORT: duel's mountains and clouds */
    u16 hb = v->sky_handles;
    if (DSW((u16)(hb + 8 * 4 + 2)) == 0) return;          /* mtn0 / rmt0 segment */
    if (v->front) {
        s16 di = (s16)((u16)-(u16)(DSW(DS_heading) - (u16)heading) & 0x3FF);  /* DS:5344 mountain scroll */
        s16 y = VS(v, top_sy);
        if (gfx_is_cga()) { di = (s16)(di | 1); y = (s16)(y | 1); }   /* odd x and row (dither phase?) */
        blit_copy_clip_hot(hnd((u16)(hb + 8 * 4)),  (s16)(di - 1024), y);
        blit_copy_clip_hot(hnd((u16)(hb + 10 * 4)), (s16)(di - 500), y);
        blit_copy_clip_hot(hnd((u16)(hb + 9 * 4)),  (s16)(di - 300), y);
        blit_copy_clip_hot(hnd((u16)(hb + 8 * 4)),  di, y);
        if (DSW((u16)(hb + 11 * 4 + 2)) == 0) return;     /* clo1 segment */
        di = (s16)((u16)-(u16)(DSW(DS_cloud_scroll) - (u16)heading) & 0x3FF);
        y = (s16)(RW(v, row_sy, 0x76) - 30);
        di = (s16)(di - 100);
        if (gfx_is_cga()) { di = (s16)(di | 1); y = (s16)(y | 1); }
        blit_copy_clip_hot(hnd((u16)(hb + 11 * 4)), (s16)(di - 1024), y);
        blit_copy_clip_hot(hnd((u16)(hb + 13 * 4)), (s16)(di - 500), y);
        blit_copy_clip_hot(hnd((u16)(hb + 12 * 4)), (s16)(di - 300), y);
        blit_copy_clip_hot(hnd((u16)(hb + 11 * 4)), di, y);
    } else {
        s16 di = (s16)((u16)(DSW(DS_heading) - (u16)heading) & 0x3FF);
        di = (s16)(di >> 1);
        s16 y = RW(v, row_sy, 0x30);
        if (gfx_is_cga()) { di = (s16)(di | 1); y = (s16)(y | 1); }
        blit_copy_clip_hot(hnd((u16)(hb + 8 * 4)),  (s16)(di - 512), y);   /* rmt0 */
        blit_copy_clip_hot(hnd((u16)(hb + 10 * 4)), (s16)(di - 250), y);   /* rmt2 */
        blit_copy_clip_hot(hnd((u16)(hb + 9 * 4)),  (s16)(di - 150), y);   /* rmt1 */
        blit_copy_clip_hot(hnd((u16)(hb + 8 * 4)),  di, y);
    }
}

/* PORT: the road unit of row si: the front view's row k is unit player_pos + 1 + k, the mirror's
 * player_pos - k. */
u16 row_unit(const SceneView *v, u16 si)
{
    int n = v->nrows2 / 2, k = si / 2;
    return v->front ? (u16)(VW(v, walk_ptr) - n + k) : (u16)(VW(v, walk_ptr) + n - k);
}

/* PORT: duel's road bands in the Amiga form ($185b4): duel fills each line's road and both shoulders
 * in one of two pens each by bit 3 of the line's distance along the road. Here the lines between two
 * rows take the band of that row's road unit, alternating every two units. The colours: road, left and
 * right shoulder, and the road in a tunnel ($184b2). */
typedef struct { u16 road, left, right, tunnel; } GroundBand;

static void road_bands(const SceneView *v, GroundBand band[], int lines)
{
    u16 pens[8];
    for (int y = 0; y < lines; y++)
        band[y] = (GroundBand){ COL(7, 0), DSW(DS_col_shoulder), DSW(DS_col_shoulder), COL(8, 0x9966) };
    if (!amiga_cockpit_road_bands(pens)) return;
    int n = v->nrows2 / 2;
    bool done[128] = { false };
    u16 b = (u16)(v->front ? row_unit(v, 0) - 1 : row_unit(v, 0) + 1) >> 1 & 1;
    for (int y = 0; y < lines; y++) band[y] = (GroundBand){ pens[b], pens[2 + b], pens[4 + b], pens[6 + b] };
    for (int k = 0; k < n; k++) {
        s16 top = k + 1 < n ? (s16)(RW(v, row_sy, 2 * k + 2) + 1) : 0, bottom = RW(v, row_sy, 2 * k);
        b = row_unit(v, (u16)(2 * k)) >> 1 & 1;
        for (s16 y = top < 0 ? 0 : top; y <= bottom && y < lines; y++)
            if (!done[y]) {
                done[y] = true;
                band[y] = (GroundBand){ pens[b], pens[2 + b], pens[4 + b], pens[6 + b] };
            }
    }
}

/* 06c9:0b0d draw_ground_front / 06c9:284f draw_ground_mirror — §4.6 */
void draw_ground(const SceneView *v)
{
    u16 wd = (u16)v->width;
    u16 end2 = (u16)(v->height * 2);
    u16 si = (u16)(VW(v, top_sy) << 1);
    u16 rowtab = DSW(v->rowtab);
    /* PORT: the loop is a do-while ending at si == height * 2; top_sy >= height would run it ~32000
     * times over random rows. Never happens with the shipped data; treated as empty (as clamp_spans). */
    if ((s16)si >= (s16)end2) return;
    const SceneRaster *r = raster();
    GroundBand band[128];
    road_bands(v, band, v->height < 128 ? v->height : 128);
    do {
        u16 di = CSW((u16)(si + rowtab));
        bool odd = (si & 2) != 0;
        DSW(DS_span_bit) = 0;
        DSW(DS_span_x) = 0;
        u16 f = DSW((u16)(DS_span_flags + si));
        u16 bx;
        if (f & 0x20) {                                   /* left drop-off */
            bx = DSW(DS_col_sky);
            if ((s16)si >= VS(v, left_sky_sy2) && VS(v, left_sky_x) < SPAN(span_ol, si)) {
                if (r->span_to(&di, VS(v, left_sky_x), bx, odd)) goto next;
                bx = DSW(DS_scene_words);                 /* DS:534A col_left */
            }
        } else {
            bx = DSW(DS_scene_words);
        }
        if (r->span_to(&di, SPAN(span_ol, si), bx, odd)) goto next;
        const GroundBand *g = &band[(si >> 1) & 127];
        if (r->span_to(&di, SPAN(span_l, si), g->left, odd)) goto next;              /* col_shoulder */
        if (r->span_to(&di, SPAN(span_r, si), g->road, odd)) goto next;              /* road */
        if (r->span_to(&di, SPAN(span_or, si), g->right, odd)) goto next;            /* col_shoulder */
        if (DSW((u16)(DS_span_flags + si)) & 0x04) {       /* right drop-off */
            if ((s16)si >= VS(v, right_sky_sy2) && VS(v, right_sky_x) >= SPAN(span_or, si)) {
                if (r->span_to(&di, VS(v, right_sky_x), DSW(DS_col_right), odd)) goto next;
            }
            if (r->span_to(&di, (s16)wd, DSW(DS_col_sky), odd)) goto next;
        } else {
            if (r->span_to(&di, SPAN(span_band, si), DSW(DS_col_right), odd)) goto next;
            if (r->span_to(&di, (s16)wd, DSW(DS_col_far), odd)) goto next;
        }
    next:
        si = (u16)(si + 2);
    } while (si != end2);
}

/* 06c9:0d01 hline: DX = x0, AX = x1, DI = y, BX = colour */
void hline(s16 dx, s16 ax, s16 di, u16 bx)
{
    raster()->hline(dx, ax, di, bx);
}

/* 06c9:0bb8 draw_tunnel_walls_front / 06c9:28f9 draw_tunnel_walls_mirror — §4.6 */
void draw_tunnel_walls(const SceneView *v)
{
    /* the original doubles tunnel_in_sy for the loop and halves it again afterwards */
    s16 end2 = (s16)(VW(v, tunnel_in_sy) << 1);
    s16 di = VS(v, tunnel_out_sy);
    s16 si = (s16)(di << 1);
    if (si >= end2) return;
    GroundBand band[128];                                 /* PORT: duel's pens in the Amiga form */
    road_bands(v, band, v->height < 128 ? v->height : 128);
    do {
        s16 l = SPAN(span_l, (u16)si);
        u16 bx;
        if (DSB(DS_toggle_37f7) == 0) {
            bx = amiga_cockpit_tunnel_colour(0);
            hline(VS(v, tunnel_in_l), l, di, bx);
            hline(SPAN(span_l, (u16)si), SPAN(span_r, (u16)si), di, band[di & 127].tunnel);
        } else {
            bx = amiga_cockpit_tunnel_colour(COL(8, 0));
            hline(VS(v, tunnel_in_l), l, di, bx);
            if (amiga_cockpit_on())                       /* PORT: duel draws the road in its tunnel pens */
                hline(SPAN(span_l, (u16)si), SPAN(span_r, (u16)si), di, band[di & 127].tunnel);
        }
        hline(SPAN(span_r, (u16)si), VS(v, tunnel_in_r), di, bx);
        di++;
        si = (s16)(si + 2);
    } while (si < end2);
}

/* 06c9:1ad6 tunnel_rib_front / 06c9:34dc tunnel_rib_mirror: white frame at row SI */
void tunnel_rib(const SceneView *v, u16 si)
{
    s16 bx = RW(v, row_sy, si);
    s16 cx = (s16)(bx - (s16)(RU(v, w, si) >> 1));
    if (DSB(DS_toggle_37f7) != 0) cx = (s16)(VS(v, top_sy) - 5);
    s16 ax = RW(v, row_l, si), di = RW(v, row_r, si);
    u16 c = amiga_cockpit_tunnel_colour(0xFF);           /* PORT: duel's pen 22 in the Amiga form */
    if (DSB(DS_toggle_37f7) == 0) gfx_draw_line(ax, cx, di, cx, c);
    gfx_draw_line(di, cx, di, bx, c);
    gfx_draw_line(ax, cx, ax, bx, c);
}
