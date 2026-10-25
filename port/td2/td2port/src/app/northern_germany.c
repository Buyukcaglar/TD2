/* The Amiga version's Northern Germany Challenge as a DOS scenery (northern_germany.h). */
#include <SDL3/SDL.h>
#include <string.h>

#include "amiga/ilbm.h"
#include "amiga/rpck.h"
#include "dos_files.h"
#include "northern_germany.h"

#define CODE "NGC"                                      /* the DOS file prefix */
#define NAME "Northern_Germany"                     /* the catalogue keeps 20 characters */

/* The DOS stage image (unpacked .DAT, from DS:346A): the sprite archive name, the 128 road records,
 * the road length, the road bytes. */
#define DAT_NAME     0x000
#define DAT_RECORDS  0x014
#define DAT_LENGTH   0x3A3
#define DAT_ROAD     0x6E7
/* An Amiga road file: a header of 125 words (it ends with the sprite file name), then the road bytes
 * up to FFh. Its records are the scenery's slicedata (flags, curve, pitch, object code). */
#define AMIGA_HEADER 0xFA
#define AMIGA_NAMES  0x7E                               /* where the header's names and colours start */

/* Each stage: the road it copies (in the Amiga game's folder), its DOS twin, and the DOS archive of
 * the Amiga sprite file its road names here. For example stage 1 names treesmountai1.shp, which is
 * the European stage 1's euro_scen1.shp under another name, so its DOS archive is EC_1. */
static const struct { const char *road, *twin, *archive; } stages[7] = {
    { "scen1/scen/rock_roaddata6", "CCC6", "TDS2TRES" },
    { "scen/sc1_roaddata2", "TDS22", "EC_1" },
    { "scen2/scen/euro_roaddata3", "EC_3", "EC_1" },
    { "scen1/scen/rock_roaddata2", "CCC2", "TDS2TRES" },
    { "scen/sc1_roaddata4", "TDS24", "EC_2" },
    { "scen2/scen/euro_roaddata5", "EC_5", "EC_2" },
    { "scen2/scen/euro_roaddata1", "EC_1", "EC_2" },
};
/* Files taken from the European Challenge and the Master scenery. The traffic keeps the European
 * slots (van, thunderbird, mercedes, as EC_CAR1-3 match euro_van, euro_thunderbird and euro_mercedes)
 * with Northern Germany's own cars in them: its euro_van.shp is the Master van (TDS2CAR3), its
 * euro_thunderbird.shp the Master mercedes (TDS2CAR1), its euro_mercedes.shp the European thunderbird
 * (EC_CAR2). */
static const struct { const char *from, *to; } copies[] = {
    { "EC_.FNT", CODE ".FNT" },
    { "TDS2CAR3.PES", CODE "CAR1.PES" }, { "TDS2CAR3.PCS", CODE "CAR1.PCS" },
    { "TDS2CAR1.PES", CODE "CAR2.PES" }, { "TDS2CAR1.PCS", CODE "CAR2.PCS" },
    { "EC_CAR2.PES", CODE "CAR3.PES" }, { "EC_CAR2.PCS", CODE "CAR3.PCS" },
};

#define AMIGA_SIGN 0x2E                                 /* the Amiga's object code of sign 0 */
#define AMIGA_SIGNS 13                                  /* codes 2Eh-3Ah; 3Bh and up are other objects */
#define DOS_SIGN   0x1C                                 /* the DOS game's (obj_place_roadside) */
#define SIGNS      20

static u16 be16(const u8 *p) { return (u16)(p[0] << 8 | p[1]); }
static void le16(u8 *p, u16 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }

static u8 *load(const char *dir, const char *name, u32 *len)
{
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", dir, name);
    u8 *b = path ? rpck_load(path, len) : NULL;
    SDL_free(path);
    return b;
}

static bool save(const char *dir, const char *name, const void *data, size_t len)
{
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", dir, name);
    bool ok = path && SDL_SaveFile(path, data, len);
    SDL_free(path);
    return ok;
}

static u8 *load_dos(char *(*find)(const char *), const char *name, size_t *len)
{
    char *path = find(name);
    u8 *b = path ? SDL_LoadFile(path, len) : NULL;
    SDL_free(path);
    return b;
}

static size_t amiga_road_len(const u8 *f, u32 len)
{
    for (u32 i = AMIGA_HEADER; i < len; i++)
        if (f[i] == 0xFF) return i - AMIGA_HEADER;
    return 0;
}

/* The sign numbers in the order a road first shows them. */
static int sign_order(const u8 *road, size_t n, const u8 *records, u8 first, int signs, int out[SIGNS])
{
    int count = 0;
    bool seen[SIGNS] = { false };
    for (size_t i = 0; i < n; i++) {
        int q = records[4 * (road[i] & 0x7F) + 3] - first;
        if (q < 0 || q >= signs || seen[q]) continue;
        seen[q] = true;
        out[count++] = q;
    }
    return count;
}

/* An Amiga vector sign file as a DOS .SGN: 20 offsets, then records of 13 words (width, height, x,
 * y, three colour pairs, character width and height, spacing) and the text. The Amiga record has
 * three palette colours where DOS has its fixed white, green and black, and DOS signs are a little
 * bigger (the paired files of the other sceneries). map[d] is the Amiga sign shown as DOS sign d. */
static u8 *convert_signs(const u8 *a, u32 alen, const int map[SIGNS], size_t *out_len)
{
    u8 *out = SDL_calloc(1, 2 * SIGNS + SIGNS * 128 + 90);
    if (!out) return NULL;
    size_t o = 2 * SIGNS;
    for (int d = 0; d < SIGNS; d++) {
        if (map[d] < 0) continue;
        u16 at = be16(a + 2 * map[d]);
        le16(out + 2 * d, (u16)o);
        u16 w = be16(a + at), h = be16(a + at + 2), y = be16(a + at + 6), spacing = be16(a + at + 18);
        static const u16 colours[6] = { 0xFFFF, 0xFFFF, 0x2222, 0xAAAA, 0, 0 };
        u16 words[13] = { (u16)(w + w / 24 + 2), (u16)(h + 5), 43, y, 0, 0, 0, 0, 0, 0, 20, 20, spacing };
        memcpy(words + 4, colours, sizeof colours);
        for (int k = 0; k < 13; k++) le16(out + o + 2 * k, words[k]);
        o += 26;
        for (u32 i = at + 20u; i < alen && a[i] && o < 2 * SIGNS + SIGNS * 128u - 1; i++) {
            u8 c = a[i];
            if (c >= 'a' && c <= 'z') c = (u8)(c - 32);
            if (c == '\n' || (c >= 32 && c < 96)) out[o++] = c;   /* the DOS font: 64 glyphs from space */
        }
        out[o++] = 0;
        if (o & 1) out[o++] = 0;
    }
    *out_len = o + 90;                                  /* the game copies 45 words from each record */
    return out;
}

/* The icon: the scenery's Amiga title picture (euro_icon, 320x200 in 32 colours) as the DOS "picl", the
 * picture on the scenery choice screen (320x178 at y 13), and "pics", the main menu's 64x36 icon at
 * (168, 154), cut from its heath picture. Colours are the nearest of the EGA's 16 or of the CGA's
 * four (mode control 0Eh: black, light cyan, light red, white). */
static const u8 ega_rgb[16][3] = {
    { 0, 0, 0 }, { 0, 0, 170 }, { 0, 170, 0 }, { 0, 170, 170 }, { 170, 0, 0 }, { 170, 0, 170 },
    { 170, 85, 0 }, { 170, 170, 170 }, { 85, 85, 85 }, { 85, 85, 255 }, { 85, 255, 85 }, { 85, 255, 255 },
    { 255, 85, 85 }, { 255, 85, 255 }, { 255, 255, 85 }, { 255, 255, 255 },
};
static const u8 cga_rgb[4][3] = { { 0, 0, 0 }, { 85, 255, 255 }, { 255, 85, 85 }, { 255, 255, 255 } };

#define ICON_H 178
#define PICS_W 64
#define PICS_H 36
#define PICS_X 126                                      /* the heath picture's middle, 75x42 */
#define PICS_Y 15
#define PICS_SW 75
#define PICS_SH 42

static u8 nearest(const int rgb[3], const u8 (*pal)[3], int n)
{
    int best = 0, dist = 0x7FFFFFFF;
    for (int i = 0; i < n; i++) {
        int dr = rgb[0] - pal[i][0], dg = rgb[1] - pal[i][1], db = rgb[2] - pal[i][2];
        int d = 3 * dr * dr + 4 * dg * dg + 2 * db * db;
        if (d < dist) { dist = d; best = i; }
    }
    return (u8)best;
}

/* The picture's rows for the 178-row icon: the longest runs of blank rows give up one row at a time. */
static bool icon_rows(const AmigaPicture *p, u16 rows[ICON_H])
{
    if (p->w != 320 || p->h < ICON_H || p->h > 256) return false;
    int run_of[256], keep[256], at[256], runs = 0;    /* each row's blank run (or -1) and place in it */
    for (int y = 0; y < p->h; y++) {
        bool blank = true;
        for (int x = 0; x < p->w && blank; x++) blank = p->pix[y * p->w + x] == 0;
        run_of[y] = -1;
        if (!blank) continue;
        if (y == 0 || run_of[y - 1] < 0) keep[runs++] = 0;
        run_of[y] = runs - 1;
        at[y] = keep[runs - 1]++;
    }
    for (int cut = p->h - ICON_H; cut > 0; cut--) {
        int longest = -1;
        for (int r = 0; r < runs; r++)
            if (keep[r] && (longest < 0 || keep[r] > keep[longest])) longest = r;
        if (longest < 0) return false;
        keep[longest]--;
    }
    int n = 0;
    for (int y = 0; y < p->h && n < ICON_H; y++)
        if (run_of[y] < 0 || at[y] < keep[run_of[y]]) rows[n++] = (u16)y;
    return n == ICON_H;
}

/* One sprite of colour indices, w x h: the 16-byte header (width in bytes, height, hot spot, own
 * position, plane map), then the pixels row-major, which the loaders leave as they are (storage mode
 * 0): four bit planes for EGA, 2-bit pixels for CGA. */
static size_t put_sprite(u8 *out, const u8 *px, int w, int h, u16 x, u16 y, bool cga)
{
    int wb = cga ? w / 4 : w / 8;
    u16 head[6] = { (u16)wb, (u16)h, 0, 0, x, y };
    for (int k = 0; k < 6; k++) le16(out + 2 * k, head[k]);
    static const u8 ega_planes[4] = { 1, 2, 4, 8 };
    memcpy(out + 12, cga ? (const u8 *)"\0\0\0\0" : ega_planes, 4);
    u8 *d = out + 16;
    for (int k = 0; k < (cga ? 1 : 4); k++)
        for (int yy = 0; yy < h; yy++)
            for (int b = 0; b < wb; b++) {
                u8 v = 0;
                for (int i = 0; i < (cga ? 4 : 8); i++) {
                    u8 c = px[yy * w + b * (cga ? 4 : 8) + i];
                    v = cga ? (u8)(v << 2 | c) : (u8)(v << 1 | (c >> k & 1));
                }
                *d++ = v;
            }
    return (size_t)(d - out);
}

/* NGCICON.PES or .PCS: an archive of picl and pics (its length, the count, the names, the offsets
 * after the table), packed. */
static bool write_icon(const AmigaPicture *p, const u16 rows[ICON_H], bool cga, const char *dir)
{
    const u8 (*pal)[3] = cga ? cga_rgb : ega_rgb;
    int ncol = cga ? 4 : 16;
    u8 map[32];
    for (int i = 0; i < 32; i++) {
        int rgb[3] = { p->pal[i][0], p->pal[i][1], p->pal[i][2] };
        map[i] = nearest(rgb, pal, ncol);
    }
    u8 *picl = SDL_malloc(320 * ICON_H), pics[PICS_W * PICS_H];
    u8 *arc = SDL_malloc(22 + 2 * 16 + 320 * ICON_H / 2 + PICS_W * PICS_H / 2);
    if (!picl || !arc) {
        SDL_free(picl);
        SDL_free(arc);
        return false;
    }
    for (int y = 0; y < ICON_H; y++)
        for (int x = 0; x < 320; x++) picl[y * 320 + x] = map[p->pix[rows[y] * p->w + x] & 31];
    for (int y = 0; y < PICS_H; y++)                    /* each icon pixel: the mean of its source box */
        for (int x = 0; x < PICS_W; x++) {
            int x0 = PICS_X + x * PICS_SW / PICS_W, x1 = PICS_X + (x + 1) * PICS_SW / PICS_W;
            int y0 = PICS_Y + y * PICS_SH / PICS_H, y1 = PICS_Y + (y + 1) * PICS_SH / PICS_H;
            if (x1 == x0) x1++;
            if (y1 == y0) y1++;
            int sum[3] = { 0, 0, 0 }, n = 0;
            for (int yy = y0; yy < y1; yy++)
                for (int xx = x0; xx < x1; xx++, n++)
                    for (int c = 0; c < 3; c++) sum[c] += p->pal[p->pix[yy * p->w + xx] & 31][c];
            for (int c = 0; c < 3; c++) sum[c] /= n;
            pics[y * PICS_W + x] = nearest(sum, pal, ncol);
        }
    memcpy(arc + 4, "\2\0picl" "pics", 10);
    size_t o = 22;
    size_t first = put_sprite(arc + o, picl, 320, ICON_H, 0, 13, cga);
    size_t second = put_sprite(arc + o + first, pics, PICS_W, PICS_H, 168, 154, cga);
    u32 offs[2] = { 0, (u32)first }, total = (u32)(o + first + second);
    for (int i = 0; i < 2; i++)
        for (int b = 0; b < 4; b++) arc[14 + 4 * i + b] = (u8)(offs[i] >> 8 * b);
    for (int b = 0; b < 4; b++) arc[b] = (u8)(total >> 8 * b);
    size_t n;
    u8 *packed = dos_pack_rle(arc, total, &n);
    bool ok = packed && save(dir, cga ? CODE "ICON.PCS" : CODE "ICON.PES", packed, n);
    SDL_free(packed);
    SDL_free(arc);
    SDL_free(picl);
    return ok;
}

static bool build_icon(const char *amiga, const char *out)
{
    u32 len;
    u8 *f = load(amiga, "scen3/scen/euro_icon", &len);
    AmigaPicture p;
    u16 rows[ICON_H];
    bool ok = f && ilbm_read(f, len, &p);
    SDL_free(f);
    if (!ok) return false;
    ok = icon_rows(&p, rows) && write_icon(&p, rows, false, out) && write_icon(&p, rows, true, out);
    SDL_free(p.pix);
    return ok;
}

static bool fail(char *err, size_t n, const char *what, const char *name)
{
    SDL_snprintf(err, n, "Northern Germany: %s %s.", what, name);
    return false;
}

/* One stage: the twin with the archive name of the Amiga sprite file, and the signs. */
static bool build_stage(int s, const char *amiga, const char *out, char *(*find)(const char *),
                        const u8 *slices, char *err, size_t errn)
{
    char name[64];
    u32 nlen, slen, sglen;
    SDL_snprintf(name, sizeof name, "scen3/scen/euro_roaddata%d", s);
    u8 *road = load(amiga, name, &nlen);
    u8 *src = load(amiga, stages[s].road, &slen);
    bool same = road && src && nlen == slen && nlen > AMIGA_HEADER
             && memcmp(road, src, AMIGA_NAMES) == 0
             && memcmp(road + AMIGA_HEADER, src + AMIGA_HEADER, nlen - AMIGA_HEADER) == 0;
    SDL_free(src);
    if (!same) {
        SDL_free(road);
        return fail(err, errn, "the Amiga files are not the expected ones:", name);
    }

    SDL_snprintf(name, sizeof name, "%s.DAT", stages[s].twin);
    size_t plen, dlen;
    u8 *packed = load_dos(find, name, &plen);
    u8 *dat = packed ? dos_unpack(packed, plen, &dlen) : NULL;
    SDL_free(packed);
    if (!dat || dlen < DAT_ROAD) {
        SDL_free(dat);
        SDL_free(road);
        return fail(err, errn, "missing or unreadable DOS file", name);
    }
    memset(dat + DAT_NAME, 0, 20);
    memcpy(dat + DAT_NAME, stages[s].archive, strlen(stages[s].archive));
    size_t n;
    u8 *repacked = dos_pack_rle(dat, dlen, &n);
    SDL_snprintf(name, sizeof name, "%s%d.DAT", CODE, s);
    bool ok = repacked && save(out, name, repacked, n);
    SDL_free(repacked);

    /* The signs: the Amiga's sign q is DOS sign d where both roads show their signs in the same order. */
    SDL_snprintf(name, sizeof name, "scen3/scen/euro_vectorsigns%d", s);
    u8 *signs = ok ? load(amiga, name, &sglen) : NULL;
    if (signs && sglen >= 2 * SIGNS) {
        bool exists[SIGNS];
        for (int q = 0; q < SIGNS; q++) {
            u16 at = be16(signs + 2 * q);
            exists[q] = at >= 2 * SIGNS && at + 20u < sglen;
        }
        int aorder[SIGNS], dorder[SIGNS], map[SIGNS];
        size_t dn = (u16)(dat[DAT_LENGTH] | dat[DAT_LENGTH + 1] << 8);
        if (DAT_ROAD + dn > dlen) dn = dlen - DAT_ROAD;
        int na = sign_order(road + AMIGA_HEADER, amiga_road_len(road, nlen), slices, AMIGA_SIGN, AMIGA_SIGNS, aorder);
        int nd = sign_order(dat + DAT_ROAD, dn, dat + DAT_RECORDS, DOS_SIGN, SIGNS, dorder);
        for (int d = 0; d < SIGNS; d++) map[d] = -1;
        for (int i = 0; i < na && i < nd; i++) map[dorder[i]] = exists[aorder[i]] ? aorder[i] : -1;
        if (na && nd) {
            size_t sn;
            u8 *sgn = convert_signs(signs, sglen, map, &sn);
            SDL_snprintf(name, sizeof name, "%s%d.SGN", CODE, s);
            ok = sgn && save(out, name, sgn, sn);
            SDL_free(sgn);
        }
    }
    SDL_free(signs);
    SDL_free(dat);
    SDL_free(road);
    return ok;
}

bool northern_germany_build(const char *amiga_dir, const char *out_dir, char *(*find)(const char *name),
                            char *err, size_t err_size)
{
    u32 slen;
    u8 *file = load(amiga_dir, "scen3/scen/euro_slicedata", &slen);   /* 115 records; the rest are empty */
    u8 *slices = file ? SDL_calloc(128, 4) : NULL;
    if (slices) memcpy(slices, file, slen < 512 ? slen : 512);
    SDL_free(file);
    if (!slices) return fail(err, err_size, "the Amiga game has no", "scen3 (the scenery disk 3)");
    if (!SDL_CreateDirectory(out_dir)) {
        SDL_free(slices);
        return fail(err, err_size, "cannot create", out_dir);
    }
    bool ok = true;
    for (int s = 0; s < 7 && ok; s++) ok = build_stage(s, amiga_dir, out_dir, find, slices, err, err_size);
    SDL_free(slices);
    if (ok && !build_icon(amiga_dir, out_dir)) return fail(err, err_size, "cannot convert", "scen3/scen/euro_icon");
    for (size_t i = 0; i < SDL_arraysize(copies) && ok; i++) {
        size_t n;
        u8 *b = load_dos(find, copies[i].from, &n);
        if (!b) return fail(err, err_size, "missing DOS file", copies[i].from);
        ok = save(out_dir, copies[i].to, b, n);
        SDL_free(b);
    }
    static const char catalogue[] = CODE " " NAME " 7\r\n\x1A";
    if (ok) ok = save(out_dir, "SCENES.DAT", catalogue, sizeof catalogue - 1);
    if (!ok && !*err) fail(err, err_size, "cannot write to", out_dir);
    return ok;
}
