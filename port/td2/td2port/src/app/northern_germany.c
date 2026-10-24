/* The Amiga version's Northern Germany Challenge as a DOS scenery (northern_germany.h). */
#include <SDL3/SDL.h>
#include <string.h>

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
/* Files taken from the European Challenge. */
static const struct { const char *from, *to; } copies[] = {
    { "EC_.FNT", CODE ".FNT" },
    { "EC_CAR1.PES", CODE "CAR1.PES" }, { "EC_CAR1.PCS", CODE "CAR1.PCS" },
    { "EC_CAR2.PES", CODE "CAR2.PES" }, { "EC_CAR2.PCS", CODE "CAR2.PCS" },
    { "EC_CAR3.PES", CODE "CAR3.PES" }, { "EC_CAR3.PCS", CODE "CAR3.PCS" },
    { "EC_ICON.PES", CODE "ICON.PES" }, { "EC_ICON.PCS", CODE "ICON.PCS" },
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
