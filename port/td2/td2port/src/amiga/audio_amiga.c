/* The Amiga audio backend (audio_amiga.h). What the DOS game reports becomes what duel does at the same
 * moment: the title song when the game starts its menu song, the race loops at the start of a life, the
 * logic's physics step on each of the game's ten steps a second, the effects at their events. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amiga/amiga_mem.h"
#include "amiga/audio_amiga.h"
#include "amiga/paula.h"
#include "amiga/race_logic.h"
#include "amiga/race_sound.h"
#include "amiga/song.h"

/* Where the files go in amiga_mem: the song file at 10000h (song.c), then the race effects, then the
 * car's two samples, then the 8SVX game over sound. */
#define FX_BASE   0x30000u
#define FX_END    0x38000u
#define CAR_BASE  0x38000u
#define CAR_END   0x48000u
#define FORM_BASE 0x48000u
#define FORM_END  0x60000u

static u32 game_over;                               /* sfx/gameover, an 8SVX; 0 if missing */

static char root[1024];
static u8 *song_file;
static u32 song_len;
static bool ready;
static enum { QUIET, MUSIC, RACE } mode;
static char car_loaded[16];
static struct { u8 gear; u16 rpm; bool siren, radar; } prev;

/* The DOS car codes and the Amiga files of the same car ("<prefix>engine", "<prefix>turbo"). */
static const struct { const char *dos, *amiga; } cars[] = {
    { "F40", "cars/f40" }, { "P959", "cars/p959" },
    { "CAMA", "cars1/cars/camo" }, { "DODG", "cars1/cars/dodge" }, { "GT50", "cars1/cars/gt500" },
    { "GOAT", "cars1/cars/gto" }, { "STNG", "cars1/cars/stingray" },
    { "COUN", "cars2/cars/coun" }, { "LOTU", "cars2/cars/lotu" }, { "ROSS", "cars2/cars/ross" },
    { "RUF", "cars2/cars/ruf" }, { "VETT", "cars2/cars/vett" },
};

static u8 *read_file(const char *name, u32 *len)
{
    char path[1100];
    snprintf(path, sizeof path, "%s/%s", root, name);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *buf = n > 0 ? malloc((size_t)n) : NULL;
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    if (buf) *len = (u32)n;
    return buf;
}

/* Copies a file to amiga_mem at *at (word aligned) and moves *at past it; 0 if missing or too big. */
static u32 load_at(const char *name, u32 *at, u32 end)
{
    u32 len;
    u8 *buf = read_file(name, &len);
    if (!buf) return 0;
    u32 a = 0;
    if (*at + len <= end) {
        a = *at;
        memcpy(amiga_mem + a, buf, len);
        *at = (a + len + 1) & ~1u;
    }
    free(buf);
    return a;
}

bool audio_amiga_open(const char *dir, char *err, size_t errlen)
{
    ready = false;
    snprintf(root, sizeof root, "%s", dir);
    free(song_file);
    song_file = read_file("sfx/song", &song_len);
    if (!song_file) {
        snprintf(err, errlen, "%s has no sfx/song", dir);
        return false;
    }
    if (!song_load(song_file, song_len, err, errlen)) return false;
    const AmigaSeg *s = &song_seg;
    if (s->base[s->nsec - 1] + s->size[s->nsec - 1] > FX_BASE) {
        snprintf(err, errlen, "sfx/song is too big");
        return false;
    }
    u32 at = FX_BASE;
    RaceSamples *r = &race_samples;
    r->radar = load_at("sfx/radar", &at, FX_END);
    r->squeal = load_at("sfx/Squeal", &at, FX_END);
    r->bump = load_at("sfx/Bump", &at, FX_END);
    r->crash = load_at("sfx/crash", &at, FX_END);
    r->siren = load_at("sfx/siren", &at, FX_END);
    if (!r->radar || !r->squeal || !r->bump || !r->crash || !r->siren) {
        snprintf(err, errlen, "%s is missing race effects in sfx", dir);
        return false;
    }
    at = FORM_BASE;
    game_over = load_at("sfx/gameover", &at, FORM_END);
    car_loaded[0] = 0;
    ready = true;
    return true;
}

bool audio_amiga_ready(void) { return ready; }

static void load_car(const char *code)
{
    const char *prefix = cars[0].amiga;
    for (size_t i = 0; i < sizeof cars / sizeof cars[0]; i++)
        if (code && strcmp(code, cars[i].dos) == 0) prefix = cars[i].amiga;
    if (strcmp(car_loaded, prefix) == 0) return;
    char name[64];
    u32 at = CAR_BASE;
    snprintf(name, sizeof name, "%sengine", prefix);
    race_samples.engine = load_at(name, &at, CAR_END);
    snprintf(name, sizeof name, "%sturbo", prefix);
    race_samples.turbo = load_at(name, &at, CAR_END);
    snprintf(car_loaded, sizeof car_loaded, "%s", prefix);
}

/* ---- the two players and their interrupts */

static void race_audio_int(u16 intreqr) { race_sound_audio_int(intreqr, paula_intena()); }

static void race_vblank(void)                       /* $1231c: the siren sweep, then the driver */
{
    race_siren_sweep();
    race_sound_vblank(paula_intena());
}

static void silence(void)
{
    if (mode == MUSIC) song_stop();
    awr16(0xDFF09A, 0x0780);                        /* audio interrupts and DMA off */
    awr16(0xDFF096, 0x000F);
    paula_set_servers(NULL, NULL);
    paula_set_vblank(NULL);
    mode = QUIET;
}

static void start_music(void)
{
    silence();
    char err[128];
    if (!song_load(song_file, song_len, err, sizeof err)) return;   /* a fresh copy: the player edits its data */
    paula_set_servers(song_audio_int, song_tick);
    song_open();
    song_read_instruments();
    song_play();
    mode = MUSIC;
}

/* duel plays its game over sound from an overlay routine that has not been read; here the music
 * player's effect command plays it once, at full volume, on channel 0. */
static void play_game_over(void)
{
    silence();
    char err[128];
    if (!game_over || !song_load(song_file, song_len, err, sizeof err)) return;
    paula_set_servers(song_audio_int, song_tick);
    song_open();
    song_play_sfx(game_over, 0, 64, 1, 64);
    mode = MUSIC;
}

static void start_race(const char *car)
{
    silence();
    load_car(car);
    paula_set_servers(race_audio_int, NULL);
    paula_set_vblank(race_vblank);
    race_sound_init();
    race_logic_reset();
    memset(&race_car, 0, sizeof race_car);
    race_car.shift_squeal = -1;
    race_car.engine_on = true;
    memset(&prev, 0, sizeof prev);
    race_start_loops();
    mode = RACE;
}

/* ---- the backend */

static void amiga_reset(int rate)
{
    amiga_set_reg_hook(paula_write);
    paula_set_servers(NULL, NULL);
    paula_set_vblank(NULL);
    paula_reset(rate);
    mode = QUIET;
}

static void amiga_speaker(u16 divisor, u8 port61_bits) { (void)divisor; (void)port61_bits; }

static void amiga_render(s16 *out, int n) { paula_render(out, n); }

static void amiga_event(SoundEvent e, int n, const char *car)
{
    if (!ready) return;
    switch (e) {
    case SOUND_SONG:
        if (n == 1) start_music();                  /* the Amiga game has only its title song */
        else silence();
        break;
    case SOUND_RACE_START: start_race(car); break;
    case SOUND_RACE_END:
        if (mode != RACE) break;
        race_siren_stop();
        race_fade_out();
        race_car.engine_on = false;
        break;
    case SOUND_BUMP: if (mode == RACE) race_car.bump = true; break;
    case SOUND_CRASH: if (mode == RACE) race_crash(); break;
    case SOUND_GAME_OVER: play_game_over(); break;
    }
}

/* The DOS car's state in duel's terms ($1b292 for the skid squeal, $1a71e for the gear change squeal),
 * then duel's physics step. */
static void amiga_drive(const DriveSound *d)
{
    if (mode != RACE) return;
    RaceCar *c = &race_car;
    race_sound_on = d->sound_on;
    c->rpm = d->rpm;
    c->speed = (s32)d->speed << 8;
    c->throttle = d->throttle;
    c->in_gear = d->in_gear;
    c->engine_on = d->running;
    u16 v = d->skid ? (u16)((d->skid >> 4) + 25) : 0;
    c->squeal_volume = v > 64 ? 64 : v;
    c->pos = (s32)d->pos;
    c->cop_pos = (s32)d->cop_pos;
    c->cop_speed = (s32)d->cop_speed << 2;

    u8 gear = d->in_gear ? d->gear : 0;
    if (d->in_gear && d->throttle >= 0) {
        if (gear == 1 && prev.gear == 0 && (s16)prev.rpm > 4000) {          /* a fast start: wheelspin */
            s16 s = (s16)(25 - (s16)((u16)(prev.rpm - 0x898) >> 8));
            c->shift_squeal = s < 0 ? 0 : s;
        } else if (gear == 2 && prev.gear < 2 && (s16)(d->rpm - prev.rpm) < -0x640) {
            c->shift_squeal = 0xB;                  /* into second with a big drop */
        }
    }
    if (d->siren && !prev.siren) race_siren_start();
    if (!d->siren && prev.siren) race_siren_stop();
    if (d->radar && !prev.radar) race_radar();
    prev.gear = gear;
    prev.rpm = d->rpm;
    prev.siren = d->siren;
    prev.radar = d->radar;
    race_step();
}

const AudioBackend audio_amiga = { "Amiga", amiga_reset, amiga_speaker, amiga_render, amiga_event, amiga_drive };
