/* The game data manager and the settings file (app_data.h). */
#include "app_data.h"

#include <SDL3/SDL.h>
#include <stdio.h>
#include <string.h>

#define MAX_DIRS      16
#define MAX_SETTINGS  32
#define MAX_ENTRIES   30            /* the game reads at most this many catalogue entries (flow.h) */

static char *profile_dir;
static char *settings_path;
static char *dirs[MAX_DIRS];
static int ndirs;
static struct { char key[32]; char value[512]; } settings[MAX_SETTINGS];
static int nsettings;

/* ---------------------------------------------------------------- settings */

static void settings_load(void)
{
    nsettings = 0;
    size_t size = 0;
    char *text = SDL_LoadFile(settings_path, &size);
    if (!text) return;
    for (char *line = text, *next; line && *line; line = next) {
        next = SDL_strchr(line, '\n');
        if (next) *next++ = 0;
        size_t n = SDL_strlen(line);
        while (n && (line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = 0;
        char *eq = SDL_strchr(line, '=');
        if (line[0] == '#' || !eq || nsettings == MAX_SETTINGS) continue;
        *eq = 0;
        SDL_strlcpy(settings[nsettings].key, line, sizeof settings[0].key);
        SDL_strlcpy(settings[nsettings].value, eq + 1, sizeof settings[0].value);
        nsettings++;
    }
    SDL_free(text);
}

static void settings_save(void)
{
    SDL_IOStream *io = SDL_IOFromFile(settings_path, "w");
    if (!io) return;
    SDL_IOprintf(io, "# Test Drive II port settings. The app writes this file when a setting changes.\n");
    for (int i = 0; i < nsettings; i++) SDL_IOprintf(io, "%s=%s\n", settings[i].key, settings[i].value);
    SDL_CloseIO(io);
}

const char *app_setting(const char *key)
{
    for (int i = 0; i < nsettings; i++)
        if (SDL_strcmp(settings[i].key, key) == 0) return settings[i].value;
    return NULL;
}

void app_setting_set(const char *key, const char *value)
{
    int i = 0;
    while (i < nsettings && SDL_strcmp(settings[i].key, key) != 0) i++;
    if (i == nsettings) {
        if (nsettings == MAX_SETTINGS) return;
        nsettings++;
        SDL_strlcpy(settings[i].key, key, sizeof settings[0].key);
    }
    SDL_strlcpy(settings[i].value, value, sizeof settings[0].value);
    settings_save();
}

/* ---------------------------------------------------------------- folders and files */

static char *find_in(const char *dir, const char *name)
{
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", dir, name);
    if (SDL_GetPathInfo(path, NULL)) return path;
    SDL_free(path);
    path = NULL;
    int count = 0;
    char **entries = SDL_GlobDirectory(dir, NULL, 0, &count);
    for (int i = 0; entries && i < count && !path; i++)
        if (SDL_strcasecmp(entries[i], name) == 0) SDL_asprintf(&path, "%s/%s", dir, entries[i]);
    SDL_free(entries);
    return path;
}

static bool has(const char *dir, const char *name)
{
    char *p = find_in(dir, name);
    SDL_free(p);
    return p != NULL;
}

/* Both graphics versions of a sprite file (EGA .PES and CGA .PCS), so that live switching works. */
static bool has_shapes(const char *dir, const char *code, const char *part)
{
    char a[32], b[32];
    SDL_snprintf(a, sizeof a, "%s%s.PES", code, part);
    SDL_snprintf(b, sizeof b, "%s%s.PCS", code, part);
    return has(dir, a) && has(dir, b);
}

static bool car_complete(const char *dir, const char *code)
{
    static const char *files[] = { ".BIN", "O.BIN", ".SS" };
    static const char *shapes[] = { "DASH", "REAR", "ROAD", "ST" };
    char name[32];
    for (size_t i = 0; i < SDL_arraysize(files); i++) {
        SDL_snprintf(name, sizeof name, "%s%s", code, files[i]);
        if (!has(dir, name)) return false;
    }
    for (size_t i = 0; i < SDL_arraysize(shapes); i++)
        if (!has_shapes(dir, code, shapes[i])) return false;
    return true;
}

/* The number of stages whose files are there (code0.DAT, code1.DAT, ...), at most `listed`; 0 when
 * the traffic cars or the menu icon are missing. */
static int scenery_stages(const char *dir, const char *code, int listed)
{
    static const char *shapes[] = { "CAR1", "CAR2", "CAR3", "ICON" };
    for (size_t i = 0; i < SDL_arraysize(shapes); i++)
        if (!has_shapes(dir, code, shapes[i])) return 0;
    int n = 0;
    char name[32];
    while (n < listed && n < 10) {
        SDL_snprintf(name, sizeof name, "%s%d.DAT", code, n);
        if (!has(dir, name)) break;
        n++;
    }
    return n;
}

static const char *missing_base_file(const char *dir)
{
    static const char *files[] = { "TD2EGA.EXE", "SONGS.BIN", "VOICES.BIN", "CARS.DAT", "SCENES.DAT" };
    static const char *screens[] = {
        "ACCOLADE", "TESTDRV2", "DSITITLE", "GAMEOPT", "GAMEDIFF", "GASSTUFF", "ENDGAME", "COP", "ROAD",
    };
    for (size_t i = 0; i < SDL_arraysize(files); i++)
        if (!has(dir, files[i])) return files[i];
    for (size_t i = 0; i < SDL_arraysize(screens); i++)
        if (!has_shapes(dir, screens[i], "")) return screens[i];
    if (!car_complete(dir, "F40")) return "the Ferrari F40 (F40*)";
    if (!car_complete(dir, "P959")) return "the Porsche 959 (P959*)";
    if (scenery_stages(dir, "TDS2", 6) < 6) return "the Master scenery (TDS2*)";
    return NULL;
}

static void add_dir(const char *dir)
{
    if (ndirs < MAX_DIRS && dir && *dir) dirs[ndirs++] = SDL_strdup(dir);
}

static bool open_profile(const char *dir)
{
    if (!SDL_CreateDirectory(dir)) return false;
    char *path = NULL;
    SDL_asprintf(&path, "%s/settings.ini", dir);
    SDL_IOStream *io = SDL_IOFromFile(path, "a");      /* the folder must be writable */
    if (!io) {
        SDL_free(path);
        return false;
    }
    SDL_CloseIO(io);
    profile_dir = SDL_strdup(dir);
    settings_path = path;
    size_t n = SDL_strlen(profile_dir);
    while (n > 1 && (profile_dir[n - 1] == '/' || profile_dir[n - 1] == '\\')) profile_dir[--n] = 0;
    return true;
}

bool app_data_init(const char *game_dir_arg, const char *user_dir_arg, char *err, size_t err_size)
{
    const char *base = SDL_GetBasePath();
    char *portable = NULL;
    if (base) SDL_asprintf(&portable, "%sProfile", base);
    bool ok = user_dir_arg ? open_profile(user_dir_arg)
                           : (portable && open_profile(portable));
    SDL_free(portable);
    if (!ok && !user_dir_arg) {
        char *pref = SDL_GetPrefPath(NULL, "TestDrive2");
        ok = pref && open_profile(pref);
        SDL_free(pref);
    }
    if (!ok) {
        SDL_snprintf(err, err_size, "Cannot create the profile folder %s.", user_dir_arg ? user_dir_arg : "for scores and settings");
        return false;
    }
    settings_load();

    if (game_dir_arg) {
        add_dir(game_dir_arg);
    } else if (app_setting("game")) {
        add_dir(app_setting("game"));
        for (int i = 0; i < nsettings; i++)
            if (SDL_strcmp(settings[i].key, "expansion") == 0) add_dir(settings[i].value);
    } else {
        char *next_to_exe = NULL;
        if (base) SDL_asprintf(&next_to_exe, "%sGame", base);
        add_dir(next_to_exe && !missing_base_file(next_to_exe) ? next_to_exe : "Game");
        SDL_free(next_to_exe);
    }
    const char *missing = missing_base_file(dirs[0]);
    if (missing) {
        SDL_snprintf(err, err_size,
                     "The folder %s does not hold the base DOS game of Test Drive II: %s is missing.\n\n"
                     "The base game is TD2EGA.EXE with its screens and music, the Ferrari F40, the Porsche 959 "
                     "and the Master scenery. Car and scenery expansions are optional.", dirs[0], missing);
        return false;
    }
    return true;
}

const char *app_data_profile_dir(void) { return profile_dir; }
int app_data_game_dir_count(void) { return ndirs; }
const char *app_data_game_dir(int i) { return i >= 0 && i < ndirs ? dirs[i] : NULL; }
char *app_data_find(const char *name) { return ndirs ? find_in(dirs[0], name) : NULL; }

/* ---------------------------------------------------------------- catalogues */

typedef struct { char code[5]; char name[21]; int stages; } Entry;

/* Reads "code name" (cars) or "code name stages" (sceneries) entries, as the game's fscanf does. */
static int read_catalogue(const char *dir, const char *file, bool scenes, Entry *out, int max)
{
    char *path = find_in(dir, file);
    size_t size = 0;
    char *text = path ? SDL_LoadFile(path, &size) : NULL;
    SDL_free(path);
    if (!text) return 0;
    for (size_t i = 0; i < size; i++)
        if (text[i] == 0x1A) text[i] = 0;
    int n = 0;
    char *save = NULL;
    for (char *tok = SDL_strtok_r(text, " \t\r\n", &save); tok && n < max; ) {
        Entry e = { 0 };
        SDL_strlcpy(e.code, tok, sizeof e.code);
        char *name = SDL_strtok_r(NULL, " \t\r\n", &save);
        if (!name) break;
        SDL_strlcpy(e.name, name, sizeof e.name);
        if (scenes) {
            char *stages = SDL_strtok_r(NULL, " \t\r\n", &save);
            if (!stages) break;
            e.stages = SDL_atoi(stages);
        }
        out[n++] = e;
        tok = SDL_strtok_r(NULL, " \t\r\n", &save);
    }
    SDL_free(text);
    return n;
}

static bool write_catalogue(const char *file, bool scenes, const Entry *e, int n)
{
    char *path = NULL;
    SDL_asprintf(&path, "%s/%s", profile_dir, file);
    SDL_IOStream *io = SDL_IOFromFile(path, "wb");
    SDL_free(path);
    if (!io) return false;
    for (int i = 0; i < n; i++) {
        if (scenes) SDL_IOprintf(io, "%s %s %d\r\n", e[i].code, e[i].name, e[i].stages);
        else SDL_IOprintf(io, "%s %s\r\n", e[i].code, e[i].name);
    }
    SDL_IOprintf(io, "\x1A");
    return SDL_CloseIO(io);
}

static bool listed(const Entry *e, int n, const char *code)
{
    for (int i = 0; i < n; i++)
        if (SDL_strcasecmp(e[i].code, code) == 0) return true;
    return false;
}

bool app_data_write_catalogues(char *err, size_t err_size)
{
    Entry cars[MAX_ENTRIES], scenes[MAX_ENTRIES], found[MAX_ENTRIES];
    int ncars = 0, nscenes = 0;
    for (int d = 0; d < ndirs; d++) {
        int n = read_catalogue(dirs[d], "CARS.DAT", false, found, MAX_ENTRIES);
        for (int i = 0; i < n && ncars < MAX_ENTRIES; i++)
            if (!listed(cars, ncars, found[i].code) && car_complete(dirs[d], found[i].code)) cars[ncars++] = found[i];
        n = read_catalogue(dirs[d], "SCENES.DAT", true, found, MAX_ENTRIES);
        for (int i = 0; i < n && nscenes < MAX_ENTRIES; i++) {
            if (listed(scenes, nscenes, found[i].code)) continue;
            found[i].stages = scenery_stages(dirs[d], found[i].code, found[i].stages);
            if (found[i].stages > 0) scenes[nscenes++] = found[i];
        }
    }
    if (!write_catalogue("CARS.DAT", false, cars, ncars) || !write_catalogue("SCENES.DAT", true, scenes, nscenes)) {
        SDL_snprintf(err, err_size, "Cannot write the game catalogues to %s.", profile_dir);
        return false;
    }
    return true;
}
