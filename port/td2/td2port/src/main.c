/* Test Drive II: The Duel SDL3 port — entry point.
 *
 * usage: td2port [--game-dir DIR] [--user-dir DIR] [--scale N] [--frame-rate FPS] [--cga | --hercules] [--check]
 *   --game-dir   folder with the original game files (default: the settings' game folders, else "Game"
 *                next to the exe or in the working directory; app/app_data.h)
 *   --user-dir   profile folder for settings, high scores and SELECT.DAT (default: "Profile" next to
 *                the exe when writable, else %APPDATA%\TestDrive2 on Windows)
 *   --scale      initial window scale (default: the saved one, else 3)
 *   --frame-rate emulated original drawing speed while driving (default HOST_DEFAULT_FPS; 0 = unpaced)
 *   --cga        draw with the CGA graphics of TD2CGA.EXE instead of EGA
 *   --hercules   TD2CGA.EXE's Hercules mode ("td2cga herc"): the CGA game on a monochrome monitor
 *   --check      load and verify the original executable, print a summary and exit (no window)
 */
#define SDL_MAIN_HANDLED
#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"
#include "app/app_data.h"
#include "app/app_menu.h"
#include "app/app_ui.h"
#include "amiga/audio_amiga.h"
#include "mem.h"
#include "platform/gfx.h"
#include "platform/gfx_backend.h"
#include "platform/input.h"
#include "platform/timer.h"

int game_main(void);   /* game/flow.c: port of main() at 0000:07b3 */

static void app_command(HostCommand cmd)
{
    switch (cmd) {
    case HOST_CMD_NEXT_GRAPHICS: app_next_graphics(); break;
    case HOST_CMD_NEXT_SOUND: app_next_sound(); break;
    case HOST_CMD_MENU: app_menu_open(); break;
    }
}

static int startup_error(const char *msg)
{
    static const char *const ok[] = { "OK" };
    fprintf(stderr, "%s\n", msg);
    app_ui_question(NULL, "Test Drive II", msg, ok, 1);
    return 1;
}

/* First start, or the saved game folder no longer holds the base game: ask for the folder or archive
 * that does, until one does or the player quits. */
static bool ask_for_game(const char *user_dir, char *err, size_t err_size)
{
    static const char *const buttons[] = { "Choose folder…", "Choose archive…", "Quit" };
    for (;;) {
        char text[1024];
        SDL_snprintf(text, sizeof text,
                     "Test Drive II needs the original DOS game files.\n\n%s\n\n"
                     "Choose the folder, or the archive (zip, 7z, rar, lha), that holds them.", err);
        int choice = app_ui_question(NULL, "Test Drive II", text, buttons, 3);
        if (choice != 0 && choice != 1) return false;
        char *path = app_ui_pick_path(NULL, choice == 0, choice == 0 ? "The Test Drive II game folder"
                                                                     : "The Test Drive II game archive");
        if (!path) continue;
        app_setting_set("game", path);
        SDL_free(path);
        if (app_data_init(NULL, user_dir, err, err_size)) return true;
    }
}

/* The saved settings, where the command line did not choose (app/app_data.h). */
static void apply_settings(const GfxBackend *backend, int *scale)
{
    static const GfxBackend *const backends[] = { &gfx_ega_backend, &gfx_cga_backend, &gfx_herc_backend };
    const char *g = app_setting("graphics");
    for (size_t i = 0; !backend && g && i < sizeof backends / sizeof backends[0]; i++)
        if (!strcmp(g, backends[i]->name)) backend = backends[i];
    gfx_set_backend(backend ? backend : &gfx_ega_backend);
    const char *m = app_setting("hercules_monitor");
    if (m && !strcmp(m, "green")) gfx_herc_set_phosphor(GFX_HERC_GREEN);
    if (m && !strcmp(m, "amber")) gfx_herc_set_phosphor(GFX_HERC_AMBER);
    if (*scale < 1) *scale = app_setting("scale") ? atoi(app_setting("scale")) : 3;
    if (*scale < 1 || *scale > 8) *scale = 3;
    /* The Amiga sound, when the settings name the Amiga game's folder or archive. */
    if (app_amiga_open(NULL)) {
        const char *s = app_setting("sound");
        if (s && !strcmp(s, audio_amiga.name)) host_set_audio_backend(&audio_amiga);
    }
}

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The exe is a windowed app, so it has no console of its own. Output that a caller redirected (the
 * snapshot tool, a pipe) works as it is; otherwise messages go to the console it was started from. */
static void attach_parent_console(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE), err = GetStdHandle(STD_ERROR_HANDLE);
    bool have_out = out != NULL && out != INVALID_HANDLE_VALUE;
    bool have_err = err != NULL && err != INVALID_HANDLE_VALUE;
    if ((have_out && have_err) || !AttachConsole(ATTACH_PARENT_PROCESS)) return;
    if (!have_out) freopen("CONOUT$", "w", stdout);
    if (!have_err) freopen("CONOUT$", "w", stderr);
}
#else
static void attach_parent_console(void) {}
#endif

int main(int argc, char **argv)
{
    attach_parent_console();
    const char *dir = NULL, *user_dir = NULL;
    int scale = 0;
    bool check = false;
    const GfxBackend *backend = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--game-dir") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--scale") && i + 1 < argc) scale = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--check")) check = true;
        else if (!strcmp(argv[i], "--cga")) backend = &gfx_cga_backend;
        else if (!strcmp(argv[i], "--hercules")) backend = &gfx_herc_backend;
        else if (!strcmp(argv[i], "--user-dir") && i + 1 < argc) user_dir = argv[++i];
        else if (!strcmp(argv[i], "--frame-rate") && i + 1 < argc) host_set_frame_rate(atoi(argv[++i]));
        else {
            fprintf(stderr, "usage: %s [--game-dir DIR] [--user-dir DIR] [--scale N] [--frame-rate FPS] [--cga | --hercules] [--check]\n", argv[0]);
            return 2;
        }
    }

    char err[512];
    if (!app_data_init(dir, user_dir, err, sizeof err)) {
        if (dir || !app_data_profile_dir() || check) return startup_error(err);
        if (!ask_for_game(user_dir, err, sizeof err)) return 1;
    }
    char *exe_path = app_data_find(TD_EXE_NAME);
    bool loaded = exe_path && mem_load_exe(exe_path, err, sizeof err);
    SDL_free(exe_path);
    if (!loaded) return startup_error(err);
    if (check) {
        printf("%s ok (%s): image %u bytes at %04X:0000, DGROUP %04X\n", TD_EXE_NAME, TD_VARIANT_NAME,
               mem_image_size, LOAD_SEG, DGROUP);
        return 0;
    }

    if (!app_data_write_catalogues(err, sizeof err)) return startup_error(err);
    host_set_user_dir(app_data_profile_dir());
    for (int i = 0; i < app_data_game_dir_count(); i++) host_add_game_dir(app_data_game_dir(i));
    apply_settings(backend, &scale);
    if (!host_init(scale)) return 1;
    if (app_setting("fullscreen") && !strcmp(app_setting("fullscreen"), "1")) host_set_fullscreen(true);
    host_set_command_handler(app_command);
    gfx_init();      /* EGA model, frame source */
    timer_init();    /* host tick handler, timer routines */
    input_init();    /* INT 9 handler, getkey code pointers */
    int rc = game_main();
    host_shutdown();
    return rc;
}
