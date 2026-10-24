/* The app's context menu (right click, or Ctrl+Shift+M): graphics mode, Hercules monitor colour,
 * window size, full screen, game files, about, quit. It opens from inside host_pump(), at any point of
 * the game, so every command here is one that is safe at any time: a graphics switch is only
 * requested, the rest changes the window or the monitor colour or the settings, and new game files
 * take effect on a restart. The game is paused until the command is done. */
#include "app_menu.h"
#include "app_data.h"
#include "app_ui.h"
#include "../host.h"
#include "../platform/gfx_backend.h"

#include <SDL3/SDL.h>

enum {
    CMD_EGA = 1, CMD_CGA, CMD_HERC, CMD_NEXT_GRAPHICS,
    CMD_PHOSPHOR_WHITE, CMD_PHOSPHOR_GREEN, CMD_PHOSPHOR_AMBER,
    CMD_SCALE_1, CMD_SCALE_2, CMD_SCALE_3, CMD_SCALE_4,
    CMD_FULLSCREEN, CMD_GAME_FILES, CMD_ABOUT, CMD_QUIT,
};

#define VERSION "0.1"

static const struct { int cmd; u32 rgb; const char *name; } phosphors[] = {
    { CMD_PHOSPHOR_WHITE, GFX_HERC_WHITE, "white" }, { CMD_PHOSPHOR_GREEN, GFX_HERC_GREEN, "green" },
    { CMD_PHOSPHOR_AMBER, GFX_HERC_AMBER, "amber" },
};

/* The mode the game shows or is about to show, saved as the next start's mode. */
static void save_graphics(void)
{
    app_setting_set("graphics", (gfx_pending_backend() ? gfx_pending_backend() : gfx_backend())->name);
}

/* The Game files window: what is installed, and adding an expansion folder or archive. */
static void game_files(void)
{
    static const char *const buttons[] = { "Add folder…", "Add archive…", "Close" };
    static const char *const restart[] = { "Restart now", "Later" };
    static const char *const ok[] = { "OK" };
    void *win = host_native_window();
    char text[4096];
    app_data_summary(text, sizeof text);
    SDL_strlcat(text, "\n\nExpansions add cars and sceneries: a folder or an archive (zip, 7z, rar, lha) with "
                "their files and their CARS.DAT or SCENES.DAT.", sizeof text);
    int choice = app_ui_question(win, "Game files", text, buttons, 3);
    if (choice != 0 && choice != 1) return;
    char *path = app_ui_pick_path(win, choice == 0, choice == 0 ? "An expansion folder" : "An expansion archive");
    if (!path) return;
    int ncars = 0, nscenes = 0;
    if (!app_data_probe(path, &ncars, &nscenes)) {
        SDL_snprintf(text, sizeof text, "%s holds no complete cars or sceneries for Test Drive II.", path);
        app_ui_question(win, "Game files", text, ok, 1);
        SDL_free(path);
        return;
    }
    app_setting_add("expansion", path);
    SDL_snprintf(text, sizeof text, "%s adds %d cars and %d sceneries. They are available after a restart of "
                 "the game.", path, ncars, nscenes);
    SDL_free(path);
    if (app_ui_question(win, "Game files", text, restart, 2) == 0 && app_ui_restart()) host_quit();
}

static void about(void)
{
    static const char *const ok[] = { "OK" };
    app_ui_question(host_native_window(), "About Test Drive II",
                    "Test Drive II: The Duel, port " VERSION "\n\n"
                    "Plays the original 1989 DOS game by Distinctive Software and Accolade from its own "
                    "files, which are not included.\n\n"
                    "Port code: the Kylofon Test Drive II port (MIT licence) and this project's work on it.\n"
                    "Libraries: SDL 3 (zlib licence), libarchive (BSD licence), zlib, xz.\n\n"
                    "Ctrl+Shift+G: next graphics mode\nCtrl+Shift+M or right click: this menu\nAlt+Enter: full screen",
                    ok, 1);
}

void app_next_graphics(void)
{
    gfx_request_next_backend();
    save_graphics();
}

void app_menu_open(void)
{
    const GfxBackend *shown = gfx_pending_backend() ? gfx_pending_backend() : gfx_backend();
    u32 phosphor = gfx_herc_phosphor();
    int scale = host_window_scale();
    AppMenuItem graphics[] = {
        { "EGA", CMD_EGA, shown == &gfx_ega_backend },
        { "CGA", CMD_CGA, shown == &gfx_cga_backend },
        { "Hercules", CMD_HERC, shown == &gfx_herc_backend },
        { NULL },
        { "Next mode\tCtrl+Shift+G", CMD_NEXT_GRAPHICS },
    };
    AppMenuItem monitor[] = {
        { "White", CMD_PHOSPHOR_WHITE, phosphor == GFX_HERC_WHITE },
        { "Green", CMD_PHOSPHOR_GREEN, phosphor == GFX_HERC_GREEN },
        { "Amber", CMD_PHOSPHOR_AMBER, phosphor == GFX_HERC_AMBER },
    };
    AppMenuItem size[] = {
        { "1×", CMD_SCALE_1, !host_fullscreen() && scale == 1 },
        { "2×", CMD_SCALE_2, !host_fullscreen() && scale == 2 },
        { "3×", CMD_SCALE_3, !host_fullscreen() && scale == 3 },
        { "4×", CMD_SCALE_4, !host_fullscreen() && scale == 4 },
        { NULL },
        { "Full screen\tAlt+Enter", CMD_FULLSCREEN, host_fullscreen() },
    };
    AppMenuItem items[] = {
        { "Graphics", 0, false, graphics, (int)(sizeof graphics / sizeof graphics[0]) },
        { "Hercules monitor", 0, false, monitor, (int)(sizeof monitor / sizeof monitor[0]) },
        { "Window size", 0, false, size, (int)(sizeof size / sizeof size[0]) },
        { NULL },
        { "Game files…", CMD_GAME_FILES },
        { "About Test Drive II", CMD_ABOUT },
        { NULL },
        { "Quit", CMD_QUIT },
    };

    host_pause_begin();
    int cmd = app_ui_popup_menu(host_native_window(), items, (int)(sizeof items / sizeof items[0]));

    switch (cmd) {
    case CMD_EGA:  gfx_request_backend(&gfx_ega_backend); save_graphics(); break;
    case CMD_CGA:  gfx_request_backend(&gfx_cga_backend); save_graphics(); break;
    case CMD_HERC: gfx_request_backend(&gfx_herc_backend); save_graphics(); break;
    case CMD_NEXT_GRAPHICS: app_next_graphics(); break;
    case CMD_SCALE_1: case CMD_SCALE_2: case CMD_SCALE_3: case CMD_SCALE_4: {
        char v[2] = { (char)('1' + cmd - CMD_SCALE_1), 0 };
        host_set_window_scale(cmd - CMD_SCALE_1 + 1);
        app_setting_set("scale", v);
        app_setting_set("fullscreen", "0");
        break;
    }
    case CMD_FULLSCREEN:
        host_set_fullscreen(!host_fullscreen());
        app_setting_set("fullscreen", host_fullscreen() ? "1" : "0");
        break;
    case CMD_GAME_FILES: game_files(); break;
    case CMD_ABOUT: about(); break;
    case CMD_QUIT: host_quit();
    default:
        for (size_t i = 0; i < sizeof phosphors / sizeof phosphors[0]; i++)
            if (phosphors[i].cmd == cmd) {
                gfx_herc_set_phosphor(phosphors[i].rgb);
                app_setting_set("hercules_monitor", phosphors[i].name);
            }
        break;
    }
    host_pause_end();
}
