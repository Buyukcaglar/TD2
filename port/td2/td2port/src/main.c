/* Test Drive II: The Duel SDL3 port — entry point.
 *
 * usage: td2port [--game-dir DIR] [--user-dir DIR] [--scale N] [--frame-rate FPS] [--cga | --hercules] [--check]
 *   --game-dir   folder with the original game files (default: "Game" in the working directory)
 *   --user-dir   folder for high scores and SELECT.DAT (default: %APPDATA%\TestDrive2 on Windows,
 *                the SDL preference folder elsewhere)
 *   --scale      initial window scale (default 3)
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
#include "mem.h"
#include "platform/gfx.h"
#include "platform/gfx_backend.h"
#include "platform/input.h"
#include "platform/timer.h"

int game_main(void);   /* game/flow.c: port of main() at 0000:07b3 */

static void app_command(HostCommand cmd)
{
    switch (cmd) {
    case HOST_CMD_NEXT_GRAPHICS: gfx_request_next_backend(); break;
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
    const char *dir = "Game";
    int scale = 3;
    bool check = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--game-dir") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--scale") && i + 1 < argc) scale = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--check")) check = true;
        else if (!strcmp(argv[i], "--cga")) gfx_set_backend(&gfx_cga_backend);
        else if (!strcmp(argv[i], "--hercules")) gfx_set_backend(&gfx_herc_backend);
        else if (!strcmp(argv[i], "--user-dir") && i + 1 < argc) host_set_user_dir(argv[++i]);
        else if (!strcmp(argv[i], "--frame-rate") && i + 1 < argc) host_set_frame_rate(atoi(argv[++i]));
        else {
            fprintf(stderr, "usage: %s [--game-dir DIR] [--user-dir DIR] [--scale N] [--frame-rate FPS] [--cga | --hercules] [--check]\n", argv[0]);
            return 2;
        }
    }

    char exe_path[1024];
    snprintf(exe_path, sizeof exe_path, "%s/%s", dir, TD_EXE_NAME);
    char err[256];
    if (!mem_load_exe(exe_path, err, sizeof err)) {
        fprintf(stderr, "%s\n", err);
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Test Drive II", err, NULL);
        return 1;
    }
    if (check) {
        printf("%s ok (%s): image %u bytes at %04X:0000, DGROUP %04X\n", TD_EXE_NAME, TD_VARIANT_NAME,
               mem_image_size, LOAD_SEG, DGROUP);
        return 0;
    }

    if (!host_init(dir, scale)) return 1;
    host_set_command_handler(app_command);
    gfx_init();      /* EGA model, frame source */
    timer_init();    /* host tick handler, timer routines */
    input_init();    /* INT 9 handler, getkey code pointers */
    int rc = game_main();
    host_shutdown();
    return rc;
}
