/* The app's context menu (right click, or Ctrl+Shift+M): graphics mode, Hercules monitor colour,
 * window size, full screen, quit. It opens from inside host_pump(), at any point of the game, so every
 * command here is one that is safe at any time: a graphics switch is only requested, and the rest
 * changes the window or the monitor colour. The game is paused while the menu is open. */
#include "app_menu.h"
#include "app_ui.h"
#include "../host.h"
#include "../platform/gfx_backend.h"

enum {
    CMD_EGA = 1, CMD_CGA, CMD_HERC, CMD_NEXT_GRAPHICS,
    CMD_PHOSPHOR_WHITE, CMD_PHOSPHOR_GREEN, CMD_PHOSPHOR_AMBER,
    CMD_SCALE_1, CMD_SCALE_2, CMD_SCALE_3, CMD_SCALE_4,
    CMD_FULLSCREEN, CMD_QUIT,
};

static const struct { int cmd; u32 rgb; } phosphors[] = {
    { CMD_PHOSPHOR_WHITE, GFX_HERC_WHITE }, { CMD_PHOSPHOR_GREEN, GFX_HERC_GREEN }, { CMD_PHOSPHOR_AMBER, GFX_HERC_AMBER },
};

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
        { "Quit", CMD_QUIT },
    };

    host_pause_begin();
    int cmd = app_ui_popup_menu(host_native_window(), items, (int)(sizeof items / sizeof items[0]));
    host_pause_end();

    switch (cmd) {
    case CMD_EGA:  gfx_request_backend(&gfx_ega_backend); break;
    case CMD_CGA:  gfx_request_backend(&gfx_cga_backend); break;
    case CMD_HERC: gfx_request_backend(&gfx_herc_backend); break;
    case CMD_NEXT_GRAPHICS: gfx_request_next_backend(); break;
    case CMD_SCALE_1: case CMD_SCALE_2: case CMD_SCALE_3: case CMD_SCALE_4:
        host_set_window_scale(cmd - CMD_SCALE_1 + 1);
        break;
    case CMD_FULLSCREEN: host_set_fullscreen(!host_fullscreen()); break;
    case CMD_QUIT: host_quit();
    default:
        for (size_t i = 0; i < sizeof phosphors / sizeof phosphors[0]; i++)
            if (phosphors[i].cmd == cmd) gfx_herc_set_phosphor(phosphors[i].rgb);
        break;
    }
}
