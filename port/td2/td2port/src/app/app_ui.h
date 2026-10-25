#pragma once
/* The app's own user interface around the game, one implementation per operating system
 * (app_ui_win32.c; a macOS one later). It never draws into the game picture: menus, question windows
 * and file pickers are the system's own or follow its look, light or dark (docs/native-windows.md §2). */
#include "../types.h"

/* One entry of a popup menu. A separator has no label. An entry with a submenu opens it and is never
 * chosen itself; any other entry returns its id (non-zero). Text is UTF-8; after a tab comes the
 * shortcut, shown right-aligned. */
typedef struct AppMenuItem {
    const char *label;
    int id;
    bool checked;                       /* shown with a radio mark */
    const struct AppMenuItem *submenu;
    int submenu_n;
} AppMenuItem;

/* Shows the menu at the mouse pointer over the game window (native_window: host_native_window()) and
 * returns the chosen id, or 0 when the menu was dismissed. Blocks until then. */
int app_ui_popup_menu(void *native_window, const AppMenuItem *items, int n);

/* A question window: the text (UTF-8, '\n' for new lines) and a row of buttons, the first of them the
 * default (Enter). Returns the index of the button chosen, or -1 when the window was closed (Escape).
 * Modal over `parent` (NULL before the game window exists). */
int app_ui_question(void *parent, const char *title, const char *text, const char *const *buttons, int n);

/* The About box, as in the user's Civ64: the app icon, up to two lines and a link beside it (a click
 * opens it in the browser), the licence (UTF-8, '\n' for new lines) in a scrolling read-only field,
 * and OK. Modal over `parent`. */
void app_ui_about(void *parent, const char *title, const char *const *lines, int n, const char *url,
                  const char *license);

/* The system's picker for a folder, or for an archive file (zip, 7z, rar, lha, lzh). Returns the
 * chosen path (SDL_free it), or NULL when cancelled. */
char *app_ui_pick_path(void *parent, bool folder, const char *title);

/* Starts the app again with the same command line; the caller quits right after. */
bool app_ui_restart(void);
