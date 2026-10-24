#pragma once
/* The app's own user interface around the game, one implementation per operating system
 * (app_ui_win32.c; a macOS one later). It never draws into the game picture: menus and question
 * windows are the system's own, so they follow its light or dark theme (docs/native-windows.md §2). */
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
