/* app_ui.h on Windows: a Win32 popup menu owned by the SDL window. SDL3 already allows dark mode for
 * the app and its window (SetPreferredAppMode, AllowDarkModeForWindow), so the menu follows the
 * system's light or dark app theme. */
#include "app_ui.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HMENU build_menu(const AppMenuItem *items, int n)
{
    HMENU menu = CreatePopupMenu();
    for (int i = 0; i < n; i++) {
        const AppMenuItem *it = &items[i];
        if (!it->label) {
            AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
            continue;
        }
        wchar_t text[128];
        if (!MultiByteToWideChar(CP_UTF8, 0, it->label, -1, text, (int)(sizeof text / sizeof text[0])))
            text[0] = 0;
        MENUITEMINFOW mi = { sizeof mi };
        mi.fMask = MIIM_STRING | MIIM_FTYPE | MIIM_STATE | MIIM_ID;
        mi.fType = MFT_STRING | (it->checked ? MFT_RADIOCHECK : 0);
        mi.fState = it->checked ? MFS_CHECKED : 0;
        mi.wID = (UINT)it->id;
        mi.dwTypeData = text;
        if (it->submenu) {
            mi.fMask |= MIIM_SUBMENU;
            mi.hSubMenu = build_menu(it->submenu, it->submenu_n);
        }
        InsertMenuItemW(menu, (UINT)GetMenuItemCount(menu), TRUE, &mi);
    }
    return menu;
}

int app_ui_popup_menu(void *native_window, const AppMenuItem *items, int n)
{
    HWND hwnd = (HWND)native_window;
    HMENU menu = build_menu(items, n);
    POINT at;
    GetCursorPos(&at);
    SetForegroundWindow(hwnd);          /* so the menu closes when the user clicks elsewhere */
    int id = (int)TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, at.x, at.y, hwnd, NULL);
    DestroyMenu(menu);                  /* destroys the submenus too */
    return id;
}

#else

int app_ui_popup_menu(void *native_window, const AppMenuItem *items, int n)
{
    (void)native_window; (void)items; (void)n;
    return 0;
}

#endif
