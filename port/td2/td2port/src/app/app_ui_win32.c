/* app_ui.h on Windows.
 *
 * Menus are Win32 popup menus owned by the SDL window. SDL3 already allows dark mode for the app and
 * its window (uxtheme's SetPreferredAppMode and AllowDarkModeForWindow), so they follow the system's
 * light or dark app theme. Question windows are small windows of our own in the same look: the
 * system's message font at the monitor's DPI, the theme's colours, dark-themed buttons and title bar.
 * The pickers are the system's file dialog, which follows the theme by itself. */
#include "app_ui.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <uxtheme.h>
#include <vssym32.h>
#include <SDL3/SDL.h>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "uxtheme.lib")

/* ---------------------------------------------------------------- menus */

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

/* ---------------------------------------------------------------- theme */

/* The user's app theme: "AppsUseLightTheme" is 0 for dark (Settings > Personalisation > Colours). */
static bool theme_is_dark(void)
{
    DWORD light = 1, size = sizeof light;
    RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                 L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &light, &size);
    return light == 0;
}

/* uxtheme's undocumented dark-mode switches (the ones SDL3 uses for its windows), so that controls and
 * scroll bars of a window can take the dark theme. Windows 10 1903 and later; elsewhere no-ops. */
static void allow_dark(HWND hwnd)
{
    typedef int (WINAPI *SetPreferredAppMode_t)(int);
    typedef BOOL (WINAPI *AllowDarkModeForWindow_t)(HWND, BOOL);
    static HMODULE uxtheme;
    static SetPreferredAppMode_t set_mode;
    static AllowDarkModeForWindow_t allow_window;
    if (!uxtheme) {
        uxtheme = LoadLibraryW(L"uxtheme.dll");
        if (!uxtheme) return;
        OSVERSIONINFOW v = { sizeof v };
        typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOW *);
        RtlGetVersion_t get_version = (RtlGetVersion_t)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        if (get_version) get_version(&v);
        if (v.dwBuildNumber >= 18362) {
            set_mode = (SetPreferredAppMode_t)(void *)GetProcAddress(uxtheme, MAKEINTRESOURCEA(135));
            allow_window = (AllowDarkModeForWindow_t)(void *)GetProcAddress(uxtheme, MAKEINTRESOURCEA(133));
        }
        if (set_mode) set_mode(1);      /* AllowDark: follow the system */
    }
    if (allow_window) allow_window(hwnd, TRUE);
}

/* ---------------------------------------------------------------- question windows */

#define BUTTON_ID 100

typedef struct {
    bool dark;
    HBRUSH bg;
    COLORREF fg, bg_colour;
    int result;
    int count;
    bool done;
} Question;

static LRESULT CALLBACK question_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    Question *q = (Question *)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (m) {
    case WM_CREATE:
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)((CREATESTRUCTW *)l)->lpCreateParams);
        return 0;
    case DM_GETDEFID:
        return MAKELRESULT(BUTTON_ID, DC_HASDEFID);
    case WM_COMMAND:
        if (LOWORD(w) == IDCANCEL) q->result = -1;
        else if (LOWORD(w) == IDOK) q->result = 0;
        else if (LOWORD(w) >= BUTTON_ID && LOWORD(w) < BUTTON_ID + q->count) q->result = LOWORD(w) - BUTTON_ID;
        else return 0;
        q->done = true;
        return 0;
    case WM_CLOSE:
        q->result = -1;
        q->done = true;
        return 0;
    case WM_ERASEBKGND: {
        RECT r;
        GetClientRect(h, &r);
        FillRect((HDC)w, &r, q->bg);
        return 1;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        SetTextColor((HDC)w, q->fg);
        SetBkColor((HDC)w, q->bg_colour);
        return (LRESULT)q->bg;
    default:
        return DefWindowProcW(h, m, w, l);
    }
}

static wchar_t *wide(const char *s)
{
    return (wchar_t *)SDL_iconv_string("UTF-16LE", "UTF-8", s, SDL_strlen(s) + 1);
}

int app_ui_question(void *parent, const char *title, const char *text, const char *const *buttons, int n)
{
    HWND owner = (HWND)parent;
    HINSTANCE inst = GetModuleHandleW(NULL);
    static bool registered;
    if (!registered) {
        WNDCLASSEXW wc = { sizeof wc };
        wc.lpfnWndProc = question_proc;
        wc.hInstance = inst;
        wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
        wc.lpszClassName = L"TD2QuestionWindow";
        RegisterClassExW(&wc);
        registered = true;
    }
    Question q = { 0 };
    q.dark = theme_is_dark();
    q.bg_colour = q.dark ? RGB(0x20, 0x20, 0x20) : GetSysColor(COLOR_WINDOW);
    q.fg = q.dark ? RGB(0xFF, 0xFF, 0xFF) : GetSysColor(COLOR_WINDOWTEXT);
    q.bg = CreateSolidBrush(q.bg_colour);
    q.count = n;
    q.result = -1;

    UINT dpi = owner ? GetDpiForWindow(owner) : GetDpiForSystem();
    NONCLIENTMETRICSW ncm = { sizeof ncm };
    SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0, dpi);
    HFONT font = CreateFontIndirectW(&ncm.lfMessageFont);
#define PX(v) MulDiv((v), (int)dpi, 96)

    /* Measure the text and the buttons. */
    wchar_t *wtext = wide(text), *wtitle = wide(title);
    HDC dc = GetDC(NULL);
    HGDIOBJ old = SelectObject(dc, font);
    RECT tr = { 0, 0, PX(440), 0 };
    DrawTextW(dc, wtext, -1, &tr, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    int bw[8], bh = PX(28), total = 0;
    wchar_t *wbutton[8];
    if (n > 8) n = 8;
    for (int i = 0; i < n; i++) {
        wbutton[i] = wide(buttons[i]);
        SIZE s;
        GetTextExtentPoint32W(dc, wbutton[i], lstrlenW(wbutton[i]), &s);
        bw[i] = s.cx + PX(32) > PX(88) ? s.cx + PX(32) : PX(88);
        total += bw[i] + (i ? PX(8) : 0);
    }
    SelectObject(dc, old);
    ReleaseDC(NULL, dc);

    int margin = PX(20), text_w = tr.right, text_h = tr.bottom;
    int client_w = (text_w > total ? text_w : total) + 2 * margin;
    int client_h = margin + text_h + PX(20) + bh + margin;
    DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU, ex = WS_EX_DLGMODALFRAME | (owner ? 0 : WS_EX_APPWINDOW);
    RECT wr = { 0, 0, client_w, client_h };
    AdjustWindowRectExForDpi(&wr, style, FALSE, ex, dpi);
    RECT area;
    if (owner) GetWindowRect(owner, &area);
    else SystemParametersInfoW(SPI_GETWORKAREA, 0, &area, 0);
    int ww = wr.right - wr.left, wh = wr.bottom - wr.top;
    int x = area.left + (area.right - area.left - ww) / 2, y = area.top + (area.bottom - area.top - wh) / 2;

    HWND h = CreateWindowExW(ex, L"TD2QuestionWindow", wtitle, style, x, y, ww, wh, owner, NULL, inst, &q);
    BOOL dark = q.dark;
    DwmSetWindowAttribute(h, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    allow_dark(h);
    HWND label = CreateWindowExW(0, L"STATIC", wtext, WS_CHILD | WS_VISIBLE | SS_NOPREFIX, margin, margin, text_w,
                                 text_h, h, NULL, inst, NULL);
    SendMessageW(label, WM_SETFONT, (WPARAM)font, FALSE);
    int bx = client_w - margin - total, by = margin + text_h + PX(20);
    HWND first = NULL;
    for (int i = 0; i < n; i++) {
        HWND b = CreateWindowExW(0, L"BUTTON", wbutton[i],
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | (i == 0 ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON),
                                 bx, by, bw[i], bh, h, (HMENU)(INT_PTR)(BUTTON_ID + i), inst, NULL);
        SendMessageW(b, WM_SETFONT, (WPARAM)font, FALSE);
        if (q.dark) {
            allow_dark(b);
            SetWindowTheme(b, L"DarkMode_Explorer", NULL);
        }
        if (i == 0) first = b;
        bx += bw[i] + PX(8);
        SDL_free(wbutton[i]);
    }
#undef PX
    SDL_free(wtext);
    SDL_free(wtitle);

    if (owner) EnableWindow(owner, FALSE);
    ShowWindow(h, SW_SHOW);
    SetForegroundWindow(h);
    if (first) SetFocus(first);
    MSG msg;
    while (!q.done && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (IsDialogMessageW(h, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (owner) {
        EnableWindow(owner, TRUE);
        SetForegroundWindow(owner);
    }
    DestroyWindow(h);
    DeleteObject(font);
    DeleteObject(q.bg);
    return q.result;
}

/* ---------------------------------------------------------------- the About box */

/* Laid out as the user's Civ64 About box: the icon with the lines and the link beside it, "License:"
 * over the licence in a scrolling read-only field, and OK at the bottom right, in dialog units of
 * Segoe UI 9. Dark mode as in the question windows; no theme of Windows draws a dark push button, so
 * OK is drawn here. */
#define ABOUT_ICON 201
#define ABOUT_LINK 202
#define ABOUT_LICENSE 203
#define DARK_BG RGB(32, 32, 32)
#define DARK_FIELD RGB(43, 43, 43)
#define DARK_TEXT RGB(255, 255, 255)
#define DARK_LINK RGB(96, 205, 255)

typedef struct {
    WORD buf[1024];
    size_t n;
} Template;

static void t_word(Template *t, WORD w)
{
    if (t->n < sizeof t->buf / sizeof t->buf[0]) t->buf[t->n++] = w;
}

static void t_str(Template *t, const wchar_t *s)
{
    do t_word(t, (WORD)*s); while (*s++);
}

/* One control, DWORD-aligned; a predefined class by its atom (80h button, 81h edit, 82h static). */
static void t_item(Template *t, DWORD style, short x, short y, short cx, short cy, WORD id, WORD cls,
                   const wchar_t *text)
{
    if (t->n & 1) t_word(t, 0);
    t_word(t, LOWORD(style));
    t_word(t, HIWORD(style));
    t_word(t, 0);
    t_word(t, 0);
    t_word(t, (WORD)x);
    t_word(t, (WORD)y);
    t_word(t, (WORD)cx);
    t_word(t, (WORD)cy);
    t_word(t, id);
    t_word(t, 0xFFFF);
    t_word(t, cls);
    t_str(t, text);
    t_word(t, 0);
}

typedef struct {
    const wchar_t *url, *license;
    bool dark;
    HBRUSH bg, field;
} About;

static void about_theme(HWND dlg, About *a)
{
    a->dark = theme_is_dark();
    BOOL dark = a->dark;
    DwmSetWindowAttribute(dlg, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof dark);
    allow_dark(dlg);
    HWND c = GetDlgItem(dlg, ABOUT_LICENSE);
    allow_dark(c);                          /* the licence's scroll bar */
    SetWindowTheme(c, a->dark ? L"DarkMode_Explorer" : NULL, NULL);
    SendMessageW(c, WM_THEMECHANGED, 0, 0);
    RedrawWindow(dlg, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
}

/* OK: in light mode the theme's push button (defaulted), in dark mode a flat face with a lighter
 * border, the accent's blue while it has the focus. */
static void about_button(const DRAWITEMSTRUCT *di, const About *a)
{
    RECT r = di->rcItem;
    wchar_t text[32] = L"";
    bool pressed = (di->itemState & ODS_SELECTED) != 0, focus = (di->itemState & ODS_FOCUS) != 0;
    HFONT font = (HFONT)SendMessageW(di->hwndItem, WM_GETFONT, 0, 0);
    HGDIOBJ old = font ? SelectObject(di->hDC, font) : NULL;
    GetWindowTextW(di->hwndItem, text, (int)(sizeof text / sizeof text[0]));
    if (a->dark) {
        HBRUSH face = CreateSolidBrush(pressed ? RGB(45, 45, 45) : RGB(60, 60, 60));
        HBRUSH edge = CreateSolidBrush(focus ? DARK_LINK : RGB(100, 100, 100));
        FillRect(di->hDC, &r, face);
        FrameRect(di->hDC, &r, edge);
        DeleteObject(face);
        DeleteObject(edge);
        SetTextColor(di->hDC, DARK_TEXT);
    } else {
        HTHEME th = OpenThemeData(di->hwndItem, L"BUTTON");
        FillRect(di->hDC, &r, GetSysColorBrush(COLOR_BTNFACE));
        if (th) {
            DrawThemeBackground(th, di->hDC, BP_PUSHBUTTON, pressed ? PBS_PRESSED : PBS_DEFAULTED, &r, NULL);
            CloseThemeData(th);
        } else {
            DrawFrameControl(di->hDC, &r, DFC_BUTTON, DFCS_BUTTONPUSH | (pressed ? DFCS_PUSHED : 0));
        }
        SetTextColor(di->hDC, GetSysColor(COLOR_BTNTEXT));
        if (focus && !(di->itemState & ODS_NOFOCUSRECT)) {
            RECT f = r;
            InflateRect(&f, -3, -3);
            DrawFocusRect(di->hDC, &f);
        }
    }
    SetBkMode(di->hDC, TRANSPARENT);
    if (pressed) OffsetRect(&r, 1, 1);
    DrawTextW(di->hDC, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE |
                                         ((di->itemState & ODS_NOACCEL) ? DT_HIDEPREFIX : 0));
    if (old) SelectObject(di->hDC, old);
}

static INT_PTR CALLBACK about_proc(HWND dlg, UINT m, WPARAM w, LPARAM l)
{
    About *a = (About *)GetWindowLongPtrW(dlg, DWLP_USER);
    switch (m) {
    case WM_INITDIALOG: {
        a = (About *)l;
        SetWindowLongPtrW(dlg, DWLP_USER, (LONG_PTR)a);
        HICON icon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1));
        if (icon) SendDlgItemMessageW(dlg, ABOUT_ICON, STM_SETICON, (WPARAM)icon, 0);
        SetDlgItemTextW(dlg, ABOUT_LICENSE, a->license);
        about_theme(dlg, a);
        SetFocus(GetDlgItem(dlg, IDOK));
        return FALSE;                       /* the focus is set */
    }
    case WM_SETTINGCHANGE:
        if (a && l && lstrcmpW((const wchar_t *)l, L"ImmersiveColorSet") == 0) about_theme(dlg, a);
        break;
    case WM_DRAWITEM:
        if (a && w == IDOK) {
            about_button((const DRAWITEMSTRUCT *)l, a);
            return TRUE;
        }
        break;
    case WM_CTLCOLORDLG:
        if (a && a->dark) return (INT_PTR)a->bg;
        break;
    case WM_CTLCOLORSTATIC:
        if (!a) break;
        if ((HWND)l == GetDlgItem(dlg, ABOUT_LINK)) {
            SetTextColor((HDC)w, a->dark ? DARK_LINK : RGB(0, 0, 204));
            SetBkMode((HDC)w, TRANSPARENT);
            return (INT_PTR)(a->dark ? a->bg : GetSysColorBrush(COLOR_BTNFACE));
        }
        if (a->dark) {                      /* the lines, the icon and the read-only licence */
            bool field = (HWND)l == GetDlgItem(dlg, ABOUT_LICENSE);
            SetTextColor((HDC)w, DARK_TEXT);
            SetBkColor((HDC)w, field ? DARK_FIELD : DARK_BG);
            return (INT_PTR)(field ? a->field : a->bg);
        }
        break;
    case WM_SETCURSOR:
        if ((HWND)w == GetDlgItem(dlg, ABOUT_LINK)) {
            SetCursor(LoadCursorW(NULL, (LPCWSTR)IDC_HAND));
            SetWindowLongPtrW(dlg, DWLP_MSGRESULT, TRUE);
            return TRUE;
        }
        break;
    case WM_COMMAND:
        if (a && LOWORD(w) == ABOUT_LINK && HIWORD(w) == STN_CLICKED) {
            ShellExecuteW(dlg, L"open", a->url, NULL, NULL, SW_SHOWNORMAL);
            return TRUE;
        }
        if (LOWORD(w) == IDOK || LOWORD(w) == IDCANCEL) {
            EndDialog(dlg, 1);
            return TRUE;
        }
        break;
    default:
        break;
    }
    return FALSE;
}

void app_ui_about(void *parent, const char *title, const char *const *lines, int n, const char *url,
                  const char *license)
{
    /* the edit control breaks lines at \r\n only */
    char *crlf = SDL_malloc(2 * SDL_strlen(license) + 1), *o = crlf;
    for (const char *c = license; *c; c++) {
        if (*c == '\n') *o++ = '\r';
        *o++ = *c;
    }
    *o = 0;
    wchar_t *wtitle = wide(title), *wurl = wide(url), *wlicense = wide(crlf);
    SDL_free(crlf);
    if (n > 2) n = 2;

    Template t = { 0 };
    DWORD style = DS_MODALFRAME | DS_SETFONT | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    t_word(&t, LOWORD(style));
    t_word(&t, HIWORD(style));
    t_word(&t, 0);
    t_word(&t, 0);
    t_word(&t, (WORD)(5 + n));              /* controls */
    t_word(&t, 0);
    t_word(&t, 0);
    t_word(&t, 260);
    t_word(&t, 196);
    t_word(&t, 0);                          /* no menu */
    t_word(&t, 0);                          /* the dialog class */
    t_str(&t, wtitle);
    t_word(&t, 9);
    t_str(&t, L"Segoe UI");
    t_item(&t, WS_CHILD | WS_VISIBLE | SS_ICON, 10, 10, 21, 20, ABOUT_ICON, 0x82, L"");
    for (int i = 0; i < n; i++) {
        wchar_t *line = wide(lines[i]);
        t_item(&t, WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 42, (short)(10 + 11 * i), 208, 9, 0xFFFF, 0x82, line);
        SDL_free(line);
    }
    t_item(&t, WS_CHILD | WS_VISIBLE | WS_TABSTOP | SS_LEFT | SS_NOTIFY | SS_NOPREFIX, 42, (short)(10 + 11 * n),
           208, 9, ABOUT_LINK, 0x82, wurl);
    t_item(&t, WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 48, 240, 9, 0xFFFF, 0x82, L"License:");
    t_item(&t, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 10, 59,
           240, 108, ABOUT_LICENSE, 0x81, L"");
    /* owner-drawn; Enter still chooses it, the dialog manager's default being IDOK */
    t_item(&t, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 200, 174, 50, 15, IDOK, 0x80, L"OK");

    About a = { wurl, wlicense, false, CreateSolidBrush(DARK_BG), CreateSolidBrush(DARK_FIELD) };
    DialogBoxIndirectParamW(GetModuleHandleW(NULL), (LPCDLGTEMPLATEW)t.buf, (HWND)parent, about_proc, (LPARAM)&a);
    DeleteObject(a.bg);
    DeleteObject(a.field);
    SDL_free(wtitle);
    SDL_free(wurl);
    SDL_free(wlicense);
}

/* ---------------------------------------------------------------- pickers, restart */

char *app_ui_pick_path(void *parent, bool folder, const char *title)
{
    HRESULT init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    IFileOpenDialog *d = NULL;
    char *result = NULL;
    if (SUCCEEDED(CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &IID_IFileOpenDialog, (void **)&d))) {
        FILEOPENDIALOGOPTIONS opts = 0;
        IFileOpenDialog_GetOptions(d, &opts);
        IFileOpenDialog_SetOptions(d, opts | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | (folder ? FOS_PICKFOLDERS : FOS_FILEMUSTEXIST));
        wchar_t *wtitle = wide(title);
        IFileOpenDialog_SetTitle(d, wtitle);
        SDL_free(wtitle);
        if (!folder) {
            COMDLG_FILTERSPEC types[] = {
                { L"Archives (zip, 7z, rar, lha)", L"*.zip;*.7z;*.rar;*.lha;*.lzh" },
                { L"All files", L"*.*" },
            };
            IFileOpenDialog_SetFileTypes(d, 2, types);
        }
        IShellItem *item = NULL;
        if (SUCCEEDED(IFileOpenDialog_Show(d, (HWND)parent)) && SUCCEEDED(IFileOpenDialog_GetResult(d, &item))) {
            wchar_t *path = NULL;
            if (SUCCEEDED(IShellItem_GetDisplayName(item, SIGDN_FILESYSPATH, &path))) {
                result = SDL_iconv_string("UTF-8", "UTF-16LE", (const char *)path, (lstrlenW(path) + 1) * sizeof(wchar_t));
                CoTaskMemFree(path);
            }
            IShellItem_Release(item);
        }
        IFileOpenDialog_Release(d);
    }
    if (SUCCEEDED(init)) CoUninitialize();
    return result;
}

bool app_ui_restart(void)
{
    wchar_t exe[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return false;
    STARTUPINFOW si = { sizeof si };
    PROCESS_INFORMATION pi;
    wchar_t *cmd = _wcsdup(GetCommandLineW());
    BOOL ok = CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    free(cmd);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

#else

#include <stdio.h>

int app_ui_popup_menu(void *native_window, const AppMenuItem *items, int n)
{
    (void)native_window; (void)items; (void)n;
    return 0;
}

int app_ui_question(void *parent, const char *title, const char *text, const char *const *buttons, int n)
{
    (void)parent; (void)title; (void)buttons; (void)n;
    fprintf(stderr, "%s\n", text);
    return -1;
}

char *app_ui_pick_path(void *parent, bool folder, const char *title)
{
    (void)parent; (void)folder; (void)title;
    return NULL;
}

void app_ui_about(void *parent, const char *title, const char *const *lines, int n, const char *url,
                  const char *license)
{
    (void)parent; (void)lines; (void)n; (void)license;
    fprintf(stderr, "%s\n%s\n", title, url);
}

bool app_ui_restart(void) { return false; }

#endif
