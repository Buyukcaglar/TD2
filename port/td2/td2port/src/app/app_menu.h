#pragma once
/* The app's context menu (app_menu.c). */
#include "../types.h"

void app_next_graphics(void);   /* Ctrl+Shift+G: request the next graphics mode and save it */
void app_next_sound(void);      /* Ctrl+Shift+S: PC speaker or Amiga sound, and save it */
/* Opens the Amiga game's sound files from a folder or archive (NULL: the "amiga" setting). */
bool app_amiga_open(const char *path);
void app_menu_open(void);   /* from the HOST_CMD_MENU command: shows the menu and carries out the choice */
