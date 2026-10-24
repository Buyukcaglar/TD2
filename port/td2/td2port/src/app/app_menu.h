#pragma once
/* The app's context menu (app_menu.c). */
void app_next_graphics(void);   /* Ctrl+Shift+G: request the next graphics mode and save it */
void app_menu_open(void);   /* from the HOST_CMD_MENU command: shows the menu and carries out the choice */
