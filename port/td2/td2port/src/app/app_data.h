#pragma once
/* The game data manager and the settings file (docs/native-windows.md sections 3 and 4).
 *
 * Folders. The profile folder holds settings.ini, the high scores, SELECT.DAT and the generated
 * catalogues. It is --user-dir, else "Profile" next to the exe when that folder is writable (the
 * portable case), else the per-user folder (%APPDATA%\TestDrive2). The game folders are --game-dir, else
 * the settings' "game" folder and its "expansion" folders, else "Game" next to the exe, else "Game" in
 * the working directory. The game folders are only read.
 *
 * Game files. The first game folder must hold the base DOS game: TD2EGA.EXE, the common screens and
 * music, the Ferrari F40, the Porsche 959 and the Master scenery. Any folder may add cars and sceneries
 * with their own CARS.DAT and SCENES.DAT, as the original's car and scenery disks did. The catalogues
 * the game reads are those entries merged, in folder order, keeping only the cars and sceneries whose
 * files are all there; they are written to the profile folder, which the game reads first. */
#include "../types.h"

bool app_data_init(const char *game_dir_arg, const char *user_dir_arg, char *err, size_t err_size);
const char *app_data_profile_dir(void);
int  app_data_game_dir_count(void);
const char *app_data_game_dir(int i);
char *app_data_find(const char *name);                   /* first game folder's file, or NULL; SDL_free it */
bool app_data_write_catalogues(char *err, size_t err_size);

/* Settings (settings.ini in the profile folder: "key=value" lines). */
const char *app_setting(const char *key);                /* NULL when not set */
void app_setting_set(const char *key, const char *value);   /* saves the file */
