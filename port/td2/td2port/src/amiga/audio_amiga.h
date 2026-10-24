#pragma once
/* The Amiga audio backend: the Amiga game's own music player (song.c) in the menus and its race sound
 * driver and logic (race_sound.c, race_logic.c) during a race, played through the Paula model, from the
 * Amiga game's files. The DOS game drives it with its sound events and car state (audio_backend.h). */
#include "audio_backend.h"

/* Loads the music and the race effects from the Amiga game folder (the one with duel and sfx); the car
 * samples are read from there at each race start. False with a reason when files are missing. */
bool audio_amiga_open(const char *dir, char *err, size_t errlen);
bool audio_amiga_ready(void);

extern const AudioBackend audio_amiga;
