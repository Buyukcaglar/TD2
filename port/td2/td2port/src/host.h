#pragma once
/* Host services on top of SDL3: window/present, the 99.9985 Hz timer tick, keyboard (raw XT scan codes
 * for the game's own INT 9 handler, plus a BIOS-style buffer), gamepad, PC speaker audio, game file
 * lookup and fatal errors. No game logic lives here. */
#include "types.h"
#include "audio_backend.h"

#define PIT_HZ        1193182u
#define PIT_DIV_GAME  0x2E9Cu        /* 11932 -> 99.9985 Hz, the game's timer rate (06c9:6059) */

/* The game folders, searched in the order they were added (app/app_data.h). Call before host_init. */
void host_add_game_dir(const char *dir);
bool host_init(int window_scale);
void host_shutdown(void);

/* Called once per 99.9985 Hz tick from host_pump() (the port's replacement for INT 8).
 * The timer module installs its ISR body (tick counters and the timer routine list). */
void host_set_tick_handler(void (*handler)(void));

/* Source of the displayed image: fills a w x h XRGB8888 frame (at most HOST_FRAME_MAX_W x
 * HOST_FRAME_MAX_H) and returns true if it changed since the last call. The frame is shown with 4:3
 * aspect. Installed by the graphics module (EGA/CGA 320x200, Hercules 640x300). */
#define HOST_FRAME_MAX_W 640
#define HOST_FRAME_MAX_H 300
void host_set_frame_source(bool (*compose)(u32 *xrgb), int w, int h);
void host_set_title_mode(const char *mode);   /* "Test Drive II (<mode>)" */

/* App commands: key combinations and mouse clicks the app handles itself, which the game never sees.
 * The keys are the same on Windows and macOS (Ctrl, not Cmd): Ctrl+Shift+G cycles the graphics mode,
 * Ctrl+Shift+S the sound, Ctrl+Shift+M or a right click opens the app's menu. The handler runs inside host_pump(), at any
 * point of the game, so it may only do what is safe at any time (record a switch, change the window). */
typedef enum { HOST_CMD_NEXT_GRAPHICS, HOST_CMD_NEXT_SOUND, HOST_CMD_MENU } HostCommand;
void host_set_command_handler(void (*handler)(HostCommand cmd));

/* For the app's own UI (app/): the native window (HWND on Windows), and a pause of the game clock and
 * the sound while a menu or question window is open, so the game does not run on behind it. */
void *host_native_window(void);
void host_pause_begin(void);
void host_pause_end(void);
int  host_window_scale(void);                 /* the window's width over 320, rounded */
void host_set_window_scale(int scale);         /* leaves full screen; 320 x 240 times scale */
bool host_fullscreen(void);
void host_set_fullscreen(bool on);
_Noreturn void host_quit(void);

/* Runs due timer ticks, generates speaker audio, handles window events and presents the screen when
 * it changed. Every busy-wait loop of the original (key polls, deadlines, delays) must call this.
 * Sleeps briefly when nothing was due, so tight polling loops do not spin the CPU. */
void host_pump(void);

/* Emulated original frame rate (port option, default HOST_DEFAULT_FPS). The original's stage loop ran as
 * fast as the PC could draw; the simulation runs on timer ticks, but a few things count rendered frames
 * (gear-gate close delay, dash phase). host_frame_begin() pumps and then waits for the next frame slot at
 * the configured rate (0 = unpaced). */
#define HOST_DEFAULT_FPS 15
void host_set_frame_rate(int fps);
int  host_frame_rate(void);
void host_frame_begin(void);

/* Presents immediately if the frame source reports a change (used by unpaced effects that the
 * original drew at CPU speed). Blocks on VSync. */
void host_present_now(void);

/* ---- Raw keyboard (the game's INT 9 handler, 06c9:6907). The handler is called from host_pump() /
 * host event processing, in event order, with the XT set-1 scan code of each key event: make codes for
 * presses and key repeats (typematic), code | 0x80 for releases. Extended keys (arrows, Home, ...) give
 * the same codes as their keypad twins, without the E0 prefix. F11/F12 are not reported. */
void host_set_scan_handler(void (*handler)(u8 xt_code));

/* ---- BIOS keyboard (INT 16h; not used by TD2, which reads its own INT 9 state). Key words are (XT scan code << 8) | ASCII, including key repeats. */
bool host_kbd_peek(u16 *key);    /* AH=01h: true if a key is buffered (not removed) */
bool host_kbd_read(u16 *key);    /* AH=00h without blocking: removes and returns the oldest key */
void host_kbd_flush(void);
u8   host_kbd_shift_flags(void); /* AH=02h: bit0 right shift, bit1 left shift, bit2 ctrl, bit3 alt */

/* Held-key driving controls (port option, default on): the driving poll reads directions and the
 * A/Z shift keys from the live keyboard state instead of BIOS key repeats. --bios-keys turns it off. */
void host_set_held_keys(bool on);
bool host_held_keys(void);
/* True while the key with this XT scan code is down. Supports A (0x1E), Z (0x2C) and the cursor /
 * keypad block 0x47..0x51 (arrows and keypad digits both count). */
bool host_xt_key_down(u8 xt_scan);

/* ---- Joystick: first connected gamepad. Axes -32768..32767, buttons bit0 = A, bit1 = B. */
bool host_joy_read(s16 *x, s16 *y, u8 *buttons);

/* ---- PC speaker: PIT channel 2 divisor and port 61h bits 0 (PIT gate) and 1 (speaker data); it
 * sounds while both are set. divisor 0 means 65536. Changes take effect from the current tick onward. */
void host_speaker(u16 divisor, u8 port61_bits);
/* The audio backend the speaker writes and sound events go to (audio_backend.h). Default: the PC
 * speaker. It can change at any time: the new backend starts with the speaker's last state and with
 * what the game plays now (the race, or the last song). */
void host_set_audio_backend(const AudioBackend *b);
const AudioBackend *host_audio_backend(void);
/* The game's sound events and, ten times a second during a race, the car's state (audio_backend.h). */
void host_sound_event(SoundEvent e, int n, const char *car);
void host_sound_drive(const DriveSound *d);

/* ---- Developer aid: with TD2_STATE_DIR set, the sim timer routine's entry state (the 1 MiB of memory,
 * then the leftover BP and CX as little-endian words) is saved as stateNNN.bin every TD2_STATE_EVERY
 * calls (default 64), up to TD2_STATE_MAX files (default 40). The differential harness replays these. */
void host_sim_state(const u8 *memory, u32 size, u16 bp, u16 cx);

/* ---- Game files: case-insensitive lookup in the profile folder, then the game directory. Returns a
 * malloc'd path (SDL_free it) or NULL if the file does not exist. For files the game writes pass
 * create = true; the path is then always inside the profile folder. */
void  host_set_user_dir(const char *dir);   /* before host_init; NULL = per-user app data folder */
char *host_game_path(const char *name, bool create);
void  host_free(void *p);        /* frees memory returned by host functions (host_game_path) */

/* ---- Errors: shows a message box, shuts down and exits with code 3 (like the original abort). */
_Noreturn void host_fatal(const char *fmt, ...);
