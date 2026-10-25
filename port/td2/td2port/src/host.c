#include "host.h"
#include "audio_backend.h"

#include <SDL3/SDL.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AUDIO_RATE 44100

static SDL_Window *window;
static SDL_Renderer *renderer;
static SDL_Texture *texture;
static SDL_AudioStream *audio;
static SDL_Gamepad *gamepad;
#define MAX_GAME_DIRS 16
static char *game_dirs[MAX_GAME_DIRS];
static int ngame_dirs;
static char *user_dir;        /* profile folder for files the game writes (scores, SELECT.DAT) */
static char *user_dir_arg;

static void (*tick_handler)(void);
static bool (*frame_source)(u32 *);
static u32 frame[HOST_FRAME_MAX_W * HOST_FRAME_MAX_H];
static int frame_w = 320, frame_h = 200;
#define VIEW_W(w) (w)                   /* logical presentation: frame width x 3/4 of it (4:3) */
#define VIEW_H(w) ((w) * 3 / 4)

/* Tick clock: tick n is due at start + n * 11927 / 1193182 s (exact rational arithmetic). */
static Uint64 clock_start_ns;
static Uint64 ticks_run;

/* Developer aid: with TD2_VIRTUAL_CLOCK set, time advances only while the host would wait, so a run
 * depends on nothing but the game (and runs as fast as the machine allows). TD2_RUN_SECONDS ends the
 * run after that much game time. Together with TD2_SNAPSHOT_DIR this gives repeatable snapshots.
 * TD2_HOLD_SECONDS stops the game at that game time (decimals allowed) and keeps its last frame in the
 * window until it is closed, for screenshots of the same moment in every graphics mode. */
static bool virtual_clock;
static Uint64 virtual_ns;
static Uint64 run_limit_ns, hold_ns;

/* TD2_KEYS presses keys at given game times, for headless runs of the menus and races:
 * "20:Return,24.5:Down,30:Up/5" (seconds, an SDL scancode name, and optionally how many seconds to
 * hold it; 0.1 s otherwise). */
#define KEY_SCRIPT_MAX 256
static struct { Uint64 at_ns, hold_ns; SDL_Scancode sc; SDL_Keymod mod; u8 state; } key_script[KEY_SCRIPT_MAX];
static int key_script_n;
static void key_script_load(const char *text);
static void key_script_run(Uint64 game_ns);

static Uint64 now_ns(void) { return virtual_clock ? virtual_ns : SDL_GetTicksNS(); }
static void wait_ns(Uint64 ns)
{
    if (virtual_clock) virtual_ns += ns;
    else SDL_DelayNS(ns);
}

/* BIOS keyboard buffer (15 keys, like the real one). */
#define KBD_SIZE 16
static u16 kbd_buf[KBD_SIZE];
static int kbd_head, kbd_tail;

/* What the player hears (audio_backend.h). */
static const AudioBackend *audio_be = &audio_pc_speaker;
static double samples_per_tick_frac;
static SDL_IOStream *audio_dump;          /* TD2_AUDIO_DUMP: copy of the output as a WAV file */
static Uint32 audio_dump_bytes;

static void process_events(void);

/* Developer aid: with TD2_AUDIO_DUMP set to a file name, everything the speaker plays is also written
 * there as a 16-bit stereo WAV file (works with SDL_AUDIO_DRIVER=dummy). */
static void audio_dump_header(void)
{
    static const char riff[] = "RIFF", wave[] = "WAVEfmt ", data[] = "data";
    SDL_SeekIO(audio_dump, 0, SDL_IO_SEEK_SET);
    SDL_WriteIO(audio_dump, riff, 4);
    SDL_WriteU32LE(audio_dump, 36 + audio_dump_bytes);
    SDL_WriteIO(audio_dump, wave, 8);
    SDL_WriteU32LE(audio_dump, 16);
    SDL_WriteU16LE(audio_dump, 1);                                  /* PCM */
    SDL_WriteU16LE(audio_dump, 2);                                  /* stereo */
    SDL_WriteU32LE(audio_dump, AUDIO_RATE);
    SDL_WriteU32LE(audio_dump, AUDIO_RATE * 4);
    SDL_WriteU16LE(audio_dump, 4);
    SDL_WriteU16LE(audio_dump, 16);
    SDL_WriteIO(audio_dump, data, 4);
    SDL_WriteU32LE(audio_dump, audio_dump_bytes);
    SDL_SeekIO(audio_dump, 0, SDL_IO_SEEK_END);
}

static void audio_dump_open(void)
{
    const char *path = SDL_getenv("TD2_AUDIO_DUMP");
    if (!path || !*path) return;
    audio_dump = SDL_IOFromFile(path, "wb");
    if (!audio_dump) { fprintf(stderr, "TD2_AUDIO_DUMP: %s\n", SDL_GetError()); return; }
    audio_dump_bytes = 0;
    audio_dump_header();
}

static void audio_dump_close(void)
{
    if (!audio_dump) return;
    audio_dump_header();
    SDL_CloseIO(audio_dump);
    audio_dump = NULL;
}

void host_set_user_dir(const char *dir)
{
    SDL_free(user_dir_arg);
    user_dir_arg = dir ? SDL_strdup(dir) : NULL;
}

/* The profile folder is --user-dir, or the per-user application data folder
 * (%APPDATA%\TestDrive2 on Windows). It is created if missing. */
static bool init_user_dir(void)
{
    if (user_dir_arg) {
        if (!SDL_CreateDirectory(user_dir_arg)) {
            fprintf(stderr, "cannot create user dir %s: %s\n", user_dir_arg, SDL_GetError());
            return false;
        }
        user_dir = SDL_strdup(user_dir_arg);
    } else {
        user_dir = SDL_GetPrefPath(NULL, "TestDrive2");
        if (!user_dir) {
            fprintf(stderr, "no user data folder: %s\n", SDL_GetError());
            return false;
        }
    }
    size_t n = SDL_strlen(user_dir);
    while (n > 1 && (user_dir[n - 1] == '/' || user_dir[n - 1] == '\\')) user_dir[--n] = 0;
    return true;
}

void host_add_game_dir(const char *dir)
{
    if (ngame_dirs < MAX_GAME_DIRS && dir) game_dirs[ngame_dirs++] = SDL_strdup(dir);
}

static bool SDLCALL window_watch(void *data, SDL_Event *ev);

bool host_init(int window_scale)
{
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_GAMEPAD)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return false;
    }
    if (!init_user_dir()) return false;
    if (window_scale < 1) window_scale = 3;
    if (!SDL_CreateWindowAndRenderer("Test Drive II (" TD_VARIANT_NAME ")", 320 * window_scale, 240 * window_scale,
                                     SDL_WINDOW_RESIZABLE, &window, &renderer)) {
        fprintf(stderr, "window/renderer failed: %s\n", SDL_GetError());
        return false;
    }
    SDL_SetRenderVSync(renderer, 1);
    SDL_AddEventWatch(window_watch, NULL);

    audio_be->reset(AUDIO_RATE);
    audio_dump_open();
    SDL_AudioSpec spec = { SDL_AUDIO_S16, 2, AUDIO_RATE };
    audio = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, NULL, NULL);
    if (audio) {
        SDL_ResumeAudioStreamDevice(audio);
        static s16 silence[2 * AUDIO_RATE / 20];           /* 50 ms of lead-in against underruns */
        SDL_PutAudioStreamData(audio, silence, sizeof silence);
    } else {
        fprintf(stderr, "audio unavailable: %s\n", SDL_GetError());
    }

    const char *v = SDL_getenv("TD2_VIRTUAL_CLOCK"), *limit = SDL_getenv("TD2_RUN_SECONDS");
    virtual_clock = v && *v && SDL_strcmp(v, "0") != 0;
    run_limit_ns = limit && SDL_atoi(limit) > 0 ? (Uint64)SDL_atoi(limit) * SDL_NS_PER_SECOND : 0;
    const char *hold = SDL_getenv("TD2_HOLD_SECONDS");
    hold_ns = hold && SDL_atof(hold) > 0 ? (Uint64)(SDL_atof(hold) * SDL_NS_PER_SECOND) : 0;
    key_script_load(SDL_getenv("TD2_KEYS"));
    clock_start_ns = now_ns();
    ticks_run = 0;
    return true;
}

void host_shutdown(void)
{
    if (gamepad) SDL_CloseGamepad(gamepad);
    if (audio) SDL_DestroyAudioStream(audio);
    audio_dump_close();
    if (texture) SDL_DestroyTexture(texture);
    if (renderer) SDL_DestroyRenderer(renderer);
    if (window) SDL_DestroyWindow(window);
    for (int i = 0; i < ngame_dirs; i++) SDL_free(game_dirs[i]);
    ngame_dirs = 0;
    SDL_free(user_dir);
    SDL_free(user_dir_arg);
    user_dir = user_dir_arg = NULL;
    SDL_Quit();
}

void host_set_tick_handler(void (*handler)(void)) { tick_handler = handler; }
void host_set_title_mode(const char *mode)
{
    char title[64];
    SDL_snprintf(title, sizeof title, "Test Drive II (%s)", mode);
    SDL_SetWindowTitle(window, title);
}
void host_set_frame_source(bool (*compose)(u32 *), int w, int h)
{
    frame_source = compose;
    frame_w = SDL_clamp(w, 1, HOST_FRAME_MAX_W);
    frame_h = SDL_clamp(h, 1, HOST_FRAME_MAX_H);
    /* The frame fills a 4:3 area, as the 200-line (or Hercules 348-line) picture did on its monitor. */
    SDL_SetRenderLogicalPresentation(renderer, VIEW_W(frame_w), VIEW_H(frame_w), SDL_LOGICAL_PRESENTATION_LETTERBOX);
    if (texture) SDL_DestroyTexture(texture);
    texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_XRGB8888, SDL_TEXTUREACCESS_STREAMING, frame_w, frame_h);
    /* The window rarely holds a whole number of window pixels per picture pixel (200 lines become 240,
     * Hercules's 348 become 540, then the window's size): nearest sampling then draws some rows one
     * window pixel taller than others, which shows as uneven lines, worst in Hercules's one-pixel
     * dither. Pixel-art sampling keeps the pixels square and blends only the one window pixel where
     * two of them meet, so every row has the same height. */
    if (!SDL_SetTextureScaleMode(texture, SDL_SCALEMODE_PIXELART))
        SDL_SetTextureScaleMode(texture, SDL_SCALEMODE_NEAREST);
}

static Uint64 tick_due_ns(Uint64 n)
{
    return clock_start_ns + n * PIT_DIV_GAME * SDL_NS_PER_SECOND / PIT_HZ;
}

static void audio_for_one_tick(void)
{
    if (!audio && !audio_dump) return;
    samples_per_tick_frac += (double)AUDIO_RATE * PIT_DIV_GAME / PIT_HZ;
    int n = (int)samples_per_tick_frac;
    samples_per_tick_frac -= n;
    s16 buf[2 * 1024];                                     /* stereo frames */
    if (n > (int)SDL_arraysize(buf) / 2) n = SDL_arraysize(buf) / 2;
    audio_be->render(buf, n);
    /* Drop device output if the device is far behind (e.g. after a stall) instead of building latency.
     * The speaker keeps running and the dump still gets every sample. */
    int bytes = n * 2 * (int)sizeof(s16);
    if (audio && SDL_GetAudioStreamQueued(audio) <= AUDIO_RATE / 4 * 2 * (int)sizeof(s16))
        SDL_PutAudioStreamData(audio, buf, bytes);
    if (audio_dump && SDL_WriteIO(audio_dump, buf, (size_t)bytes) == (size_t)bytes) {
        audio_dump_bytes += (Uint32)bytes;
        if (ticks_run % 100 == 0) audio_dump_header();      /* about once a second, in case of a kill */
    }
}

void host_sim_state(const u8 *memory, u32 size, u16 bp, u16 cx)
{
    static const char *dir;
    static bool checked;
    static int calls, n, max = 40, every = 64;
    if (!checked) {
        dir = SDL_getenv("TD2_STATE_DIR");
        const char *m = SDL_getenv("TD2_STATE_MAX"), *e = SDL_getenv("TD2_STATE_EVERY");
        if (m && *m) max = SDL_atoi(m);
        if (e && SDL_atoi(e) > 0) every = SDL_atoi(e);
        checked = true;
    }
    if (!dir || n >= max || calls++ % every != 0) return;
    char path[512];
    SDL_snprintf(path, sizeof path, "%s/state%03d.bin", dir, n++);
    SDL_IOStream *f = SDL_IOFromFile(path, "wb");
    if (!f) { fprintf(stderr, "TD2_STATE_DIR: %s\n", SDL_GetError()); dir = NULL; return; }
    SDL_WriteIO(f, memory, size);
    SDL_WriteU16LE(f, bp);
    SDL_WriteU16LE(f, cx);
    SDL_CloseIO(f);
}

/* Developer aid: with TD2_SNAPSHOT_DIR set, every presented frame at least 2 s (or TD2_SNAPSHOT_MS)
 * after the previous snapshot is saved there as snapNNNN.bmp (works with SDL_VIDEO_DRIVER=dummy).
 * With TD2_SNAPSHOT_HELD set, a frame skipped as too soon is saved as well once it has stayed on the
 * screen that long (held: the host is waiting), so a still screen shown briefly after another (the top
 * scores, a menu) is not lost. */
static void snapshot(bool held)
{
    static const char *dir;
    static bool checked, keep_held, skipped;
    static Uint64 last_ns, every_ns = 2 * SDL_NS_PER_SECOND;
    static int n;
    if (!checked) {
        dir = SDL_getenv("TD2_SNAPSHOT_DIR");
        const char *ms = SDL_getenv("TD2_SNAPSHOT_MS");
        if (ms && SDL_atoi(ms) > 0) every_ns = (Uint64)SDL_atoi(ms) * SDL_NS_PER_MS;
        keep_held = SDL_getenv("TD2_SNAPSHOT_HELD") != NULL;
        checked = true;
    }
    if (!dir || (held && !skipped)) return;
    Uint64 now = now_ns();
    if (n && now - last_ns < every_ns) {
        if (!held) skipped = keep_held;
        return;
    }
    last_ns = now;
    skipped = false;
    SDL_Surface *s = SDL_CreateSurfaceFrom(frame_w, frame_h, SDL_PIXELFORMAT_XRGB8888, frame, frame_w * 4);
    if (!s) return;
    char path[512];
    SDL_snprintf(path, sizeof path, "%s/snap%04d.bmp", dir, n);
    SDL_SaveBMP(s, path);
    if (key_script_n) fprintf(stderr, "snap%04d.bmp at %.2f s\n", n, (double)(tick_due_ns(ticks_run) - clock_start_ns) / SDL_NS_PER_SECOND);
    n++;
    SDL_DestroySurface(s);
}

/* The current frame in the window, letterboxed to the window's size. */
static void show_frame(void)
{
    if (!texture) return;
    SDL_UpdateTexture(texture, NULL, frame, frame_w * 4);
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
    SDL_RenderClear(renderer);
    SDL_FRect dst = { 0, 0, (float)VIEW_W(frame_w), (float)VIEW_H(frame_w) };
    SDL_RenderTexture(renderer, texture, NULL, &dst);
    SDL_RenderPresent(renderer);
}

static void present(void)
{
    snapshot(false);
    show_frame();
}

/* The frame drawn again when the window changes size, goes to or from fullscreen (Alt+Enter) or is
 * uncovered, also while the game draws nothing new (a menu waiting for a key). An event watch sees
 * these events at once, also during Windows' live resize, which runs its own message loop until the
 * mouse button is released. */
static bool SDLCALL window_watch(void *data, SDL_Event *ev)
{
    (void)data;
    switch (ev->type) {
    case SDL_EVENT_WINDOW_EXPOSED:
    case SDL_EVENT_WINDOW_RESIZED:
    case SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED:
    case SDL_EVENT_WINDOW_ENTER_FULLSCREEN:
    case SDL_EVENT_WINDOW_LEAVE_FULLSCREEN:
    case SDL_EVENT_WINDOW_RESTORED:
    case SDL_EVENT_WINDOW_MAXIMIZED:
        show_frame();
        break;
    default:
        break;
    }
    return true;
}

static Uint64 last_present_ns;

void host_present_now(void)
{
    if (frame_source && frame_source(frame)) {
        present();
        last_present_ns = now_ns();
    }
}

void host_pump(void)
{
    process_events();

    bool worked = false;
    Uint64 now = now_ns();
    int budget = 50;                                /* at most 0.5 s of catch-up per call */
    while (tick_due_ns(ticks_run + 1) <= now && budget-- > 0) {
        ticks_run++;
        if (tick_handler) tick_handler();
        audio_for_one_tick();
        worked = true;
    }
    if (budget < 0) {                               /* fell too far behind: resynchronise the clock */
        clock_start_ns = now - (tick_due_ns(ticks_run) - clock_start_ns);
    }
    key_script_run(tick_due_ns(ticks_run) - clock_start_ns);
    if (run_limit_ns && tick_due_ns(ticks_run) - clock_start_ns >= run_limit_ns) {
        host_shutdown();
        exit(0);
    }
    if (hold_ns && tick_due_ns(ticks_run) - clock_start_ns >= hold_ns) {
        if (frame_source && frame_source(frame)) show_frame();
        fprintf(stderr, "holding at %.2f s\n", (double)(tick_due_ns(ticks_run) - clock_start_ns) / SDL_NS_PER_SECOND);
        fflush(stderr);
        for (;;) {                                  /* the window watch redraws it; quitting exits */
            process_events();
            SDL_Delay(15);
        }
    }

    /* Present at most once per ~8 ms; VSync paces it further. */
    if (frame_source && now - last_present_ns >= 8 * SDL_NS_PER_MS) {
        if (frame_source(frame)) {
            present();
            last_present_ns = now_ns();
            worked = true;
        }
    }
    if (!worked) {
        snapshot(true);
        Uint64 next = tick_due_ns(ticks_run + 1);
        now = now_ns();
        if (next > now) wait_ns(SDL_min(next - now, SDL_NS_PER_MS));
    }
}

static int frame_rate = HOST_DEFAULT_FPS;
static Uint64 next_frame_ns;

/* ---------------------------------------------------------------- the app UI's window services */

static Uint64 pause_start_ns;

void *host_native_window(void)
{
#ifdef _WIN32
    return SDL_GetPointerProperty(SDL_GetWindowProperties(window), SDL_PROP_WINDOW_WIN32_HWND_POINTER, NULL);
#else
    return NULL;
#endif
}

void host_pause_begin(void)
{
    pause_start_ns = now_ns();
    if (audio) SDL_PauseAudioStreamDevice(audio);
}

/* The clock moves on by the time the pause took, so no ticks are owed for it. */
void host_pause_end(void)
{
    Uint64 paused = now_ns() - pause_start_ns;
    clock_start_ns += paused;
    if (next_frame_ns) next_frame_ns += paused;
    if (audio) SDL_ResumeAudioStreamDevice(audio);
}

int host_window_scale(void)
{
    int w = 0, h = 0;
    SDL_GetWindowSize(window, &w, &h);
    return (w + 160) / 320;
}

void host_set_window_scale(int scale)
{
    if (host_fullscreen()) SDL_SetWindowFullscreen(window, false);
    SDL_SetWindowSize(window, 320 * scale, 240 * scale);
}

bool host_fullscreen(void) { return (SDL_GetWindowFlags(window) & SDL_WINDOW_FULLSCREEN) != 0; }
void host_set_fullscreen(bool on) { SDL_SetWindowFullscreen(window, on); }

_Noreturn void host_quit(void)
{
    host_shutdown();
    exit(0);
}

void host_set_frame_rate(int fps) { frame_rate = fps < 0 ? 0 : fps; }
int  host_frame_rate(void) { return frame_rate; }

void host_frame_begin(void)
{
    host_pump();
    if (frame_rate <= 0) return;
    Uint64 period = SDL_NS_PER_SECOND / (Uint64)frame_rate;
    Uint64 now = now_ns();
    if (next_frame_ns == 0 || now > next_frame_ns + period) next_frame_ns = now;   /* resync after stalls */
    while (now_ns() < next_frame_ns) host_pump();
    next_frame_ns += period;
}

/* ---------------------------------------------------------------- keyboard */

static void kbd_push(u16 key)
{
    int next = (kbd_tail + 1) % KBD_SIZE;
    if (next == kbd_head) return;                   /* buffer full: BIOS beeps and drops the key */
    kbd_buf[kbd_tail] = key;
    kbd_tail = next;
}

bool host_kbd_peek(u16 *key)
{
    process_events();
    if (kbd_head == kbd_tail) return false;
    if (key) *key = kbd_buf[kbd_head];
    return true;
}

bool host_kbd_read(u16 *key)
{
    process_events();
    if (kbd_head == kbd_tail) return false;
    if (key) *key = kbd_buf[kbd_head];
    kbd_head = (kbd_head + 1) % KBD_SIZE;
    return true;
}

void host_kbd_flush(void)
{
    process_events();
    kbd_head = kbd_tail = 0;
}

u8 host_kbd_shift_flags(void)
{
    SDL_Keymod m = SDL_GetModState();
    u8 f = 0;
    if (m & SDL_KMOD_RSHIFT) f |= 0x01;
    if (m & SDL_KMOD_LSHIFT) f |= 0x02;
    if (m & SDL_KMOD_CTRL)   f |= 0x04;
    if (m & SDL_KMOD_ALT)    f |= 0x08;
    if (m & SDL_KMOD_NUM)    f |= 0x20;
    if (m & SDL_KMOD_CAPS)   f |= 0x40;
    return f;
}

static bool held_keys = true;

void host_set_held_keys(bool on) { held_keys = on; }
bool host_held_keys(void) { return held_keys; }

bool host_xt_key_down(u8 xt)
{
    const bool *ks = SDL_GetKeyboardState(NULL);
    /* Keypad digits are cursor keys only with Num Lock off; with it on they type digits, which the
     * game maps to fire + direction through the key buffer. */
    bool num = (SDL_GetModState() & SDL_KMOD_NUM) != 0;
#define KP(sc) (!num && ks[sc])
    switch (xt) {
    case 0x1E: return ks[SDL_SCANCODE_A];
    case 0x2C: return ks[SDL_SCANCODE_Z];
    case 0x47: return ks[SDL_SCANCODE_HOME]     || KP(SDL_SCANCODE_KP_7);
    case 0x48: return ks[SDL_SCANCODE_UP]       || KP(SDL_SCANCODE_KP_8);
    case 0x49: return ks[SDL_SCANCODE_PAGEUP]   || KP(SDL_SCANCODE_KP_9);
    case 0x4B: return ks[SDL_SCANCODE_LEFT]     || KP(SDL_SCANCODE_KP_4);
    case 0x4D: return ks[SDL_SCANCODE_RIGHT]    || KP(SDL_SCANCODE_KP_6);
    case 0x4F: return ks[SDL_SCANCODE_END]      || KP(SDL_SCANCODE_KP_1);
    case 0x50: return ks[SDL_SCANCODE_DOWN]     || KP(SDL_SCANCODE_KP_2);
    case 0x51: return ks[SDL_SCANCODE_PAGEDOWN] || KP(SDL_SCANCODE_KP_3);
#undef KP
    default:   return false;
    }
}

/* XT scan codes (set 1) and ASCII for a US keyboard, as INT 16h AH=00h reports them. */
static u16 bios_key(SDL_Keycode k, SDL_Scancode sc, SDL_Keymod mod)
{
    bool shift = (mod & SDL_KMOD_SHIFT) != 0, ctrl = (mod & SDL_KMOD_CTRL) != 0, alt = (mod & SDL_KMOD_ALT) != 0;
    bool caps = (mod & SDL_KMOD_CAPS) != 0, num = (mod & SDL_KMOD_NUM) != 0;
    static const u8 letter_scan[26] = { 0x1E,0x30,0x2E,0x20,0x12,0x21,0x22,0x23,0x17,0x24,0x25,0x26,0x32,
                                        0x31,0x18,0x19,0x10,0x13,0x1F,0x14,0x16,0x2F,0x11,0x2D,0x15,0x2C };
    if (k >= SDLK_A && k <= SDLK_Z) {
        int i = (int)(k - SDLK_A);
        u8 scan = letter_scan[i];
        if (alt) return (u16)(scan << 8);
        if (ctrl) return (u16)(scan << 8 | (i + 1));
        bool upper = shift != caps;
        return (u16)(scan << 8 | ((upper ? 'A' : 'a') + i));
    }
    static const char digits_shift[] = ")!@#$%^&*(";
    if (k >= SDLK_0 && k <= SDLK_9) {
        int d = (int)(k - SDLK_0);
        u8 scan = d == 0 ? 0x0B : (u8)(0x01 + d);
        if (alt) return (u16)((0x78 + (d == 0 ? 9 : d - 1)) << 8);
        return (u16)(scan << 8 | (u8)(shift ? digits_shift[d] : '0' + d));
    }
    /* Numeric keypad: digits with Num Lock, cursor keys without. */
    struct { SDL_Keycode kc; u8 scan; char digit; } kp[] = {
        { SDLK_KP_7, 0x47, '7' }, { SDLK_KP_8, 0x48, '8' }, { SDLK_KP_9, 0x49, '9' },
        { SDLK_KP_4, 0x4B, '4' }, { SDLK_KP_5, 0x4C, '5' }, { SDLK_KP_6, 0x4D, '6' },
        { SDLK_KP_1, 0x4F, '1' }, { SDLK_KP_2, 0x50, '2' }, { SDLK_KP_3, 0x51, '3' },
        { SDLK_KP_0, 0x52, '0' }, { SDLK_KP_PERIOD, 0x53, '.' },
    };
    for (size_t i = 0; i < SDL_arraysize(kp); i++)
        if (k == kp[i].kc) return (u16)(kp[i].scan << 8 | ((num != shift) ? (u8)kp[i].digit : (kp[i].scan == 0x4C ? 0 : 0)));
    switch (k) {
    case SDLK_ESCAPE:    return 0x011B;
    case SDLK_RETURN:
    case SDLK_KP_ENTER:  return ctrl ? 0x1C0A : 0x1C0D;
    case SDLK_BACKSPACE: return ctrl ? 0x0E7F : 0x0E08;
    case SDLK_TAB:       return shift ? 0x0F00 : 0x0F09;
    case SDLK_SPACE:     return 0x3920;
    case SDLK_UP:        return 0x4800;
    case SDLK_DOWN:      return 0x5000;
    case SDLK_LEFT:      return 0x4B00;
    case SDLK_RIGHT:     return 0x4D00;
    case SDLK_HOME:      return 0x4700;
    case SDLK_END:       return 0x4F00;
    case SDLK_PAGEUP:    return 0x4900;
    case SDLK_PAGEDOWN:  return 0x5100;
    case SDLK_INSERT:    return 0x5200;
    case SDLK_DELETE:    return 0x5300;
    case SDLK_MINUS:     return shift ? 0x0C5F : 0x0C2D;
    case SDLK_EQUALS:    return shift ? 0x0D2B : 0x0D3D;
    case SDLK_LEFTBRACKET:  return shift ? 0x1A7B : 0x1A5B;
    case SDLK_RIGHTBRACKET: return shift ? 0x1B7D : 0x1B5D;
    case SDLK_SEMICOLON: return shift ? 0x273A : 0x273B;
    case SDLK_APOSTROPHE:return shift ? 0x2822 : 0x2827;
    case SDLK_GRAVE:     return shift ? 0x297E : 0x2960;
    case SDLK_BACKSLASH: return shift ? 0x2B7C : 0x2B5C;
    case SDLK_COMMA:     return shift ? 0x333C : 0x332C;
    case SDLK_PERIOD:    return shift ? 0x343E : 0x342E;
    case SDLK_SLASH:     return shift ? 0x353F : 0x352F;
    case SDLK_KP_MINUS:  return 0x4A2D;
    case SDLK_KP_PLUS:   return 0x4E2B;
    case SDLK_KP_MULTIPLY: return 0x372A;
    default: break;
    }
    if (k >= SDLK_F1 && k <= SDLK_F10) return (u16)((0x3B + (k - SDLK_F1)) << 8);
    (void)sc;
    return 0;
}

static void (*scan_handler)(u8);

void host_set_scan_handler(void (*handler)(u8)) { scan_handler = handler; }

/* XT set-1 make code of an SDL key (port/spec/platform.md section 6); 0 = not reported. */
static u8 xt_scan(SDL_Scancode sc)
{
    if (sc >= SDL_SCANCODE_A && sc <= SDL_SCANCODE_Z) {
        static const u8 letter_scan[26] = { 0x1E,0x30,0x2E,0x20,0x12,0x21,0x22,0x23,0x17,0x24,0x25,0x26,0x32,
                                            0x31,0x18,0x19,0x10,0x13,0x1F,0x14,0x16,0x2F,0x11,0x2D,0x15,0x2C };
        return letter_scan[sc - SDL_SCANCODE_A];
    }
    if (sc >= SDL_SCANCODE_1 && sc <= SDL_SCANCODE_0) return (u8)(0x02 + (sc - SDL_SCANCODE_1));
    if (sc >= SDL_SCANCODE_F1 && sc <= SDL_SCANCODE_F10) return (u8)(0x3B + (sc - SDL_SCANCODE_F1));
    switch (sc) {
    case SDL_SCANCODE_ESCAPE:       return 0x01;
    case SDL_SCANCODE_MINUS:        return 0x0C;
    case SDL_SCANCODE_EQUALS:       return 0x0D;
    case SDL_SCANCODE_BACKSPACE:    return 0x0E;
    case SDL_SCANCODE_TAB:          return 0x0F;
    case SDL_SCANCODE_LEFTBRACKET:  return 0x1A;
    case SDL_SCANCODE_RIGHTBRACKET: return 0x1B;
    case SDL_SCANCODE_RETURN:
    case SDL_SCANCODE_KP_ENTER:     return 0x1C;
    case SDL_SCANCODE_LCTRL:
    case SDL_SCANCODE_RCTRL:        return 0x1D;
    case SDL_SCANCODE_SEMICOLON:    return 0x27;
    case SDL_SCANCODE_APOSTROPHE:   return 0x28;
    case SDL_SCANCODE_GRAVE:        return 0x29;
    case SDL_SCANCODE_LSHIFT:       return 0x2A;
    case SDL_SCANCODE_BACKSLASH:    return 0x2B;
    case SDL_SCANCODE_COMMA:        return 0x33;
    case SDL_SCANCODE_PERIOD:       return 0x34;
    case SDL_SCANCODE_SLASH:
    case SDL_SCANCODE_KP_DIVIDE:    return 0x35;
    case SDL_SCANCODE_RSHIFT:       return 0x36;
    case SDL_SCANCODE_KP_MULTIPLY:  return 0x37;
    case SDL_SCANCODE_LALT:
    case SDL_SCANCODE_RALT:         return 0x38;
    case SDL_SCANCODE_SPACE:        return 0x39;
    case SDL_SCANCODE_CAPSLOCK:     return 0x3A;
    case SDL_SCANCODE_NUMLOCKCLEAR: return 0x45;
    case SDL_SCANCODE_SCROLLLOCK:   return 0x46;
    case SDL_SCANCODE_HOME:
    case SDL_SCANCODE_KP_7:         return 0x47;
    case SDL_SCANCODE_UP:
    case SDL_SCANCODE_KP_8:         return 0x48;
    case SDL_SCANCODE_PAGEUP:
    case SDL_SCANCODE_KP_9:         return 0x49;
    case SDL_SCANCODE_KP_MINUS:     return 0x4A;
    case SDL_SCANCODE_LEFT:
    case SDL_SCANCODE_KP_4:         return 0x4B;
    case SDL_SCANCODE_KP_5:         return 0x4C;
    case SDL_SCANCODE_RIGHT:
    case SDL_SCANCODE_KP_6:         return 0x4D;
    case SDL_SCANCODE_KP_PLUS:      return 0x4E;
    case SDL_SCANCODE_END:
    case SDL_SCANCODE_KP_1:         return 0x4F;
    case SDL_SCANCODE_DOWN:
    case SDL_SCANCODE_KP_2:         return 0x50;
    case SDL_SCANCODE_PAGEDOWN:
    case SDL_SCANCODE_KP_3:         return 0x51;
    case SDL_SCANCODE_INSERT:
    case SDL_SCANCODE_KP_0:         return 0x52;
    case SDL_SCANCODE_DELETE:
    case SDL_SCANCODE_KP_PERIOD:    return 0x53;
    default:                        return 0;
    }
}

static void (*command_handler)(HostCommand cmd);
static bool swallowed[SDL_SCANCODE_COUNT];   /* app combinations whose release the game must not see */

void host_set_command_handler(void (*handler)(HostCommand cmd)) { command_handler = handler; }

/* The app's own key combinations (host.h). Returns true when the key belongs to the app. */
static bool app_combination(SDL_Keycode key, SDL_Keymod mod, bool repeat)
{
    if (!(mod & SDL_KMOD_CTRL) || !(mod & SDL_KMOD_SHIFT) || (mod & (SDL_KMOD_ALT | SDL_KMOD_GUI))) return false;
    HostCommand cmd;
    switch (key) {
    case SDLK_G: cmd = HOST_CMD_NEXT_GRAPHICS; break;
    case SDLK_S: cmd = HOST_CMD_NEXT_SOUND; break;
    case SDLK_M: cmd = HOST_CMD_MENU; break;
    default: return false;
    }
    if (!repeat && command_handler) command_handler(cmd);
    return true;
}

static void key_down(SDL_Keycode key, SDL_Scancode sc, SDL_Keymod mod)
{
    u16 bios = bios_key(key, sc, mod);
    if (bios) kbd_push(bios);
    u8 xt = xt_scan(sc);
    if (xt && scan_handler) scan_handler(xt);
}

static void key_up(SDL_Scancode sc)
{
    u8 xt = xt_scan(sc);
    if (xt && scan_handler) scan_handler((u8)(xt | 0x80));
}

static void key_script_load(const char *text)
{
    key_script_n = 0;
    if (!text) return;
    char item[48];
    while (*text && key_script_n < KEY_SCRIPT_MAX) {
        size_t n = strcspn(text, ",");
        SDL_snprintf(item, sizeof item, "%.*s", (int)SDL_min(n, sizeof item - 1), text);
        text += n + (text[n] == ',');
        char *colon = SDL_strchr(item, ':'), *slash = SDL_strchr(item, '/');
        double hold = 0.1;
        if (slash) { *slash = 0; hold = SDL_atof(slash + 1); }
        SDL_Keymod mod = SDL_KMOD_NONE;
        char *name = colon ? colon + 1 : NULL;
        for (char *plus; name && (plus = SDL_strchr(name, '+')) != NULL; name = plus + 1) {
            *plus = 0;
            if (SDL_strcasecmp(name, "Ctrl") == 0) mod |= SDL_KMOD_LCTRL;
            else if (SDL_strcasecmp(name, "Shift") == 0) mod |= SDL_KMOD_LSHIFT;
            else if (SDL_strcasecmp(name, "Alt") == 0) mod |= SDL_KMOD_LALT;
        }
        SDL_Scancode sc = name ? SDL_GetScancodeFromName(name) : SDL_SCANCODE_UNKNOWN;
        if (sc == SDL_SCANCODE_UNKNOWN) {
            fprintf(stderr, "TD2_KEYS: ignoring \"%s\"\n", item);
            continue;
        }
        key_script[key_script_n].at_ns = (Uint64)(SDL_atof(item) * SDL_NS_PER_SECOND);
        key_script[key_script_n].hold_ns = (Uint64)(hold * SDL_NS_PER_SECOND);
        key_script[key_script_n].sc = sc;
        key_script[key_script_n].mod = mod;
        key_script[key_script_n].state = 0;
        key_script_n++;
    }
}

static void key_script_run(Uint64 game_ns)
{
    for (int i = 0; i < key_script_n; i++) {
        if (key_script[i].state == 0 && game_ns >= key_script[i].at_ns) {
            SDL_Keycode key = SDL_GetKeyFromScancode(key_script[i].sc, SDL_KMOD_NONE, false);
            if (app_combination(key, key_script[i].mod, false)) key_script[i].state = 3;   /* never released */
            else {
                key_down(key, key_script[i].sc, key_script[i].mod);
                key_script[i].state = 1;
            }
            fprintf(stderr, "TD2_KEYS: %.2f s %s\n", (double)game_ns / SDL_NS_PER_SECOND,
                    SDL_GetScancodeName(key_script[i].sc));
        } else if (key_script[i].state == 1 && game_ns >= key_script[i].at_ns + key_script[i].hold_ns) {
            key_up(key_script[i].sc);
            key_script[i].state = 2;
        }
    }
}

static void process_events(void)
{
    SDL_Event ev;
    while (SDL_PollEvent(&ev)) {
        switch (ev.type) {
        case SDL_EVENT_QUIT:
            host_quit();
        case SDL_EVENT_MOUSE_BUTTON_UP:
            if (ev.button.button == SDL_BUTTON_RIGHT && command_handler) command_handler(HOST_CMD_MENU);
            break;
        case SDL_EVENT_KEY_DOWN: {
            /* Alt+Enter toggles fullscreen and the app combinations go to the app; everything else goes to
             * the BIOS buffer, repeats included. */
            if (ev.key.key == SDLK_RETURN && (ev.key.mod & SDL_KMOD_ALT)) {
                if (!ev.key.repeat)
                    SDL_SetWindowFullscreen(window, !(SDL_GetWindowFlags(window) & SDL_WINDOW_FULLSCREEN));
                break;
            }
            if (app_combination(ev.key.key, ev.key.mod, ev.key.repeat)) {
                swallowed[ev.key.scancode] = true;
                break;
            }
            key_down(ev.key.key, ev.key.scancode, ev.key.mod);
            break;
        }
        case SDL_EVENT_KEY_UP:
            if (swallowed[ev.key.scancode]) swallowed[ev.key.scancode] = false;
            else key_up(ev.key.scancode);
            break;
        case SDL_EVENT_GAMEPAD_ADDED:
            if (!gamepad) gamepad = SDL_OpenGamepad(ev.gdevice.which);
            break;
        case SDL_EVENT_GAMEPAD_REMOVED:
            if (gamepad && SDL_GetGamepadID(gamepad) == ev.gdevice.which) {
                SDL_CloseGamepad(gamepad);
                gamepad = NULL;
            }
            break;
        default:
            break;
        }
    }
}

bool host_joy_read(s16 *x, s16 *y, u8 *buttons)
{
    if (!gamepad) return false;
    s16 ax = SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_LEFTX);
    s16 ay = SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_LEFTY);
    if (SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_LEFT))  ax = -32768;
    if (SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_RIGHT)) ax = 32767;
    if (SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_UP))    ay = -32768;
    if (SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_DPAD_DOWN))  ay = 32767;
    u8 b = 0;
    if (SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_SOUTH)) b |= 1;
    if (SDL_GetGamepadButton(gamepad, SDL_GAMEPAD_BUTTON_EAST))  b |= 2;
    if (x) *x = ax;
    if (y) *y = ay;
    if (buttons) *buttons = b;
    return true;
}

/* ---------------------------------------------------------------- speaker, files, errors */

/* What a backend switch hands over: the speaker's state and what the game plays. */
static struct {
    u16 divisor;
    u8 port61;
    int song;                                       /* the last song started, 0 during a race */
    Uint64 song_tick;                               /* when it started (ticks_run) */
    bool race;
    char car[8];
} sound_now;

void host_set_audio_backend(const AudioBackend *b)
{
    audio_be = b;
    if (!renderer) return;                          /* before host_init, which resets it */
    b->reset(AUDIO_RATE);
    b->speaker(sound_now.divisor, sound_now.port61);
    if (!b->event) return;
    if (sound_now.race) b->event(SOUND_RACE_START, 0, sound_now.car);
    else if (sound_now.song && b->song_at) b->song_at(sound_now.song, (u32)((ticks_run - sound_now.song_tick) * 10));
    else if (sound_now.song) b->event(SOUND_SONG, sound_now.song, NULL);
}

const AudioBackend *host_audio_backend(void) { return audio_be; }
bool host_amiga_pace(void) { return audio_be->amiga_pace; }
bool host_sound_busy(void) { return audio_be->busy && audio_be->busy(); }

void host_speaker(u16 divisor, u8 port61_bits)
{
    sound_now.divisor = divisor;
    sound_now.port61 = port61_bits;
    audio_be->speaker(divisor, port61_bits);
}

void host_sound_event(SoundEvent e, int n, const char *car)
{
    switch (e) {
    case SOUND_SONG:
        sound_now.song = n;
        sound_now.song_tick = ticks_run;
        sound_now.race = false;
        break;
    case SOUND_RACE_START:
        sound_now.song = 0;
        sound_now.race = true;
        SDL_strlcpy(sound_now.car, car ? car : "", sizeof sound_now.car);
        break;
    case SOUND_RACE_END: sound_now.race = false; break;
    default: break;
    }
    if (audio_be->event) audio_be->event(e, n, car);
}

void host_sound_drive(const DriveSound *d)
{
    if (audio_be->drive) audio_be->drive(d);
}

/* Case-insensitive lookup of name inside dir; NULL if it does not exist. */
static char *find_in_dir(const char *dir, const char *name)
{
    char *direct = NULL;
    SDL_asprintf(&direct, "%s/%s", dir, name);
    if (SDL_GetPathInfo(direct, NULL)) return direct;
    SDL_free(direct);

    int count = 0;
    char **entries = SDL_GlobDirectory(dir, NULL, 0, &count);
    char *found = NULL;
    for (int i = 0; entries && i < count; i++) {
        if (SDL_strcasecmp(entries[i], name) == 0) {
            SDL_asprintf(&found, "%s/%s", dir, entries[i]);
            break;
        }
    }
    SDL_free(entries);
    return found;
}

/* Files in the profile folder shadow the game folders, which are searched in order. Writes always go
 * to the profile folder, so the game folders are only read. */
char *host_game_path(const char *name, bool create)
{
    if (!name || !*name || SDL_strchr(name, '/') || SDL_strchr(name, '\\') || SDL_strchr(name, ':')) return NULL;
    char *path = user_dir ? find_in_dir(user_dir, name) : NULL;
    if (path) return path;
    if (create) {
        SDL_asprintf(&path, "%s/%s", user_dir, name);
        return path;
    }
    for (int i = 0; i < ngame_dirs && !path; i++) path = find_in_dir(game_dirs[i], name);
    return path;
}

void host_free(void *p)
{
    SDL_free(p);
}

_Noreturn void host_fatal(const char *fmt, ...)
{
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    fprintf(stderr, "fatal: %s\n", msg);
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Test Drive II", msg, window);
    host_shutdown();
    exit(3);
}
