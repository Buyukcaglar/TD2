/* Host stand-in for the differential-test DLL: no window, no audio, no input, no files.
 * host_fatal returns to the adapter that is running (longjmp) instead of exiting the process. */
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "host.h"
#include "dh.h"

jmp_buf *dh_fatal_jmp;
char dh_fatal_msg[256];

bool host_init(const char *game_dir, int window_scale) { (void)game_dir; (void)window_scale; return true; }
void host_shutdown(void) {}
void host_set_tick_handler(void (*handler)(void)) { (void)handler; }
void host_set_frame_source(bool (*compose)(u32 *), int w, int h) { (void)compose; (void)w; (void)h; }
void host_set_title_mode(const char *mode) { (void)mode; }
void host_pump(void) {}
void host_set_frame_rate(int fps) { (void)fps; }
int  host_frame_rate(void) { return 0; }
void host_frame_begin(void) {}
void host_present_now(void) {}
void host_set_scan_handler(void (*handler)(u8)) { (void)handler; }
bool host_kbd_peek(u16 *key) { (void)key; return false; }
bool host_kbd_read(u16 *key) { (void)key; return false; }
void host_kbd_flush(void) {}
u8   host_kbd_shift_flags(void) { return 0; }
void host_set_held_keys(bool on) { (void)on; }
bool host_held_keys(void) { return false; }
bool host_xt_key_down(u8 xt_scan) { (void)xt_scan; return false; }
bool host_joy_read(s16 *x, s16 *y, u8 *buttons) { *x = *y = 0; *buttons = 0; return false; }
void host_speaker(u16 divisor, u8 port61_bits) { (void)divisor; (void)port61_bits; }
void host_sim_state(const u8 *memory, u32 size, u16 bp, u16 cx) { (void)memory; (void)size; (void)bp; (void)cx; }
void host_set_user_dir(const char *dir) { (void)dir; }
char *host_game_path(const char *name, bool create) { (void)name; (void)create; return NULL; }
void host_free(void *p) { free(p); }

_Noreturn void host_fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dh_fatal_msg, sizeof dh_fatal_msg, fmt, ap);
    va_end(ap);
    if (dh_fatal_jmp) longjmp(*dh_fatal_jmp, 1);
    fprintf(stderr, "fatal outside a test call: %s\n", dh_fatal_msg);
    abort();
}
