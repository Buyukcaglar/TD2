#ifndef TD2EGA_TIMER_CONTROL_H
#define TD2EGA_TIMER_CONTROL_H
#include <stdint.h>
#include "td2ega_timer_callbacks.h"

typedef struct td2ega_timer_control_state {
    uint16_t current_cs, vector_offset, vector_segment, saved_offset, saved_segment;
    uint16_t reload, remaining, relay_remaining, histogram_index;
    uint16_t histogram[40];
    td2ega_callback_words callbacks;
    uint8_t field_5e94, field_5e95, pic_mask, speaker_control, control_43;
} td2ega_timer_control_state;
typedef struct td2ega_timer_event {
    uint16_t kind; /* 0 IF effect, 1 port read, 2 port write */
    uint16_t port, value;
} td2ega_timer_event;
typedef struct td2ega_timer_control_result {
    uint16_t status; /* 0 normal, 1 original divide-fault prefix, 2 native diagnostic */
    uint16_t enables_interrupts, divisor, event_count;
    td2ega_timer_event events[32];
} td2ega_timer_control_result;

/* Serialized snapshot/effect contract. Events name original byte port values,
 * not elapsed time or a frequency. No actual hardware I/O occurs here. */
void td2ega_timer_install_divisor(td2ega_timer_control_state *state,
    uint16_t divisor, td2ega_timer_control_result *result);
void td2ega_timer_install_fixed(td2ega_timer_control_state *state,
    td2ega_timer_control_result *result);
void td2ega_timer_cleanup(td2ega_timer_control_state *state,
    td2ega_timer_control_result *result);
#endif
