#include "td2ega_timer_control.h"
#include <stddef.h>

static int start(td2ega_timer_control_state *state, td2ega_timer_control_result *result)
{
    if (result == NULL) return 0;
    *result = (td2ega_timer_control_result){0};
    if (state == NULL) {
        result->status = 2;
        return 0;
    }
    return 1;
}

static void event(td2ega_timer_control_result *result, uint16_t kind,
                    uint16_t port, uint16_t value)
{
    td2ega_timer_event *next = &result->events[result->event_count++];
    next->kind = kind;
    next->port = port;
    next->value = value;
}

static uint8_t read_pic(td2ega_timer_control_state *state, td2ega_timer_control_result *result)
{
    event(result, 1, 0x21, state->pic_mask);
    return state->pic_mask;
}

static void write_pic(td2ega_timer_control_state *state, td2ega_timer_control_result *result, uint8_t value)
{
    state->pic_mask = value;
    event(result, 2, 0x21, value);
}

static void disable_speaker(td2ega_timer_control_state *state, td2ega_timer_control_result *result)
{
    event(result, 1, 0x61, state->speaker_control);
    state->speaker_control &= 0xfc;
    event(result, 2, 0x61, state->speaker_control);
}

static void install(td2ega_timer_control_state *state, uint16_t divisor,
                      td2ega_timer_control_result *result)
{
    unsigned i;
    uint8_t mask;
    result->divisor = divisor;
    event(result, 0, 0, 0);
    state->callbacks.word[0] = 0;
    state->callbacks.word[1] = 0;
    event(result, 0, 0, 1);
    disable_speaker(state, result);
    state->control_43 = 0xb6;
    event(result, 2, 0x43, 0xb6);
    mask = read_pic(state, result);
    write_pic(state, result, (uint8_t)(mask | 3u));
    state->histogram_index = 0;
    for (i = 0; i < 40; i++) state->histogram[i] = 0;
    event(result, 0, 0, 0);
    if (state->vector_offset != 0x61bf) state->saved_offset = state->vector_offset;
    /* Original offset and segment ownership tests are separate. Same-CS with
     * a different offset skips installation; never repair that implicitly. */
    if (state->vector_segment != state->current_cs) {
        state->saved_segment = state->vector_segment;
        state->vector_offset = 0x61bf;
        state->vector_segment = state->current_cs;
    }
    mask = read_pic(state, result);
    write_pic(state, result, (uint8_t)(mask & 0xfcu));
    event(result, 0, 0, 1);
    event(result, 2, 0x40, (uint8_t)divisor);
    event(result, 2, 0x40, (uint8_t)(divisor >> 8));
    result->enables_interrupts = 1;
}

void td2ega_timer_install_divisor(td2ega_timer_control_state *state,
    uint16_t divisor, td2ega_timer_control_result *result)
{
    int32_t denominator, quotient;
    if (!start(state, result)) return;
    denominator = divisor < 32768 ? (int32_t)divisor : (int32_t)divisor - 65536;
    if (denominator == 0) {
        result->status = 1;
        return;
    }
    quotient = 65536 / denominator;
    if (quotient < -32768 || quotient > 32767) {
        result->status = 1;
        return;
    }
    state->reload = (uint16_t)quotient;
    state->remaining = state->reload;
    state->field_5e94 = 0;
    state->field_5e95 = 1;
    install(state, divisor, result);
}

void td2ega_timer_install_fixed(td2ega_timer_control_state *state,
    td2ega_timer_control_result *result)
{
    if (!start(state, result)) return;
    state->reload = 5;
    state->remaining = 5;
    state->relay_remaining = 0x64;
    state->field_5e94 = 1;
    /* This entry does not assign5E95. */
    install(state, 0x2e9c, result);
}

void td2ega_timer_cleanup(td2ega_timer_control_state *state,
    td2ega_timer_control_result *result)
{
    uint8_t mask;
    if (!start(state, result)) return;
    if (state->vector_segment != state->current_cs || state->vector_offset != 0x61bf)
        return;
    mask = read_pic(state, result);
    write_pic(state, result, (uint8_t)(mask | 3u));
    event(result, 0, 0, 0);
    state->vector_offset = state->saved_offset;
    state->vector_segment = state->saved_segment;
    mask = read_pic(state, result);
    write_pic(state, result, (uint8_t)(mask & 0xfcu));
    event(result, 0, 0, 1);
    event(result, 2, 0x40, 0);
    event(result, 2, 0x40, 0);
    disable_speaker(state, result);
    result->enables_interrupts = 1;
}
