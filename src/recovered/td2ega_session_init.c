#include "td2ega_session_init.h"
#include "td2ega_sim_primitives.h"
#include <stddef.h>

static uint16_t word(const uint8_t *group, uint16_t offset)
{
    return (uint16_t)((uint16_t)group[offset] | ((uint16_t)group[(uint32_t)offset + 1] << 8));
}

static void store(uint8_t *group, uint16_t offset, uint16_t value)
{
    group[offset] = (uint8_t)value;
    group[(uint32_t)offset + 1] = (uint8_t)(value >> 8);
}

void td2ega_zero_simulation_state(uint8_t *group)
{
    static const uint16_t zero_words[] = {0x52ce,0x332c,0x332a,0x33bf,0x33c1,
        0x33c3,0x33c8,0x33cc};
    static const uint16_t zero_bytes[] = {0x3365,0x3367,0x336b,0x33b2,0x337b,
        0x33b3,0x33c5,0x33c6,0x5490,0x33d4};
    unsigned i;
    for (i = 0; i < sizeof zero_words / sizeof zero_words[0]; i++) store(group, zero_words[i], 0);
    for (i = 0; i < sizeof zero_bytes / sizeof zero_bytes[0]; i++) group[zero_bytes[i]] = 0;
    store(group, 0x33ca, 0xfa);
    td2ega_clear_transition(group);
}

void td2ega_reset_view_state(uint8_t *group)
{
    group[0x2f56] = 0;
    store(group, 0x2f46, 0);
    store(group, 0x2f48, 0);
    store(group, 0x2f4a, 0);
    group[0x2f57] = 1;
    group[0x2f5a] = 1;
    group[0x2f5b] = 1;
    group[0x2f5c] = 1;
    group[0x2f59] = 0x0a;
    store(group, 0x2f4c, word(group, 0x23c6));
    store(group, 0x2f4e, word(group, 0x23c8));
}

void td2ega_reset_session_state(uint8_t *group)
{
    td2ega_zero_simulation_state(group);
    store(group, 0x52cc, 0xa0);
    store(group, 0x5fd8, 0xffff);
    store(group, 0x5fda, 0xffff);
    store(group, 0x5fdc, 0xffff);
    td2ega_reset_view_state(group);
}

static void import_timer(const uint8_t *group, td2ega_timer_control_state *device)
{
    unsigned i;
    device->saved_offset = word(group, 0x5e88);
    device->saved_segment = word(group, 0x5e8a);
    device->field_5e94 = group[0x5e94];
    device->field_5e95 = group[0x5e95];
    device->relay_remaining = word(group, 0x5e96);
    device->reload = word(group, 0x5e98);
    device->remaining = word(group, 0x5e9a);
    device->histogram_index = word(group, 0x5e9c);
    for (i = 0; i < 40; i++) device->histogram[i] = word(group, (uint16_t)(0x5e9e + i * 2));
    for (i = 0; i < 12; i++) device->callbacks.word[i] = word(group, (uint16_t)(0x5f12 + i * 2));
}

static void export_timer(uint8_t *group, const td2ega_timer_control_state *device)
{
    unsigned i;
    store(group, 0x5e88, device->saved_offset);
    store(group, 0x5e8a, device->saved_segment);
    group[0x5e94] = device->field_5e94;
    group[0x5e95] = device->field_5e95;
    store(group, 0x5e96, device->relay_remaining);
    store(group, 0x5e98, device->reload);
    store(group, 0x5e9a, device->remaining);
    store(group, 0x5e9c, device->histogram_index);
    for (i = 0; i < 40; i++) store(group, (uint16_t)(0x5e9e + i * 2), device->histogram[i]);
    for (i = 0; i < 12; i++) store(group, (uint16_t)(0x5f12 + i * 2), device->callbacks.word[i]);
}

void td2ega_install_simulation_state(uint8_t *group,
    td2ega_timer_control_state *device, td2ega_session_install_result *result)
{
    static const uint16_t zero_words[] = {0x5344,0x5346,0x3322,0x942e,0x331c,
        0x5372,0x331e,0x533e,0x330c,0x330e,0x3310,0x3312,0x3352,0x52d8,0x52da,0x52d6};
    static const uint16_t zero_bytes[] = {0x336b,0x3371,0x33b6,0x33b7,0x33bc,
        0x3374,0x3375,0x3376,0x3377,0x3378,0x33d5};
    unsigned i;
    uint8_t folded = 0;
    if (result == NULL) return;
    *result = (td2ega_session_install_result){0};
    if (group == NULL || device == NULL || device->current_cs == 0) {
        result->status = 2;
        return;
    }
    for (i = 0; i < 8; i++) group[0x335d + i] = 0;
    for (i = 0; i < sizeof zero_words / sizeof zero_words[0]; i++) store(group, zero_words[i], 0);
    for (i = 0; i < sizeof zero_bytes / sizeof zero_bytes[0]; i++) group[zero_bytes[i]] = 0;
    if (group[0x90a8] != 0) group[0x33af] = 0;
    group[0x3379] = group[0x843e];
    group[0x337a] = 0x20;
    for (i = 0; i < 0x47; i++) {
        uint16_t index = (uint16_t)((group[0x3b51 + i] & 0x7fu) * 4u);
        folded ^= group[0x347e + index];
    }
    group[0x33bd] = folded;
    store(group, 0x3811, (uint16_t)(word(group, 0x3811) + 0x3b33u));
    import_timer(group, device);
    td2ega_timer_install_fixed(device, &result->timer);
    td2ega_callback_add(&device->callbacks, 0x6269, device->current_cs, &result->callbacks[0]);
    td2ega_callback_add(&device->callbacks, 0x403b, device->current_cs, &result->callbacks[1]);
    export_timer(group, device);
}
