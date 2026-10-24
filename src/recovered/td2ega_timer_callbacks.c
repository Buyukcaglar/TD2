#include "td2ega_timer_callbacks.h"
#include <stddef.h>

static void store_word(td2ega_callback_words *state, uint16_t index,
                       uint16_t value, td2ega_callback_result *result)
{
    state->word[index] = value;
    result->writes[result->write_count].word_index = index;
    result->writes[result->write_count].value = value;
    result->write_count++;
}

static int start_result(td2ega_callback_words *state,
                         td2ega_callback_result *result)
{
    if (result == NULL) return 0;
    *result = (td2ega_callback_result){0};
    result->slot = 5;
    if (state == NULL) {
        result->status = 2;
        return 0;
    }
    return 1;
}

void td2ega_callback_add(td2ega_callback_words *state, uint16_t offset,
                         uint16_t segment, td2ega_callback_result *result)
{
    uint16_t slot;
    if (!start_result(state, result)) return;
    for (slot = 0; slot < 5; slot++) {
        uint16_t index = (uint16_t)(slot * 2);
        if (state->word[index + 1] != 0) continue;
        result->slot = slot;
        store_word(state, index, offset, result);
        store_word(state, (uint16_t)(index + 1), 0, result);
        store_word(state, (uint16_t)(index + 1), segment, result);
        store_word(state, (uint16_t)(index + 3), 0, result);
        return;
    }
    /* 6160..6164: fatal-report transfer is a separate platform contract. */
    result->status = 1;
}

void td2ega_callback_remove(td2ega_callback_words *state, uint16_t offset,
                            uint16_t segment, td2ega_callback_result *result)
{
    uint16_t slot;
    if (!start_result(state, result)) return;
    for (slot = 0; slot < 5; slot++) {
        uint16_t index = (uint16_t)(slot * 2);
        if (state->word[index] != offset || state->word[index + 1] != segment)
            continue;
        result->slot = slot;
        for (; index < 8; index = (uint16_t)(index + 2)) {
            store_word(state, index, state->word[index + 2], result);
            store_word(state, (uint16_t)(index + 1), state->word[index + 3], result);
        }
        store_word(state, 8, 0, result);
        store_word(state, 9, 0, result);
        result->enables_interrupts = 1;
        return;
    }
}
