#include "td2ega_audio_metadata.h"
#include <stddef.h>

static int start(td2ega_audio_metadata *state, td2ega_audio_metadata_result *result)
{
    if (result == NULL) return 0;
    *result = (td2ega_audio_metadata_result){0};
    if (state == NULL) {
        result->status = 2;
        return 0;
    }
    return 1;
}

static uint16_t read_word(const uint8_t *source, uint16_t offset)
{
    return (uint16_t)((uint16_t)source[offset] | ((uint16_t)source[(uint32_t)offset + 1] << 8));
}

void td2ega_song_select_metadata(td2ega_audio_metadata *state,
    const uint8_t *source, uint32_t source_length, uint16_t source_segment,
    uint16_t source_offset, uint16_t selector, td2ega_audio_metadata_result *result)
{
    uint16_t first, second, value;
    if (!start(state, result)) return;
    if (state->mode != 3) return;
    first = (uint16_t)(source_offset + (uint16_t)((uint32_t)selector * 4u));
    second = (uint16_t)(first + 2u);
    if (source == NULL || source_length != 65536 || first == 65535 || second == 65535) {
        result->status = 2;
        return;
    }
    result->selected_offset = first;
    state->song_segment = source_segment;
    value = read_word(source, first);
    state->song_offset = value;
    state->restart_offset = value;
    value = read_word(source, second);
    state->song_other_offset = value;
    state->restart_other_offset = value;
    state->song_flag = 1;
    state->active_flag = 1;
    result->enables_interrupts = 1;
}

void td2ega_voice_set_metadata(td2ega_audio_metadata *state, uint16_t offset,
    uint16_t segment, td2ega_audio_metadata_result *result)
{
    if (!start(state, result)) return;
    state->voice_segment = segment;
    state->voice_offset = offset;
}

void td2ega_effect_set_metadata(td2ega_audio_metadata *state, uint16_t offset,
    uint16_t segment, td2ega_audio_metadata_result *result)
{
    if (!start(state, result)) return;
    state->active_segment = segment;
    state->active_offset = offset;
    state->active_flag = 1;
    result->enables_interrupts = 1;
}

void td2ega_effect_queue_metadata(td2ega_audio_metadata *state, uint16_t offset,
    uint16_t segment, td2ega_audio_metadata_result *result)
{
    if (!start(state, result)) return;
    state->queued_segment = segment;
    state->queued_offset = offset;
    state->queued_flag = 1;
    if (state->active_flag == 0) {
        state->active_segment = segment;
        state->active_offset = offset;
    }
    result->enables_interrupts = 1;
}

void td2ega_effect_cancel_queued(td2ega_audio_metadata *state,
    td2ega_audio_metadata_result *result)
{
    if (!start(state, result)) return;
    state->queued_flag = 0;
}
