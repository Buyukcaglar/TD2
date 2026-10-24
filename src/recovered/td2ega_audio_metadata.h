#ifndef TD2EGA_AUDIO_METADATA_H
#define TD2EGA_AUDIO_METADATA_H
#include <stdint.h>

typedef struct td2ega_audio_metadata {
    uint16_t song_offset, song_other_offset, restart_offset, restart_other_offset;
    uint16_t song_segment, voice_segment, voice_offset;
    uint16_t active_segment, active_offset, queued_segment, queued_offset;
    uint8_t mode, active_flag, queued_flag, song_flag;
} td2ega_audio_metadata;
typedef struct td2ega_audio_metadata_result {
    uint16_t status; /* 0: admitted normal effect; 2: native diagnostic */
    uint16_t enables_interrupts;
    uint16_t selected_offset;
} td2ega_audio_metadata_result;

/* Source segment is a caller-owned64KiB byte view disjoint from state/result.
 * Pointer arithmetic uses original16bit offset/selector wrap. Word accesses
 * beginning atFFFF are outside the admitted profile. */
void td2ega_song_select_metadata(td2ega_audio_metadata *state,
    const uint8_t *source, uint32_t source_length, uint16_t source_segment,
    uint16_t source_offset, uint16_t selector, td2ega_audio_metadata_result *result);
void td2ega_voice_set_metadata(td2ega_audio_metadata *state, uint16_t offset,
    uint16_t segment, td2ega_audio_metadata_result *result);
void td2ega_effect_set_metadata(td2ega_audio_metadata *state, uint16_t offset,
    uint16_t segment, td2ega_audio_metadata_result *result);
void td2ega_effect_queue_metadata(td2ega_audio_metadata *state, uint16_t offset,
    uint16_t segment, td2ega_audio_metadata_result *result);
void td2ega_effect_cancel_queued(td2ega_audio_metadata *state,
    td2ega_audio_metadata_result *result);
#endif
