#ifndef TD2EGA_KEY_ACTIONS_H
#define TD2EGA_KEY_ACTIONS_H
#include "td2ega_music_tick.h"
enum td2ega_key_action {
    TD2EGA_KEY_ENABLE_GAMEPORT,
    TD2EGA_KEY_DISABLE_GAMEPORT,
    TD2EGA_KEY_TOGGLE_EFFECTS,
    TD2EGA_KEY_TOGGLE_MUSIC,
    TD2EGA_KEY_DIALOG_0358,
    TD2EGA_KEY_DIALOG_007C
};
typedef struct td2ega_key_action_request {
    uint16_t segment, offset, argument_count;
    uint16_t arguments[3]; /* First original stack argument first. */
    td2ega_music_registers registers;
} td2ega_key_action_request;
typedef int (*td2ega_key_action_service)(void *context, uint8_t *memory,
    const td2ega_key_action_request *request, td2ega_music_registers *returned);
/* Six original noargument RETF entries645A/646F/6488/64C7/6508/6518.
 * Synthetic20-bit bus, data separatecode/liveSS; external presentation/UI
 * bodies are ABI services preservingSS/BP/control frames. ReturnedDS governs
 * guardclear, IF/DF propagate. Source text stays external; no UI is rendered.
 */
void td2ega_key_action_apply(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, enum td2ega_key_action action,
    const td2ega_music_registers *incoming, td2ega_key_action_service service,
    void *context, td2ega_music_tick_result *result);
#endif
