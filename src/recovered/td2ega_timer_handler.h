#ifndef TD2EGA_TIMER_HANDLER_H
#define TD2EGA_TIMER_HANDLER_H
#include "td2ega_music_tick.h"
typedef struct td2ega_timer_call_request {
    uint16_t kind; /* 0 far callback, 1 INT08 through temporarily restored IVT. */
    uint16_t segment, offset;
    td2ega_music_registers registers;
} td2ega_timer_call_request;
typedef int (*td2ega_timer_call_service)(void *context, uint8_t *memory,
    const td2ega_timer_call_request *request, td2ega_music_registers *returned);
typedef struct td2ega_timer_handler_result {
    uint16_t status, return_flags;
    uint32_t steps, callbacks, old_interrupts;
    td2ega_music_registers registers;
} td2ega_timer_handler_result;

/* Serialized instruction effects on a synthetic20-bit bus, data writes
 * separate from executing code/liveSS. Callback bodies are explicit adapters;
 * there is no five-row clamp or implicit reentrancy guard. Incidental
 * arithmetic flags at adapter entry are outside this profile. Original ISR
 * IRET restores supplied irq_flags and all saved registers. Bridge INT08
 * adapter uses an IRET profile: entryIF0, returned IF/DF restore pre-INT flags.
 */
void td2ega_timer_handler(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, const td2ega_music_registers *incoming,
    uint16_t irq_flags, td2ega_music_port_service port,
    td2ega_timer_call_service call, void *context, uint32_t max_steps,
    td2ega_timer_handler_result *result);
void td2ega_timer_chain_old(uint8_t *memory, uint32_t memory_bytes,
    uint16_t code_segment, const td2ega_music_registers *incoming,
    td2ega_timer_call_service call, void *context, uint32_t max_steps,
    td2ega_timer_handler_result *result);
#endif
