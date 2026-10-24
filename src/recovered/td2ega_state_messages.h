#ifndef TD2EGA_STATE_MESSAGES_H
#define TD2EGA_STATE_MESSAGES_H
#include "td2ega_state_loop.h"
enum td2ega_state_message_entry {
    TD2EGA_MESSAGE_36E0, TD2EGA_MESSAGE_3713, TD2EGA_MESSAGE_371F,
    TD2EGA_MESSAGE_372B, TD2EGA_MESSAGE_3737, TD2EGA_MESSAGE_3743,
    TD2EGA_MESSAGE_374F, TD2EGA_MESSAGE_375F, TD2EGA_MESSAGE_3788,
    TD2EGA_MESSAGE_3F0D, TD2EGA_MESSAGE_5C98
};
typedef struct td2ega_state_message_request {
    uint16_t site, segment, offset, argument_count, live_argument_count;
    uint16_t stack_segment, stack_sp;
    uint16_t arguments[10];
    td2ega_state_registers incoming;
} td2ega_state_message_request;
typedef int (*td2ega_state_message_service)(void *context, uint8_t *memory,
    const td2ega_state_message_request *request, td2ega_state_registers *returned);
typedef struct td2ega_state_message_result {
    uint16_t status, current_sp, return_bytes;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_state_message_result;
/* Complete11 entry/control bodies with explicit external farABI services.
 * 3788 returns nearRET2; othersfarRETF4. Argument/liveword order and virtual
 * stack addresses retained; nativebus doesnotmaterialize liveframes. Services
 * useprovidedarguments, preserveSS/SP/controlframes/callerargumentwords and
 * do notread/writeliveSSframes. Data/code/frame separation, nonwrappingstack
 * andCFIFDF-only flagprofile; no rendering/text/timing/IRQ/core admission.
 */
void td2ega_state_message(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, uint16_t stack_segment, uint16_t entry_sp,
    enum td2ega_state_message_entry entry, const td2ega_state_registers *incoming,
    td2ega_state_message_service service, void *context, uint32_t max_calls,
    td2ega_state_message_result *result);
#endif
