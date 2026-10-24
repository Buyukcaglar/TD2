#ifndef TD2EGA_STATE_SEQUENCES_H
#define TD2EGA_STATE_SEQUENCES_H
#include "td2ega_state_messages.h"
enum td2ega_state_sequence_entry { TD2EGA_SEQUENCE_3532, TD2EGA_SEQUENCE_3643 };
/* Complete control bodies with typed far ABI leaves and actual native5C98.
 * Original point/count reads through BP useSS; globals andDI tables useDS.
 * No geometric/resource/unit/renderer/state-machine acceptance inferred. */
void td2ega_state_sequence(uint8_t *memory,uint32_t memory_bytes,
    uint16_t load_segment,uint16_t stack_segment,uint16_t entry_sp,
    enum td2ega_state_sequence_entry entry,const td2ega_state_registers *incoming,
    td2ega_state_message_service service,void *context,uint32_t max_calls,
    td2ega_state_message_result *result);
#endif
