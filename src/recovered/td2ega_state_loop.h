#ifndef TD2EGA_STATE_LOOP_H
#define TD2EGA_STATE_LOOP_H
#include "td2ega_music_tick.h"
#include "td2ega_mutable_control.h"
typedef struct td2ega_state_registers {
    td2ega_music_registers registers;
    uint16_t bp, carry;
} td2ega_state_registers;
typedef struct td2ega_state_call_request {
    uint16_t site, segment, offset, argument_count, live_argument_count;
    uint16_t arguments[4]; /* First current stack argument first. */
    td2ega_state_registers incoming;
} td2ega_state_call_request;
typedef int (*td2ega_state_call_service)(void *context, uint8_t *memory,
    const td2ega_state_call_request *request, td2ega_state_registers *returned);
typedef struct td2ega_state_loop_result {
    uint16_t status, dispatch_target;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_state_loop_result;
/* Original1B2C orchestration with explicit far-callee ABI services. Callees
 * return normally with unchangedSP/SS and callerargument words; incidental
 * flags other thanCF/IF/DF are outside adapter profile. Live frames are
 * nonwrapping and separatedata writes. Knowndispatch targets only; unknown
 * table targets diagnostic2, nativebudget3/service4 outsideoriginal errors.
 * Explicit mutable tail state preserves CLC/RETF return andphysical0086 write.
 * No callee-body/full-state/resource/IRQ/gamecore admission from this packet.
 */
void td2ega_state_loop(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, const td2ega_mutable_control *code_state,
    const td2ega_state_registers *incoming, td2ega_state_call_service service,
    void *context, uint32_t max_calls, td2ega_state_loop_result *result);
#endif
