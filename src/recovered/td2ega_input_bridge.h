#ifndef TD2EGA_INPUT_BRIDGE_H
#define TD2EGA_INPUT_BRIDGE_H
#include "td2ega_state_loop.h"
enum td2ega_input_bridge_entry {
    TD2EGA_INPUT_CALL, TD2EGA_INPUT_BIOS_POLL, TD2EGA_INPUT_SET,
    TD2EGA_INPUT_GET, TD2EGA_INPUT_BIOS_DRAIN
};
typedef struct td2ega_input_bridge_request {
    uint16_t kind, site, segment, offset, stack_segment, stack_sp;
    td2ega_state_registers incoming;
} td2ega_input_bridge_request;
typedef struct td2ega_input_bridge_response {
    td2ega_state_registers returned;
    uint16_t zero;
} td2ega_input_bridge_response;
typedef int (*td2ega_input_bridge_service)(void *context, uint8_t *memory,
    const td2ega_input_bridge_request *request,
    td2ega_input_bridge_response *response);
typedef struct td2ega_input_bridge_result {
    uint16_t status, current_sp, return_bytes;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_input_bridge_result;
/* Serialized bus/control-frame separation. SET reads caller argument words
 * from SS:entry_sp+4/+6 in original order, retaining data/argument aliases.
 * Kind0 BIOS16 uses virtual6-byte interrupt frame; kind1 dynamic far uses4.
 * Services preserveSS/SP/controlframes; no native materialized liveframes.
 * CF/IF/DF modeled, BIOS ZF explicit. No real BIOS/IRQ/input/core admission. */
void td2ega_input_bridge(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, uint16_t stack_segment, uint16_t entry_sp,
    enum td2ega_input_bridge_entry entry, const td2ega_state_registers *incoming,
    td2ega_input_bridge_service service, void *context, uint32_t max_calls,
    td2ega_input_bridge_result *result);
#endif
