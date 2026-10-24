#ifndef TD2EGA_INPUT_POLL_H
#define TD2EGA_INPUT_POLL_H
#include "td2ega_key_dispatch.h"
#include "td2ega_gameport.h"

typedef struct td2ega_bios_key_request { uint16_t operation, ax, interrupts_enabled, direction; } td2ega_bios_key_request;
typedef struct td2ega_bios_key_response { uint16_t ax, zero, interrupts_enabled, direction; } td2ega_bios_key_response;
typedef int (*td2ega_bios_key_service)(void *context,
    const td2ega_bios_key_request *request, td2ega_bios_key_response *response);
typedef struct td2ega_input_services {
    uint16_t callback_segment, original_ds, original_ss;
    uint32_t max_gameport_reads;
    td2ega_bios_key_service bios; void *bios_context;
    td2ega_gameport_service port; void *port_context;
    td2ega_key_callback callback; void *callback_context;
} td2ega_input_services;
typedef struct td2ega_input_result {
    uint16_t status, bios_probes, bios_reads, dispatch_used, gameport_used;
    td2ega_key_registers registers;
    uint16_t dispatch_argument;
    uint32_t gameport_reads;
} td2ega_input_result;

/* Complete65C5/6601/6620 under explicit component service profiles. Original
 * group field effects and adapter writes are disjoint from active SS frames;
 * DS may equal SS. Original segment values remain explicit, never host
 * addresses. BIOS preserves nonresponse registers; explicit response IF/DF propagate.
 * Installed69B7 AH1 forcesIF1; historicalv1 preserving-flags profile is separate. Callback
 * far-frame and gameport contracts apply; no actual BIOS or device executes.
 */
void td2ega_input_poll(uint8_t *group, uint32_t group_bytes,
    const td2ega_input_services *services, const td2ega_key_registers *incoming,
    td2ega_input_result *result);
void td2ega_input_consume_if_stack_group(uint8_t *group, uint32_t group_bytes,
    const td2ega_input_services *services, const td2ega_key_registers *incoming,
    td2ega_input_result *result);
void td2ega_input_direction_bits(uint8_t *group, uint32_t group_bytes,
    const td2ega_input_services *services, const td2ega_key_registers *incoming,
    td2ega_input_result *result);
#endif
