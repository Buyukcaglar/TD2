#ifndef TD2EGA_PROJECTION_H
#define TD2EGA_PROJECTION_H
#include "td2ega_state_loop.h"
typedef struct td2ega_projection_result {
    uint16_t status,fault_site;
    uint32_t work,iterations,lookups,scans;
    td2ega_state_registers returned;
} td2ega_projection_result;
/* 13A3:0038 signed AL lookup in externalcurrentDS5560 table; restoresBX/DX,
 * returnsAX/CF, plainfarRETF. No tablecontents/functionmeaning embedded. */
uint16_t td2ega_signed_byte_lookup(const uint8_t *memory,uint32_t memory_bytes,
    const td2ega_state_registers *incoming,td2ega_state_registers *returned);
/* 21C3 raw indexed projection/control body, plainnearRET. Serializedshared
 * DS data, externaltables, code/liveSS frames separate. Work counts record
 * starts and list nodes; budget3/invalid2 separate fromoriginalreturns.
 * Status1 capturesactual23FA IDIVzero/quotientoverflow prefix. No geometry,
 * resource decoding, validcallerbounds, renderer/state/core admission. */
void td2ega_projection_step(uint8_t *memory,uint32_t memory_bytes,
    const td2ega_state_registers *incoming,uint32_t max_work,
    td2ega_projection_result *result);
#endif
