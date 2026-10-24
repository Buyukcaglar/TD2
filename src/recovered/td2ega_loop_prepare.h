#ifndef TD2EGA_LOOP_PREPARE_H
#define TD2EGA_LOOP_PREPARE_H
#include "td2ega_state_loop.h"
typedef struct td2ega_loop_prepare_result {
    uint16_t status;
    uint32_t records;
    td2ega_state_registers returned;
} td2ega_loop_prepare_result;
/* 2089: currentDS records/globals/output share one mutable bus; no resource
 * meanings or safe destination capacity inferred. DS versus1E59's SS is
 * explicit. Both record loops execute at least once. CF/IF/DF/BP modeled.
 * Native budget diagnostics are outside original return/error equivalence. */
void td2ega_loop_prepare(uint8_t *memory,uint32_t memory_bytes,
    const td2ega_state_registers *incoming,uint32_t max_records,
    td2ega_loop_prepare_result *result);
#endif
