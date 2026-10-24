#ifndef TD2EGA_PREPARE_RECORDS_H
#define TD2EGA_PREPARE_RECORDS_H
#include "td2ega_music_tick.h"
typedef struct td2ega_prepare_records_result {
    uint16_t status, bp, table_offset, record_offset;
    uint32_t steps, samples, deleted;
    td2ega_music_registers registers;
} td2ega_prepare_records_result;
/* Complete1E59, serialized20-bit bus, original SS explicit: BP+SI fields use
 * SS, globals/sampler and forward deletion use DS, ES becomes DS. Data writes
 * exclude executing code/liveSS frames; result/context disjoint. Original
 * divide overflow is status1/fault prefix; nativeinvalid2/budget3 are separate.
 * Linked byte-source C is an isolated caller composition, no game integration.
 */
void td2ega_prepare_records(uint8_t *memory, uint32_t memory_bytes,
    uint16_t stack_segment, const td2ega_music_registers *incoming,
    uint16_t incoming_bp, uint32_t max_steps, td2ega_prepare_records_result *result);
#endif
