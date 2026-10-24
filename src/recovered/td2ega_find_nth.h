#ifndef TD2EGA_FIND_NTH_H
#define TD2EGA_FIND_NTH_H
#include "td2ega_find_files.h"
typedef struct td2ega_find_nth_result {
    uint16_t status, index, es, direction;
    uint32_t next_calls;
    td2ega_sim_target_result registers;
} td2ega_find_nth_result;
/* Complete16B8:0000, including FindNext after failedFindFirst when signed
 * ordinal>1. Inherit search/sharedgroup/service profiles; actual validDTA
 * state/lifetime is not inferred from this literal caller. Native budget
 * diagnostics are outside original behavior and can leave partial state.
 */
void td2ega_find_nth(uint8_t *group, uint32_t group_bytes, uint16_t original_ds,
    uint16_t filename_offset, uint16_t ordinal,
    const td2ega_sim_target_result *incoming, uint16_t incoming_es,
    uint16_t incoming_direction, td2ega_find_service service, void *context,
    uint32_t max_next_calls, td2ega_find_nth_result *result);
#endif
