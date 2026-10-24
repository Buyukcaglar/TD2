#ifndef TD2EGA_FIND_FILES_H
#define TD2EGA_FIND_FILES_H
#include "td2ega_sim_targets.h"
typedef struct td2ega_find_request {
    uint16_t operation, ax, cx, dx, ds, dta_offset; /* 0 AH1A, 1 AH4E, 2 AH4F */
    uint8_t *dta; /* synthetic service may update43-byte group5DEE..5E18 */
} td2ega_find_request;
typedef struct td2ega_find_response { uint16_t ax, carry; } td2ega_find_response;
typedef int (*td2ega_find_service)(void *context,
    const td2ega_find_request *request, td2ega_find_response *response);
typedef struct td2ega_find_result {
    uint16_t status, found, es, direction, replacement_offset, prefix_copied;
    td2ega_sim_target_result registers;
} td2ega_find_result;

/* Complete5EF4/5F4E, serialized fullgroup/native-result views disjoint and
 * field/adapter writes separate from activeSS/code. Service preserves all
 * nonresponse registers andIF/DF, may update statedDTA bytes even on failure.
 * SuccessfulAX is near5D88, not a boolean orhostC-string guarantee. Retain
 * currentDTA/basename lifetime, 87-byte boundedprefix andliteral13-byte copy.
 * Native servicefault diagnostics are outside original error equivalence.
 */
void td2ega_find_first(uint8_t *group, uint32_t group_bytes,
    uint16_t original_ds, uint16_t filename_offset,
    const td2ega_sim_target_result *incoming, uint16_t incoming_es,
    uint16_t incoming_direction, td2ega_find_service service, void *context,
    td2ega_find_result *result);
void td2ega_find_next(uint8_t *group, uint32_t group_bytes,
    uint16_t original_ds, const td2ega_sim_target_result *incoming,
    uint16_t incoming_es, uint16_t incoming_direction,
    td2ega_find_service service, void *context, td2ega_find_result *result);
#endif
