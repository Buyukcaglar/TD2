#ifndef TD2EGA_POOL_SETUP_H
#define TD2EGA_POOL_SETUP_H
#include "td2ega_sim_targets.h"
typedef struct td2ega_pool_request { uint16_t operation, ax, bx, es; } td2ega_pool_request;
typedef struct td2ega_pool_response { uint16_t ax, bx, carry; } td2ega_pool_response;
typedef int (*td2ega_pool_service)(void *context,
    const td2ega_pool_request *request, td2ega_pool_response *response);
typedef struct td2ega_pool_result {
    uint16_t status, stage, es;
    td2ega_sim_target_result registers;
    uint32_t cleared;
} td2ega_pool_result;

/* Complete6F1E/6F86/6FD6. Shared ordinary group window includes adjacent byte
 * for wordatFFFF; original near addresses (including0) remain coordinates.
 * Serialized group/adapter effects separate from activeSS/code/result. DOS
 * profile changes onlyAX/BX/CF, preservesES/DS/otherregisters and group. The
 * original ignoresCF, preserves returnedBX through the two resize calls.
 * Native service/clear-budget diagnostics are outside original failures.
 */
void td2ega_pool_setup(uint8_t *group, uint32_t group_bytes,
    uint16_t original_cs, uint16_t original_ds, uint16_t requested_end,
    const td2ega_sim_target_result *incoming, uint16_t incoming_es,
    td2ega_pool_service service, void *context, uint32_t max_clears,
    td2ega_pool_result *result);
void td2ega_pool_setup_fixed(uint8_t *group, uint32_t group_bytes,
    uint16_t original_cs, uint16_t original_ds,
    const td2ega_sim_target_result *incoming, uint16_t incoming_es,
    td2ega_pool_service service, void *context, uint32_t max_clears,
    td2ega_pool_result *result);
void td2ega_pool_remaining(const uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *result);
#endif
