#ifndef TD2EGA_SIGNED_MOTION_H
#define TD2EGA_SIGNED_MOTION_H
#include "td2ega_sim_targets.h"
typedef struct td2ega_signed_motion_result {
    td2ega_sim_target_result registers;
    uint16_t damped, error, correction;
    uint32_t product;
} td2ega_signed_motion_result;

/* Original13A8:2EE8 returns low32 product viaDX:AX and RETF8. Native scalar
 * arguments expose bit patterns; CX is preserved only on both-highwords-zero
 * path, otherwise it contains wrapped cross terms. Result is disjoint.
 */
void td2ega_long_multiply(uint32_t first, uint32_t second,
    uint16_t incoming_cx, td2ega_sim_target_result *result);

/* Complete06B3:0008, fullsharedgroup serialized field effects separate from
 * activeSS/code/result. Explicit arithmetic-right shifts and16bit wrap, no
 * host signed overflow or original physical units. Includes native2EE8.
 */
void td2ega_update_signed_motion(uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_signed_motion_result *result);
#endif
