#ifndef TD2EGA_CONFIG_APPLY_H
#define TD2EGA_CONFIG_APPLY_H
#include "td2ega_copy_config.h"
typedef struct td2ega_config_apply_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,writes,calls;
    td2ega_state_registers returned;
} td2ega_config_apply_result;
/*3EFC: pushcurrentDS9B4/9B2, actualfar7D5E, ADDSP4, plainfarRETF4.
 * FullnestedSSframes materialized. Native0rootfarreturn/1unexpectedchildfar
 * returnboundary/2invalid/3workprefix. Sourceownership/capacity/allwriters/
 * lifetime/IRQ/core/resource-fed acceptance remainsseparate. */
void td2ega_config_apply(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_config_apply_result *);
#endif
