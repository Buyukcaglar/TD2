#ifndef TD2EGA_COPY_CONFIG_H
#define TD2EGA_COPY_CONFIG_H
#include "td2ega_state_loop.h"
typedef struct td2ega_copy_config_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,writes;
    td2ega_state_registers returned;
} td2ega_copy_config_result;
/*0=5D01 fiveSSwords[srcOff,srcSeg,dstOff,dstSeg,byteCount];
 *1=7D5E twoSSwords[srcOff,srcSeg] ->13words CS:AF3A;
 *2=7918 oneSSnear-sourceword/currentDS ->26words CS:AF3A.
 * ForwardREP order, CLD, materializedSSsavedframes/plainfarRETF4.
 * Native0return/2invalid/3workprefix; actualproducer/capacity/tablewriter/
 * IRQ/core/resource-fed acceptance separate. No hostmemmove substitution. */
void td2ega_copy_config(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_copy_config_result *);
#endif
