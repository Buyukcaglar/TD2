#ifndef TD2EGA_FAR_MEMBER_H
#define TD2EGA_FAR_MEMBER_H
#include "td2ega_state_loop.h"
typedef struct td2ega_far_member_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t bus_writes;
    td2ega_state_registers returned;
} td2ega_far_member_result;
/*06C9:C701, threeSSwords headerOffset/headerSegment/index. HeaderwordES:SI+4,
 * tableBX=(4*headerword+4*index+6)word, base=(8*headerword+6)word;
 * tablewords useES:BX andseparatelywrappedES:BX+2, notSI-relative table.
 * Raw32bitlinearadd/4right-shifts ->AXnibble/DXnormalizedsegment, CFlinearbit3.
 * ActualSS/BP/SIsaves/plainfarRETF4/callerclean. Native0return/2invalid.
 * Resourceformat/bounds/caller/writers/lifetime/core acceptance separate. */
void td2ega_far_member(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_far_member_result *);
#endif
