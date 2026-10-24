#ifndef TD2EGA_MEMBER_REORDER_H
#define TD2EGA_MEMBER_REORDER_H
#include "td2ega_far_member.h"
typedef struct td2ega_member_reorder_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,calls,byte_transfers,bus_writes;
    td2ega_state_registers returned;
} td2ega_member_reorder_result;
/* Actual06C9:C838 + actualC701, fourSSwords headerOff/Seg,scratchOff/Seg.
 * Raw count/shape/flag storage, source DS changes, wordwrap and incomingDF.
 * RootSP>=54 ensures frozenC701SP>=16. Native0farreturn/1rawchild/2invalid/
 *3before member/plane/transpose-byte/REP-byte budget. No valid format or
 * scratch/resource capacity, producer/lifetime/core or full decode admission. */
void td2ega_member_reorder(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_member_reorder_result *);
#endif
