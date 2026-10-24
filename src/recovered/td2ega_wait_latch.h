#ifndef TD2EGA_WAIT_LATCH_H
#define TD2EGA_WAIT_LATCH_H
#include "td2ega_wait_control.h"
enum td2ega_wait_latch_entry { TD2EGA_LATCH_SET, TD2EGA_LATCH_WAIT };
/* 7A10 reads rawdistanceSS arguments after79C8, publishesDS6818/A; 7A27
 * repeatedly snapshots and compares currentDS globaldeadline, without copying
 * it to a local. Counter events update synthetic bus only, no IRQ delivered.
 * Data/caller-argument aliases admitted; livecontrolframes/code separate. */
void td2ega_wait_latch(uint8_t *memory,uint32_t memory_bytes,
    uint16_t load_segment,uint16_t stack_segment,uint16_t entry_sp,
    enum td2ega_wait_latch_entry entry,const td2ega_state_registers *incoming,
    td2ega_wait_service service,void *context,uint32_t max_events,
    td2ega_wait_result *result);
#endif
