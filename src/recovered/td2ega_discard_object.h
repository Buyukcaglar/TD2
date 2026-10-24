#ifndef TD2EGA_DISCARD_OBJECT_H
#define TD2EGA_DISCARD_OBJECT_H
#include "td2ega_state_loop.h"
typedef struct td2ega_discard_object_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,scans,trims,bus_writes;
    td2ega_state_registers returned;
} td2ega_discard_object_result;
/* Actual782C far/twoSSwords point to a far descriptor/CSB269 wrapped update/
 * actual7490 fullCPU-SS cache search/free/trim. Raw arbitrary16bitDS offsets.
 * status0boundedrootRET/1rawchildRET/2invalid/3CALL-scanbudget/
 * 5unqualifiedfourbytefarframepreRET/6originalfatalpreCALL74B3.
 * Fatalcallee16A7:0002 is not executed. No metadata/size/ownership validation
 * is inferred; no heap/storage lifetime, exclusion, core or resource gate. */
void td2ega_discard_object(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,
    td2ega_discard_object_result *);
#endif
