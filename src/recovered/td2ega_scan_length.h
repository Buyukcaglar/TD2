#ifndef TD2EGA_SCAN_LENGTH_H
#define TD2EGA_SCAN_LENGTH_H
#include "td2ega_state_loop.h"
typedef struct td2ega_scan_length_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t scans,bus_writes;
    td2ega_state_registers returned;
} td2ega_scan_length_result;
/*13A8:29B4: oneSSnearoffset/currentDS, ES=DS/AL0/CXFFFF REPNE SCASB,
 * incomingDF retained. NOTCX/DECCX ->AXlength, CX0, DIrestoredviaDX;
 * no-terminator withinFFFFscans returnsAXFFFE/lastcompareCF, noerrorinvented.
 * PlainfarRETF4/caller-clean, fullSSframes. Native0return/2invalid/3scanprefix;
 * actualbounds/lifetime/FLAGS/core/resourcefed/device/game gates separate. */
void td2ega_scan_length(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_scan_length_result *);
#endif
