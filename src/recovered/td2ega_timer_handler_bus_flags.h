#ifndef TD2EGA_TIMER_HANDLER_BUS_FLAGS_H
#define TD2EGA_TIMER_HANDLER_BUS_FLAGS_H
#include "td2ega_timer_handler_bus.h"
/* Additional61BF/6230 variant. Same actualSS/body/frames/services/limits.
 * Incoming/retired flags maskF72B admits only arithmeticCF plusIF/DF and
 * explicit named system/reserved-bit profile; PF/AF/ZF/SF/OF unexposed.
 * Source arithmetic operations regain their actual defined bits. Immediate
 * ADDDI4 after a normal callback kills its unexposed arithmetic bits.
 * Prefixes retain partial masks instead of inventing child flag values.
 * Original bus interface and compiled artifacts remain frozen.
 */
void td2ega_timer_handler_bus_flags(uint8_t *,uint32_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_timer_handler_bus_limits *,const td2ega_timer_handler_bus_services *,
    td2ega_timer_handler_bus_result *);
#endif
