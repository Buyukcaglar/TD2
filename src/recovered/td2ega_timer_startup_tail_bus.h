#ifndef TD2EGA_TIMER_STARTUP_TAIL_BUS_H
#define TD2EGA_TIMER_STARTUP_TAIL_BUS_H
#include "td2ega_timer_control_bus.h"
#include "td2ega_timer_callback_bus.h"
typedef struct td2ega_timer_startup_tail_limits {
    uint32_t calls,timer_steps,timer_ports,callback_steps;
} td2ega_timer_startup_tail_limits;
typedef struct td2ega_timer_startup_tail_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,ports,bus_writes;
    uint16_t flags_word,flags_mask,stage,halt_site,call_segment,call_offset;
    td2ega_state_registers returned;
} td2ega_timer_startup_tail_result;
/* Additional original3FD9..3FF8 tail of3F40, not its earlier initialization.
 * Inherited actualSS/sourceSP10..FFE0; entry is immediately before601C CALL.
 * ActualfarCALLframes, callbackarguments/callercleanup andrawretiredchild
 * checks are explicit. 0 retiredroot/no follow,1 rawchild,2 invalid,
 * 3 budget,4 portfailure,5 qualifiedpreRET,6 callbackfatalpreCALL.
 * stage0 own tail,1 timer child,2 firstcallbackadd,3 secondcallbackadd.
 * No startup-to-exit/IRQ-lifetime/core admission is implied.
 */
void td2ega_timer_startup_tail_bus(uint8_t *,uint32_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_timer_startup_tail_limits *,td2ega_music_port_service,void *,
    td2ega_timer_startup_tail_result *);
#endif
