#ifndef TD2EGA_SESSION_INIT_BUS_H
#define TD2EGA_SESSION_INIT_BUS_H
#include "td2ega_timer_startup_tail_bus.h"
typedef struct td2ega_session_init_bus_limits {
    uint32_t steps,init_calls;
    td2ega_timer_startup_tail_limits tail;
} td2ega_session_init_bus_limits;
typedef struct td2ega_session_init_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,init_calls,tail_calls,ports,bus_writes;
    uint16_t flags_word,flags_mask,stage,halt_site,call_segment,call_offset;
    td2ega_state_registers returned;
} td2ega_session_init_bus_result;
/* Additional actualSS entries0=3F40,1=3FF9,2=38F2,3=1E31,4=5427.
 * Entries0..3 plainfarRET;4 nearRET. SourceSP:0=10..FFE0,1>=2,3>=6,
 * othersanyword. QualifiedpreRET bounds remain explicit.
 * Native0 retiredroot/no follow,1 rawchild,2 invalid,3 budget,4 portfailure,
 * 5 preRET,6 tailfatalpreCALL. Stage0 ownroot,1 inner3FF9,2 inner5427,
 * 3 inner38F2,100+tailstage on incomplete delegatedtail.
 * Steps charge each bodyentry, prefixstore, activeREP iteration andfoldhead.
 * init_calls counts3FF9/5427/38F2 calls;tail_calls separately counts3FD9tail.
 * No extra CALL/frame is inserted before the delegated3FD9 tail.
 */
void td2ega_session_init_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_session_init_bus_limits *,td2ega_music_port_service,void *,
    td2ega_session_init_bus_result *);
#endif
