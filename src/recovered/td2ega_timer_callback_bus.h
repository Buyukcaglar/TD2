#ifndef TD2EGA_TIMER_CALLBACK_BUS_H
#define TD2EGA_TIMER_CALLBACK_BUS_H
#include "td2ega_state_loop.h"
#include "td2ega_input_flags.h"
typedef struct td2ega_timer_callback_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,bus_writes;
    uint16_t flags_word,flags_mask,halt_site,slot,call_segment,call_offset;
    td2ega_state_registers returned;
} td2ega_timer_callback_bus_result;
/* Additional actualSS entry0=614C add,1=6180 remove. Two source word arguments
 * remain for caller cleanup. SP>=2 excludes unqualified initial PUSH wrap.
 * Native0 reports retired farroot/no follow;2 invalid;3 budget;5 preRET
 * SP>FFFC;6 before fatal6164 CALL, retaining PUSHAX and reporting its target.
 * Steps charge entry, search heads and each callback metadata store, allowing
 * observation of source publication prefixes without claiming actual IRQs.
 * Add has no CLI/STI; matched remove ends STI regardless of incoming IF.
 */
void td2ega_timer_callback_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,uint32_t,
    td2ega_timer_callback_bus_result *);
#endif
