#ifndef TD2EGA_TIMER_CONTROL_BUS_H
#define TD2EGA_TIMER_CONTROL_BUS_H
#include "td2ega_state_loop.h"
#include "td2ega_input_flags.h"
typedef struct td2ega_timer_control_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,ports,bus_writes;
    uint16_t flags_word,flags_mask,halt_site,initial_divisor,quotient,reserved;
    td2ega_state_registers returned;
} td2ega_timer_control_bus_result;
/* Additional fullSS roots0=601C fixed,1=6059 divisor,2=610A cleanup.
 * Roots0/1 saveactualBP; sourceSP>=2 excludes unqualified PUSH wrap. Root2
 * hasno ownsave. SourcefarRET readsactualSS words afterbody/POP effects;
 * SP>FFFC stopsbeforeRET afterprior effects. Root1 divisor isSS:[entrySP+4],
 * reread after quotient publications; source caller consumes its argument.
 * Native0retiredroot/no follow,2invalid,3budget,4portservice,5preRET,
 * 6preIDIVfault. Flags masks mayexclude all arithmetic bits (F72A) afterIDIV.
 * State.carry isvalid onlywhen flags_mask bit0 isknown. No guessed timeunits,
 * historicalCPU/IRQdelivery/lifetime/core/game/fidelity acceptance.
 */
void td2ega_timer_control_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    td2ega_music_port_service,void *,uint32_t,uint32_t,
    td2ega_timer_control_bus_result *);
#endif
