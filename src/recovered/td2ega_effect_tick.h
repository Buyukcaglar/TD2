#ifndef TD2EGA_EFFECT_TICK_H
#define TD2EGA_EFFECT_TICK_H
#include "td2ega_music_tick.h"
/* Same explicit bus/register/port/result representation, distinct event code.
 * 6269 has no CLD: IF/DF survive. Principal DS and data/code/stack separation
 * inherit the music packet's synthetic bus profile; queued/source aliases
 * remain shared. Budget diagnostic3 is outside original equivalence.
 */
void td2ega_effect_tick(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, const td2ega_music_registers *incoming,
    td2ega_music_port_service port, void *context, uint32_t max_steps,
    td2ega_music_tick_result *result);
#endif
