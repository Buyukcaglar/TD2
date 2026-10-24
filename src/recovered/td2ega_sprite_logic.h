#ifndef TD2EGA_SPRITE_LOGIC_H
#define TD2EGA_SPRITE_LOGIC_H
#include "td2ega_sprite_draw.h"
/* Entry0=7DBC/AND,1=A718/OR,2=BB08/XOR. TwoSSwords[sourceOffset,segment];
 * sourceheader8/A coordinates. Originalmode/flags, frame/local writes,
 * dispatch andnear-mask helpers retained. Syntheticbytebus adapter; actual
 * caller/writer/lifetime/device/core gates separate. Resultstatuses retain
 * sprite_draw meanings, including distinct rawindirect/workprefix outcomes. */
void td2ega_sprite_logic(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_sprite_draw_result *);
void td2ega_sprite_logic_kernel(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_sprite_draw_result *);
#endif
