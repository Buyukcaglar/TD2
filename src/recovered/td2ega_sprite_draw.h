#ifndef TD2EGA_SPRITE_DRAW_H
#define TD2EGA_SPRITE_DRAW_H
#include "td2ega_mask_span.h"
typedef struct td2ega_sprite_draw_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,iterations,calls,writes,mask_calls,dispatches;
    td2ega_state_registers returned;
} td2ega_sprite_draw_result;
/* 916C/91A4:SSfourwords[sourceOffset,segment,x,y].91D6:SStwowords
 *[sourceOffset,segment], coordinatesfromsourceheader+8/+A.
 * MaterializedSSsaved/localframes, originalnear maskcalls andfarRETF4.
 * Native0farreturn/1rawunsupported-indirectboundary/2invalid/3workprefix/
 *4servicefailure. ReadexternalCSdispatch/mask/selectiondata, explicitbytebus
 * adapter. Copykernels selectedby9562/9572supported; otherrawtargetsreturned
 * distinctly, nooriginalerror/normalreturn invented. Actualcaller/writer/
 * frame/capacity/device/IRQ/core/resourcefed acceptance remainsseparate. */
void td2ega_sprite_draw(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_sprite_draw_result *);
/* Resume reviewedcopykernel withoriginalSS/BP/frame/DS/ES/GPRstate. Usedfor
 * independentkernel contractvectors; noprologueorresourceidentityinference. */
void td2ega_sprite_kernel(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_sprite_draw_result *);
#endif
