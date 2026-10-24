#ifndef TD2EGA_MASK_SPAN_H
#define TD2EGA_MASK_SPAN_H
#include "td2ega_line_draw.h"
/* Nativeentries0..5 =82D0/8336/839C/AD22/AD8B/ADF4, plainnearRET2.
 * ImplicitAX/BX/CX/DX/SI/DI/ES, externalCSmaskbytes, DFpreserved.
 * Deviceentries useexplicitbyteRead/Write services; noportoperations.
 * Native0return/2invalid/3workprefix/4servicefailure; noactualdevicegate. */
void td2ega_mask_span(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_line_draw_result *);
#endif
