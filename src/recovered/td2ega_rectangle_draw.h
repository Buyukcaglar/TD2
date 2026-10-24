#ifndef TD2EGA_RECTANGLE_DRAW_H
#define TD2EGA_RECTANGLE_DRAW_H
#include "td2ega_line_draw.h"
/* Entry0clipped89A2/1raw8A0C, plainfarRETF4. SSargs x/y/width/height/color
 * canbemutatedinplacebyclipping andwideRAMcolor-shifts. Usesline-draw
 * explicitbyteOUT/deviceRead/deviceWrite ABI; nofarleaf. VirtualSSlocals/
 * savedcontrolframes separatefromdata/code, callerargwritesobservable.
 * Native0return/2invalid/3workbudget/4servicefailure; noactualrenderergate. */
void td2ega_rectangle_draw(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_line_draw_result *);
#endif
