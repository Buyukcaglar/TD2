#ifndef TD2EGA_EDGE_SEQUENCE_H
#define TD2EGA_EDGE_SEQUENCE_H
#include "td2ega_draw_sequence.h"
/* Actual34DCnearRET2; reusesexplicitdraw-request5arg/live15wordABI.
 * Two or three preparedfar8582calls withcallerADDSP10. Nativecallbudget
 * separatefromoriginalreturn, virtualSSpools requireframe/data separation. */
void td2ega_edge_sequence(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_draw_sequence_service,void *,
    uint32_t,td2ega_draw_sequence_result *);
#endif
