#ifndef TD2EGA_PLANE_SPAN_H
#define TD2EGA_PLANE_SPAN_H
#include "td2ega_state_loop.h"
typedef struct td2ega_plane_span_request {
    uint16_t site,segment,offset,stack_segment,stack_sp,arguments[5];
    td2ega_state_registers incoming;
} td2ega_plane_span_request;
typedef int (*td2ega_plane_span_service)(void *,uint8_t *,
    const td2ega_plane_span_request *,td2ega_state_registers *);
typedef struct td2ega_plane_span_result {
    uint16_t status,current_sp,next_ip;
    uint32_t writes,calls;
    td2ega_state_registers returned;
} td2ega_plane_span_result;
/* Nativeentry0=C17/1=D01, status0nearRET/1discardnearreturn-JMPDS0702,
 *2invalid/4servicefailure. Explicitserialized20bitbus andvirtualSSframes.
 * Plane wordsarecurrentDS; BP+5468maskbytesuseexplicitSS; nohardware/renderergate.
 * C17supportsDFinbothdirections; D01far8582serviceisordinaryreturnonly. */
void td2ega_plane_span(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_plane_span_service,void *,
    td2ega_plane_span_result *);
#endif
