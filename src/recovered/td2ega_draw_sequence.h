#ifndef TD2EGA_DRAW_SEQUENCE_H
#define TD2EGA_DRAW_SEQUENCE_H
#include "td2ega_state_loop.h"
typedef struct td2ega_draw_sequence_request {
    uint16_t kind,site,segment,offset,argument_count,live_argument_count;
    uint16_t stack_segment,stack_sp,arguments[16];
    td2ega_state_registers incoming;
} td2ega_draw_sequence_request;
typedef int (*td2ega_draw_sequence_service)(void *,uint8_t *,
    const td2ega_draw_sequence_request *,td2ega_state_registers *);
typedef struct td2ega_draw_sequence_result {
    uint16_t status,current_sp,return_bytes;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_draw_sequence_result;
/* Plain-near entries26D8/284F/28F9. Native entry0/1/2, status0normal,
 *2invalid/3callbudget/4servicefailure. Serializedsharedbus; virtualSSframe
 *pools separatefromdata/code. Leaf ABI explicit, no actualdraw/hardware claim. */
void td2ega_draw_sequence(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_draw_sequence_service,
    void *,uint32_t,td2ega_draw_sequence_result *);
#endif
