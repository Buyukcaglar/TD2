#ifndef TD2EGA_LINE_DRAW_H
#define TD2EGA_LINE_DRAW_H
#include "td2ega_state_loop.h"
typedef struct td2ega_line_draw_request {
    uint16_t kind,site,segment,offset,stack_segment,stack_sp;
    uint16_t port,value,arguments[5];
    uint32_t address;
    td2ega_state_registers incoming;
} td2ega_line_draw_request;
typedef struct td2ega_line_draw_response {
    td2ega_state_registers returned;
    uint16_t value;
} td2ega_line_draw_response;
typedef int (*td2ega_line_draw_service)(void *,uint8_t *,
    const td2ega_line_draw_request *,td2ega_line_draw_response *);
typedef struct td2ega_line_draw_result {
    uint16_t status,fault_site,current_sp;
    uint32_t work,iterations,calls,writes;
    td2ega_state_registers returned;
} td2ega_line_draw_result;
/* 8582plainfarRETF4, SSfivewordcallerargs, DS=CS whiledrawing thenrestore
 * DS/SI/DI/BP. Explicit0far8A0C/1byteOUT/2devicebyteRead/3devicebyteWrite.
 * Port/device services preserveGPR/flags; onlyfarleaf mayreturnregisters.
 * Native0normal/1actualDIVfaultprefix/2invalid/3budget/4servicefailure.
 * Work counts sixloopheads andserviceevents; virtualSSlocals/controlframes
 * separatefromdata/code. RAMplanes/explicitadapters do notadmitEGAhardware,
 * actualrenderer/resourcecapacities/callerstate/core/game/fidelity. */
void td2ega_line_draw(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_line_draw_result *);
#endif
