#ifndef TD2EGA_LOOP_CONTROLS_H
#define TD2EGA_LOOP_CONTROLS_H
#include "td2ega_state_loop.h"
enum td2ega_loop_control_entry { TD2EGA_LOOP_1F60,TD2EGA_LOOP_1F71,TD2EGA_LOOP_1F99 };
typedef struct td2ega_loop_control_request {
    uint16_t kind,site,segment,offset,argument_count,live_argument_count;
    uint16_t stack_segment,stack_sp;
    uint16_t arguments[10];
    td2ega_state_registers incoming;
} td2ega_loop_control_request;
typedef int (*td2ega_loop_control_service)(void *context,uint8_t *memory,
    const td2ega_loop_control_request *request,td2ega_state_registers *returned);
typedef struct td2ega_loop_control_result {
    uint16_t status,current_sp,return_bytes;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_loop_control_result;
/* Three complete orchestration bodies. Kind0 nearRET2, kind1 farRETF4.
 * Live5+5word arguments androot SI/DS/BP restoration explicit. Nativeframes
 * virtual; services preserveSS/SP/controlframes/callerwords, useprovidedargs.
 * CurrentDS/CS views andCFIFDF only; actualgraphics/nearleafbodies separate. */
void td2ega_loop_control(uint8_t *memory,uint32_t memory_bytes,
    uint16_t load_segment,uint16_t stack_segment,uint16_t entry_sp,
    enum td2ega_loop_control_entry entry,const td2ega_state_registers *incoming,
    td2ega_loop_control_service service,void *context,uint32_t max_calls,
    td2ega_loop_control_result *result);
#endif
