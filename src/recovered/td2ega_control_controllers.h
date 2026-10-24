#ifndef TD2EGA_CONTROL_CONTROLLERS_H
#define TD2EGA_CONTROL_CONTROLLERS_H
#include "td2ega_control_bus.h"
typedef struct td2ega_control_controllers_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,nested_calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_control_controllers_result;
/* Actualnear0=5A6F rawcounter/field controller,1=44EA field/table controller.
 * Actualcontrol_bus children/nearframes/directtailJMP/rootRET2, SP20..FFE0.
 * Native0rootRET/1rawnestedRET/2invalid/3beforeCALLorinner460Eprefix.
 * RootCALLbudget andchildnestedCALLbudget independent. FullSS/CFIFDF.
 * Actualcaller/writers/units/IRQ/lifetime/core/resource gates separate. */
void td2ega_control_controllers(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,uint32_t,
    td2ega_control_controllers_result *);
#endif
