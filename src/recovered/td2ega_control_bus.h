#ifndef TD2EGA_CONTROL_BUS_H
#define TD2EGA_CONTROL_BUS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_control_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_control_bus_result;
/* Actualnear0=4588,1=44D8,2=45BF,3=4612,4=45FC; rawDSfields/table,
 * GPR/BP/CFIFDF, fullSSincludingactual460EnearCALL4612/RET2.
 * Native0rootRET/1rawchildRET/2invalid/3before460ECALLprefix.
 * SP18..FFE0. Existinggroup APIs/sources remainfrozen/separatelybounded.
 * Actualcaller/writers/units/lifetime/IRQ/core/resource gates separate. */
void td2ega_control_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_control_bus_result *);
#endif
