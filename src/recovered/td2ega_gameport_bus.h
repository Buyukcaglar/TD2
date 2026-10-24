#ifndef TD2EGA_GAMEPORT_BUS_H
#define TD2EGA_GAMEPORT_BUS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_gameport_bus_request {
    uint16_t operation,port,value,segment,ip,ss,sp,zero_flag;
    td2ega_state_registers state;
} td2ega_gameport_bus_request;
typedef int (*td2ega_gameport_bus_service)(void *,const td2ega_gameport_bus_request *,uint8_t *);
typedef struct td2ega_gameport_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t reads,transfers,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_gameport_bus_result;
/* Additional actual SS interfaces:0=6686 sampler,1=680A initializer,
 * 2=6828 oneSSword translator. PlainRETF/caller cleanup; allwordSP admitted
 * through preRETF boundary5 whenSP>FFFC (qualified backend profile only).
 * Serialized1MiB20bitRAM/currentDS-independentSS, native pointers disjoint.
 * Typed byteport201 adapter preserves RAM/GPR/FLAGS; only IN returnsAL.
 * Native0rootreturn/2invalid/3beforeINbudget/4failedadapter/5beforefarRET.
 * IncomingZF is explicit for MOV-only initializer. No actual device/timebase,
 * IRQ/caller-writer-lifetime/full420A-403B/core acceptance. */
void td2ega_gameport_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,const td2ega_state_registers *,uint32_t,
    td2ega_gameport_bus_service,void *,td2ega_gameport_bus_result *);
#endif
