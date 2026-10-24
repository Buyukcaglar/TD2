#ifndef TD2EGA_STREAM_RECORDS_H
#define TD2EGA_STREAM_RECORDS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_stream_records_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_stream_records_result;
/*0=13A8:0F16 specialrecord/sideflags setup,1=2170 rawbyte-membership,
 *2=219A raw8byterecord scan/reset. ActualSS/currentDS/orderedaliases,
 * signedbyte*6/wordwrap andold-SI endtest retained. PlainfarRETF4/callerclean.
 * Native0returnoperation/2invalid/3before-scanprefix. Caller/bounds/writer/
 * lifetime/otherFLAGS/core/resource-fed/device/game gates separate. */
void td2ega_stream_records(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_stream_records_result *);
#endif
