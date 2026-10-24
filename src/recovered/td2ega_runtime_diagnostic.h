#ifndef TD2EGA_RUNTIME_DIAGNOSTIC_H
#define TD2EGA_RUNTIME_DIAGNOSTIC_H
#include "td2ega_runtime_message.h"
#include "td2ega_finalizer_list.h"
typedef struct td2ega_runtime_diagnostic_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t operations,rows,services,callbacks,bus_writes;
    td2ega_state_registers returned;
} td2ega_runtime_diagnostic_result;
/*0=13A8:0620 actualFC/FF messages andoptional DS6DCC:6DCE callback;
 *1=066E raw66-byte XOR checksum plusactual0620/message1 onmismatch.
 * ValidchecksumAH0 returnslastbyteinAL, notBoolean; CLD retained.
 * Native0rootfarreturn/1rawchildfarreturn/2invalid/3prefix/4adapterfailure.
 * Actualcallbackbody/catalog/writers/FLAGS/lifetime/core/platform gates open. */
void td2ega_runtime_diagnostic(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_small_platform_service,
    td2ega_finalizer_service,void *,uint32_t,td2ega_runtime_diagnostic_result *);
#endif
