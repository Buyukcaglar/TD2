#ifndef TD2EGA_RUNTIME_MESSAGE_H
#define TD2EGA_RUNTIME_MESSAGE_H
#include "td2ega_small_platform.h"
typedef struct td2ega_runtime_message_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t operations,rows,services,bus_writes;
    td2ega_state_registers returned;
} td2ega_runtime_message_result;
/*0=13A8:088C rawmessage lookup;1=08B7 actuallookup+syntheticDOS40 output.
 * OneSSword, literalRETF2 callee cleanup, incomingDF retained; actualnestedSS.
 * Native0rootfarreturn/1rawchildfarreturn/2invalid/3before-element-or-INTprefix/
 *4adapterfailure. Catalog/NUL/caller/writer/lifetime/core/device/session gates
 * separate; no originalmessage payload embedded orhost string substitution. */
void td2ega_runtime_message(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_small_platform_service,
    void *,uint32_t,td2ega_runtime_message_result *);
#endif
