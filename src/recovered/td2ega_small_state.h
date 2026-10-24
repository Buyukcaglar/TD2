#ifndef TD2EGA_SMALL_STATE_H
#define TD2EGA_SMALL_STATE_H
#include "td2ega_state_loop.h"
typedef struct td2ega_small_state_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t reads,writes;
    td2ega_state_registers returned;
} td2ega_small_state_result;
/* Entry selectors follow the documented function map; complete finite bodies,
 * serialized1MiB raw segmented bus, materialized SS frames. Status0 ordinary
 * originalreturn/2invalid native profile. Raw external086C counter/source units,
 * caller ownership, IRQ/device/session/core acceptance remain separate. */
void td2ega_small_state(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_small_state_result *);
#endif
