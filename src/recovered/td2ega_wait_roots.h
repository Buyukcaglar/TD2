#ifndef TD2EGA_WAIT_ROOTS_H
#define TD2EGA_WAIT_ROOTS_H
#include "td2ega_input_bridge.h"
#include "td2ega_wait_control.h"
#include "td2ega_small_state.h"
typedef struct td2ega_wait_roots_counter_request {
    uint16_t site,segment,offset,stack_segment,stack_sp;
    td2ega_state_registers incoming;
} td2ega_wait_roots_counter_request;
typedef int (*td2ega_wait_roots_observer)(void *,uint8_t *,
    const td2ega_wait_roots_counter_request *);
typedef struct td2ega_wait_roots_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t events,input_calls,counter_calls,dynamic_calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_wait_roots_result;
/*0=6A30 inputnonzero,1=6A4A input/79C8 lexbound,2=7A3B single79C8 predicate,
 *3=C63E input/C692 highANDlow bounds. ActualchildC bodies andSSfarframes;
 * inputdynamiccallee explicitABI service, observeronlysyntheticcounterbusupdates.
 * Native0rootRETF4/1unexpectedchildreturn/2invalid/3before-callbudget/4adapter
 * failure separate. Inputservicepreservesdynamicreturnframe; unusedinput or
 * observermaybenull forcounter-only/input-onlyroot. Nofrequency/IRQ/core claim. */
void td2ega_wait_roots(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_input_bridge_service,
    td2ega_wait_roots_observer,void *,uint32_t,td2ega_wait_roots_result *);
#endif
