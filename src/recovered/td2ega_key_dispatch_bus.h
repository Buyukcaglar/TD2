#ifndef TD2EGA_KEY_DISPATCH_BUS_H
#define TD2EGA_KEY_DISPATCH_BUS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_key_dispatch_bus_request {
    uint16_t site,target_segment,target_ip,stack_segment,stack_sp;
    td2ega_state_registers incoming;
} td2ega_key_dispatch_bus_request;
typedef struct td2ega_key_dispatch_bus_response {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t bus_writes;
    td2ega_state_registers returned;
} td2ega_key_dispatch_bus_response;
/* Service executes a callback through its return or explicitprefix. Status0
 * reports retiredfarRET/control;1/3/4/5 are rawchild/budget/service/boundary
 * prefixes. SS is inherited; exactSP/control/state/CPUwrites are returned.
 * Maywrap an actual recoveredbody; ABI fixture service isnot bodyproof. */
typedef int (*td2ega_key_dispatch_bus_service)(void *,uint8_t *,
    const td2ega_key_dispatch_bus_request *,td2ega_key_dispatch_bus_response *);
typedef struct td2ega_key_dispatch_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    uint16_t zero_flag,flags_valid,callback_target,reserved;
    td2ega_state_registers returned;
} td2ega_key_dispatch_bus_result;
/* Additional6528 far/oneSSkeyword/caller-clean/full1MiB20bitRAM/currentDS.
 * ActualPUSHBP/guard/SSargumentrewrite/savedDI-SI/PUSHCS-nearCALLBX andpops.
 * Native0rootRETF/1rawchildreturn-neverfollowed/2invalid/3beforeCALL-orchild
 * budget/4adapterfailure/5preunqualifiedfarRETSP>FFFC-orchildboundary.
 * AllwordSP admittedthroughprefixes; normalCFZF explicit. Callbackbodies,
 * alltablewriters/caller-DS-SS-capacity-lifetime-exclusion/IRQ/core remainopen.
 */
void td2ega_key_dispatch_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_key_dispatch_bus_service,
    void *,td2ega_key_dispatch_bus_result *);
#endif
