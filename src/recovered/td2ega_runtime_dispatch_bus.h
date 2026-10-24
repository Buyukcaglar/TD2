#ifndef TD2EGA_RUNTIME_DISPATCH_BUS_H
#define TD2EGA_RUNTIME_DISPATCH_BUS_H
#include "td2ega_runtime_exit.h"
#include "td2ega_runtime_message.h"
#include "td2ega_input_flags.h"
typedef struct td2ega_runtime_dispatch_request {
    uint16_t kind,site,target_segment,target_ip,stack_segment,stack_sp;
    uint16_t flags_word,flags_mask;
    td2ega_state_registers incoming;
} td2ega_runtime_dispatch_request;
typedef struct td2ega_runtime_dispatch_response {
    uint16_t status,current_sp,next_segment,next_ip,flags_word,flags_mask;
    uint32_t bus_writes;
    td2ega_state_registers returned;
    td2ega_small_platform_request exit_request;
} td2ega_runtime_dispatch_response;
typedef int (*td2ega_runtime_dispatch_service)(void *,uint8_t *,uint32_t,
    const td2ega_runtime_dispatch_request *,td2ega_runtime_dispatch_response *);
typedef struct td2ega_runtime_dispatch_services {
    td2ega_small_platform_service dos;
    td2ega_runtime_dispatch_service handler;
    td2ega_finalizer_service finalizer;
    void *context;
} td2ega_runtime_dispatch_services;
typedef struct td2ega_runtime_dispatch_limits {
    uint32_t steps,calls,message_operations,exit_operations;
} td2ega_runtime_dispatch_limits;
typedef struct td2ega_runtime_dispatch_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,calls,services,callbacks,bus_writes;
    uint16_t flags_word,flags_mask,stage,halt_site,raw_target,raw_segment;
    td2ega_state_registers returned;
    td2ega_small_platform_request exit_request;
} td2ega_runtime_dispatch_result;
/* Additional actualSS entries0=2D57 lookup,1=2C1C dispatch,2=29F6 wrapper.
 * SourceSP>=2/92/100 respectively, maxFFE0 for1/2; qualifiedpreRET0 uses7.
 * Native0 retiredfarroot/no follow,1 rawchild,2 invalid,3 budget,4 adapter,
 * 5 preparedprocess-exit boundary,6 unknownliteralCSword beforeJMP,7 preRET.
 * stage0 root,1 lookupchild,2 customhandler,3 SS707Efallback,4 innerexit,
 * 5 message08B7,6 wrapper2C1C,7 finalexit. Typedhandlers and DOS are explicit
 * profiles, not actual bodies/devices. Old runtime_exit stopsbefore05DE INT.
 * Steps charge each familyentry/lookuphead/metadata store/ownINT request;
 * calls charge familyCALLsites, delegated helper operations have ownlimits.
 */
void td2ega_runtime_dispatch_bus(uint8_t *,uint32_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_runtime_dispatch_limits *,
    const td2ega_runtime_dispatch_services *,td2ega_runtime_dispatch_result *);
#endif
