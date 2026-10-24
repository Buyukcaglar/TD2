#ifndef TD2EGA_MODE_CONTROLLER_H
#define TD2EGA_MODE_CONTROLLER_H
#include "td2ega_record_dispatch.h"
#include "td2ega_control_bus.h"
typedef struct td2ega_mode_controller_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,nested_calls,iterations,bus_writes;
    uint16_t raw_target,dispatch_site,dispatch_offset,exit_kind;
    td2ega_state_registers returned;
} td2ega_mode_controller_result;
/* Actual06C9:53A6 near/noargs, actual56ED/4612 children/5446tail/fullSS.
 * SP36..FFE0 preserves56ED34; mode7PUSHAX/CALL/POPAX allactualSS.
 * Mutable5514/55A1 andchild57A7JMPs retainactualoperand; unsupportedtarget
 * native6beforeJMP, no sourceerror/domainclosure. Knownblockretargets followed.
 * Native0rootRET/1rawchildRET/2invalid/3CALL-loopbudget/6unknownJMP.
 * exit_kind1 is56EDPOPAX+RETnonlocalparentexit, noadditionalrootRET.
 * RootCALL/leafCALL/iteration budgets distinct. Allwriters/caller/core open. */
void td2ega_mode_controller(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,uint32_t,
    td2ega_mode_controller_result *);
#endif
