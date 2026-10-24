#ifndef TD2EGA_KEYBOARD_BIOS_BUS_H
#define TD2EGA_KEYBOARD_BIOS_BUS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_keyboard_bios_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t bus_writes;
    uint16_t zero_flag,flags_valid,return_kind,reserved;
    td2ega_state_registers returned;
} td2ega_keyboard_bios_bus_result;
/* Actual06C9:69B7 with SS interrupt frame IP/CS/FLAGS, inheritedentryGPR/CFIFDF.
 * PUSHBX/PUSHDS precedeprincipalDSreads; actualpop/return/aliasesretained.
 * Native0rootreturn/2invalid/5beforeunqualifiedreturn-boundary. AH1RETF2
 * usesORAXflags/IF1; otherAH useIRET/savedflags. AllwordSP admitted through
 * prefix5:RETF2 SP>FFFC orIRET SP>FFFA. OnlyCFZFIFDF are exposed; otherFLAGS,
 * actualINTdelivery/IRQ/caller-writers-lifetime/core domains remainopen. */
void td2ega_keyboard_bios_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_keyboard_bios_bus_result *);
#endif
