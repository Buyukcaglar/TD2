#ifndef TD2EGA_INPUT_UPDATE_BUS_H
#define TD2EGA_INPUT_UPDATE_BUS_H
#include "td2ega_input_poll_bus.h"
#include "td2ega_input_fields_bus.h"
#include "td2ega_motion_flags_bus.h"
#include "td2ega_motion_scan_bus.h"
#include "td2ega_mutable_control.h"

typedef struct td2ega_input_update_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bios_calls,callback_calls,port_reads,port_transfers,bus_writes;
    uint16_t stage,unresolved_target,zero_flag,flags_valid,flags_word,flags_mask;
    td2ega_state_registers returned;
} td2ega_input_update_bus_result;
/* Additional complete near420A/actualSS interface, SP24..FFE0. Explicit
 * immutable424A/4275JBE-orJNE and42ADJA-orJNE forms; realcodewrites excluded.
 * Serialized20bitRAM/currentDS-independentSS anddisjointnativepointers.
 * RawentryFLAGS profile matches input_poll_bus. Real69B7 body withmodeledINT
 * frames, actual6528/6686/6828/fields/motion/multiply/scanner, keycallback ABI
 * service remains explicit. Calls budget counts root+component directCALLs;
 * callbackCALLs have separatebudget. Existing limits/services reused.
 * Flagsmask afterpartial-field/scanner interfaces isconservative; exactfull
 * motionFLAGS feed6601 beforeitsINT16 savedFLAGSword. Native0rootnearRET,
 * 1rawchildneverfollowed,2invalid,3beforeCALL/INT/INbudget,4adapterfailure,
 * 5unqualifiedreturnboundary,6beforeunknownscannerJMP. Notwhole403B/IRQ/core.
 */
void td2ega_input_update_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_mutable_control *,const td2ega_input_poll_bus_limits *,
    const td2ega_input_poll_bus_services *,td2ega_input_update_bus_result *);
#endif
