#ifndef TD2EGA_INPUT_POLL_BUS_H
#define TD2EGA_INPUT_POLL_BUS_H
#include "td2ega_keyboard_bios_bus.h"
#include "td2ega_key_dispatch_bus.h"
#include "td2ega_gameport_bus.h"
#include "td2ega_input_flags.h"
typedef struct td2ega_input_poll_bus_limits {
    uint32_t calls,bios_calls,callback_calls,port_reads;
} td2ega_input_poll_bus_limits;
typedef struct td2ega_input_poll_bus_services {
    td2ega_key_dispatch_bus_service key;void *key_context;
    td2ega_gameport_bus_service port;void *port_context;
    uint16_t undefined_af;
} td2ega_input_poll_bus_services;
typedef struct td2ega_input_poll_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bios_calls,callback_calls,port_reads,port_transfers,bus_writes;
    uint16_t flags_word,flags_mask,zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_input_poll_bus_result;
/* Additional actualSS roots0=65C5,1=6601,2=6620. INT16 uses explicitserialized
 * FLAGS-CS-IP frame/IF-TFentryprofile andactual69B7, notrealIVTdelivery.
 * IncomingrawFLAGS:bit1set, bitsoutside0ED7zero; validityFFFF orFFEF, tracked
 * CF/IF/DF agreeState. Undefinedlogic/shift AF isexplicitchoice0/1, maskexcludes
 * it; neverclaimed historicaldefinedAF. Keyservice preservesunexposed system
 * FLAGS profile; sourceADDSP2 redefinesarithflags afterdispatch.
 * AllwordSP throughprefixes; native0rootRETF/1rawchild-neverfollowed/2invalid/
 * 3beforeINT-CALL-orchildbudget/4adapter/5unqualifiedreturnboundary.
 * FullRAM/flags-wordvalidity differfromIRQ/installer/caller/core acceptance.
 */
void td2ega_input_poll_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_input_poll_bus_limits *,const td2ega_input_poll_bus_services *,
    td2ega_input_poll_bus_result *);
#endif
