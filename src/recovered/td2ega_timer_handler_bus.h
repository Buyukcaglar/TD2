#ifndef TD2EGA_TIMER_HANDLER_BUS_H
#define TD2EGA_TIMER_HANDLER_BUS_H
#include "td2ega_state_loop.h"
#include "td2ega_music_tick.h"
#include "td2ega_input_flags.h"

typedef struct td2ega_timer_handler_bus_call {
    uint16_t kind,segment,offset,ss,current_sp,flags_word,flags_mask,reserved;
    td2ega_state_registers registers;
} td2ega_timer_handler_bus_call;
typedef struct td2ega_timer_handler_bus_return {
    uint16_t status,current_sp,next_segment,next_ip,flags_word,flags_mask;
    uint32_t bus_writes;
    td2ega_state_registers returned;
} td2ega_timer_handler_bus_return;
typedef int (*td2ega_timer_handler_bus_service)(void *,uint8_t *,uint32_t,
    const td2ega_timer_handler_bus_call *,td2ega_timer_handler_bus_return *);
typedef struct td2ega_timer_handler_bus_services {
    td2ega_music_port_service port;
    td2ega_timer_handler_bus_service call;
    void *context;
    uint16_t undefined_af;
} td2ega_timer_handler_bus_services;
typedef struct td2ega_timer_handler_bus_limits {
    uint32_t steps,calls,ports;
} td2ega_timer_handler_bus_limits;
typedef struct td2ega_timer_handler_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,calls,ports,callbacks,old_interrupts,bus_writes;
    uint16_t flags_word,flags_mask,stage,reserved;
    td2ega_state_registers returned;
} td2ega_timer_handler_bus_result;
/* Additional fullSS roots:0=61BF handler with existing six-byte IRET frame,
 * 1=6230 near bridge. It does not deliver an IRQ. Root0 SP68..FFE0 reserves
 * 18saved bytes+4farCALL bytes+403B minimum46; root1 SP6..FFFA.
 * Actual saved words, IVT writes, far/INT frames and raw returns are retained.
 * kind0 service retires a far callback, kind1 an explicit INT08/IRET adapter;
 * services report actual coordinates/state/writes, never assumed callee-saves.
 * Native0 retired root/1 rawchild/2 invalid/3 budget/4 service/5 unqualified
 * FLAGS/return prefix. No actual callback body or IRQ/lifetime/core admission.
 */
void td2ega_timer_handler_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_timer_handler_bus_limits *,const td2ega_timer_handler_bus_services *,
    td2ega_timer_handler_bus_result *);
#endif
