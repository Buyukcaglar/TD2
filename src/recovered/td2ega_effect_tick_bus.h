#ifndef TD2EGA_EFFECT_TICK_BUS_H
#define TD2EGA_EFFECT_TICK_BUS_H
#include "td2ega_state_loop.h"
#include "td2ega_input_flags.h"
typedef struct td2ega_effect_tick_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,ports,bus_writes;
    uint16_t flags_word,flags_mask,halt_site,raw_target;
    td2ega_state_registers returned;
} td2ega_effect_tick_bus_result;
/* Additional6269 far/noargs, currentDS/inheritedSS/whole20bitRAM interface.
 * No own saved words or CALLs. Actual SS far words read after body effects;
 * native0 reports retired root coordinates without following,2invalid,
 * 3budget,4port service,5preRET qualification for SP>FFFC,
 * 6unknown current CS:6334 command-table target before JMP; never followed.
 * Flags use bit1/0ED7 and maskFFFF/FFEF; undefined logic/SHL AF masked.
 * SHR flags are dead before the next XORBH; no fabricated observable flags.
 * Own CPU writes counted; port-adapter bus changes remain separate effects.
 * No actualIRQ/nesting/source-lifetime/completeaudio/core/game acceptance.
 */
void td2ega_effect_tick_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,const td2ega_state_registers *,td2ega_music_port_service,
    void *,uint32_t,uint32_t,td2ega_effect_tick_bus_result *);
#endif
