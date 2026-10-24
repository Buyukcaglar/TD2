#ifndef TD2EGA_LINE_STEP_H
#define TD2EGA_LINE_STEP_H
#include "td2ega_state_loop.h"
typedef struct td2ega_line_step_result {
    uint16_t status,stack_segment,current_sp,return_bytes,opcode_first,opcode_second;
    uint32_t work,words;
    td2ega_state_registers returned;
} td2ega_line_step_result;
/* 06C3 original3SSargumentwords suppliedexplicitly: destination/second/first.
 * ImplicitCX=count,DX=denominator, DS5348=initialbound, ES:DIoutput/DFstep.
 * NearRET6 has8byte totalreturnextent. AuthoredCS071F/0735 writes persist.
 * Serializeddirectentry, othercode/data/liveSSframes/callerwords separate.
 * Work ticks initial/REP word writes, eachcodepatch andinnerarithmetic step;
 * nativebudget3/invalid2 outsideoriginalnormal/error equivalence. */
void td2ega_line_step(uint8_t *memory,uint32_t memory_bytes,
    uint16_t load_segment,uint16_t stack_segment,uint16_t entry_sp,
    uint16_t destination,uint16_t second_endpoint,uint16_t first_endpoint,
    const td2ega_state_registers *incoming,uint32_t max_work,
    td2ega_line_step_result *result);
#endif
