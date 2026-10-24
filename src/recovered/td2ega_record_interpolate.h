#ifndef TD2EGA_RECORD_INTERPOLATE_H
#define TD2EGA_RECORD_INTERPOLATE_H
#include "td2ega_line_step.h"
typedef struct td2ega_record_interpolate_result {
    uint16_t status,stack_segment,current_sp,return_bytes;
    uint32_t work,iterations,helper_calls,attribute_words,line_words;
    td2ega_state_registers returned;
} td2ega_record_interpolate_result;
/* 2477 plainnearRET2, currentSI fieldsDS/previousBP fieldsSS, ES=DS/DF0.
 * Fivepreparedtriplets consumed inreverseorder byactualnative06C3 RET6.
 * Data/controlframes/code separateexceptauthored06C3opcode writes.
 * Work counts outerrecords/attributeREPwords/childlinework; budget3 isprefix,
 * notoriginalreturn/error. Actualcaller/record/outputbounds remainopen. */
void td2ega_record_interpolate(uint8_t *memory,uint32_t memory_bytes,
    uint16_t load_segment,uint16_t stack_segment,uint16_t entry_sp,
    const td2ega_state_registers *incoming,uint32_t max_work,
    td2ega_record_interpolate_result *result);
#endif
