#ifndef TD2EGA_FIELD_TEXT_H
#define TD2EGA_FIELD_TEXT_H
#include "td2ega_string_memory.h"
typedef struct td2ega_field_text_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_operations,iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_field_text_result;
/* Actual0432:0006 far/twoSSnearoffsets output/input; actual2956 far child,
 * literalSSlocals/saves/frames/orderedtrimandspace-to-underscore stores.
 * SP30..FFE0 preserveschild16 afteractualarguments/farframe. IncomingDF.
 * Native0actualrootfarRET/1rawchildRET/2invalid/3CALL-operation-loopbudget.
 * No stringcapacity/format/caller/lifetime/IRQ/core/session acceptance. */
void td2ega_field_text(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,uint32_t,
    td2ega_field_text_result *);
#endif
