#ifndef TD2EGA_INPUT_FIELDS_BUS_H
#define TD2EGA_INPUT_FIELDS_BUS_H
#include "td2ega_control_bus.h"
typedef struct td2ega_input_fields_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_input_fields_bus_result;
/* Additional actual SS interfaces: 0=4281,1=43C3,2=4441,3=448A.
 * prepared42AD 0=originalJA,1=preparedJNE; no executing code mutation here.
 * Entries0/1 SP20..FFE0, actualnear4612/4441 frames; leaves2/3 SP0..FFFE.
 * max_calls caps both near children cumulatively. Native0rootRET/1rawchild
 * RETneverfollowed/2invalid/3beforeCALLprefix. OnlynormalrootZFvalid.
 * No whole420A/403B/mutator-transitions/writer-domain/IRQ/core acceptance. */
void td2ega_input_fields_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,const td2ega_state_registers *,uint32_t,
    td2ega_input_fields_bus_result *);
#endif
