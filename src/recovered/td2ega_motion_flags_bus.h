#ifndef TD2EGA_MOTION_FLAGS_BUS_H
#define TD2EGA_MOTION_FLAGS_BUS_H
#include "td2ega_signed_motion.h"
#include "td2ega_state_loop.h"
#include "td2ega_input_flags.h"
typedef struct td2ega_motion_flags_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    uint16_t zero_flag,flags_valid,unresolved_target,reserved;
    uint16_t flags_word,flags_mask;
    td2ega_state_registers returned;
} td2ega_motion_flags_bus_result;
/* Additional06B3:0008/fullSS/actual2EE8-RETF8; rootplainRETF/SP20..FFE0.
 * CaptureterminalCMP orSUB operandsbeforeconditionalclampwrites; noflags
 * reconstructionfrompostclampRAM. NormalfullarithFLAGS andbefore114CALL
 * prefix fullydefined; otherchildprefixes conservativelymasked. IFDF
 * preserved. Incomingwordprofile0ED7/bit1/maskFFFForFFEF/Stateconsistent.
 * Native0rootRET/1rawchild/2invalid/3beforeCALL/5unqualifiedreturnprefix.
 * OldAPIs-C-H-DLL-receiptsfrozen; whole420A-403B/caller-IRQ/core remainopen. */
void td2ega_motion_flags_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,uint16_t,const td2ega_state_registers *,uint32_t,
    td2ega_motion_flags_bus_result *);
#endif
