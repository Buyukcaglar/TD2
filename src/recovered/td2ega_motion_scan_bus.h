#ifndef TD2EGA_MOTION_SCAN_BUS_H
#define TD2EGA_MOTION_SCAN_BUS_H
#include "td2ega_signed_motion.h"
#include "td2ega_state_loop.h"
typedef struct td2ega_motion_scan_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    uint16_t zero_flag,flags_valid,unresolved_target,reserved;
    td2ega_state_registers returned;
} td2ega_motion_scan_bus_result;
/* Additional actual SS interfaces:0=06B3:0008 far/noargs/SP20..FFE0,
 * 1=13A8:2EE8 far/fourSSwords/RETF8/SP0..FFFF,2=06C9:44A6 near/SP0..FFFE.
 * max_calls caps the one actual motion->multiply CALL. CurrentDS and ES may
 * differ from SS. Scanner recognizes three action targets plus44BE RET tail;
 * unknown raw words stop before JMP. Native0rootRET,1rawchildRET neverfollowed,
 * 2invalid,3beforeCALL,4beforeunknownJMP,5beforefarRET with SP>FFFC (bounded
 * backend profile, not historical CPU qualification). NormalZF is valid except
 * standalone fast MUL (undefinedZF). No whole420A/403B/writer/IRQ/core admission.
 */
void td2ega_motion_scan_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_motion_scan_bus_result *);
#endif
