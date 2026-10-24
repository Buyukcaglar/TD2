#ifndef TD2EGA_RECORD_CONTROLLER_H
#define TD2EGA_RECORD_CONTROLLER_H
#include "td2ega_record_flags.h"
typedef struct td2ega_record_controller_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,calls,child_iterations,bus_writes,flag_words_written;
    uint16_t defined_flags,defined_mask,last_pop_flags,first_return_site;
    td2ega_state_registers returned;
} td2ega_record_controller_result;
/* Actual06C9:4D3F near/noargs + actual4F92/5022/5446 C bodies.
 * undefined_af is caller-supplied0/1 at the one PUSHF if AF is undefined;
 * selected real16 analysis CPU profile has TF/IOPL/NT/reserved bitszero,
 * bit1set. No actualCPU AF policy inferred. LiteralSSPUSHF/POPF preserves
 * flagword data/aliases, consumedCF/ZF/IF/DF, and actualnearframes/RET2.
 * RootSP>=20 ensures all frozenchildrenSP>=16.
 * Native0rootRET/1rawchildRET/2invalid/3before-loop-or-CALL/5beforePOPF
 * unsupportedTF/IOPL/NT context. Prefix is not sourceerror/normalreturn.
 * CPU-profile binding, fullcaller/writer/lifetime/IRQ/core gates separate. */
void td2ega_record_controller(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint16_t,uint32_t,uint32_t,
    td2ega_record_controller_result *);
#endif
