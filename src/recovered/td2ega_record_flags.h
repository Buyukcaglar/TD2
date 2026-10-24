#ifndef TD2EGA_RECORD_FLAGS_H
#define TD2EGA_RECORD_FLAGS_H
#include "td2ega_record_math.h"
typedef struct td2ega_record_flags_result {
    td2ega_record_math_result body;
    uint16_t defined_flags,defined_mask,return_site;
} td2ega_record_flags_result;
/* Actual4F92 via frozenrecord_math selector3. Preview onlyreads serialized
 * flatRAM toclassify initialreject/skip/update, then actualbody executes.
 * Normalreturn computes source-defined statusFLAGS, IF/DF andbit1;
 * XOR-final updatepath excludes undefinedAF frommask. Budgetprefix only
 * exposesCF/IF/DF/bit1. Otherbits areplaceholders, not rawPUSHF image.
 * ParentmustsupplyCPU/reserved/undefinedFLAGS andflagword ownership
 * contract before materializingPUSHF/POPF. No IRQ/wholeparent/core proof. */
void td2ega_record_flags(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_record_flags_result *);
#endif
