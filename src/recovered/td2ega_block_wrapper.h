#ifndef TD2EGA_BLOCK_WRAPPER_H
#define TD2EGA_BLOCK_WRAPPER_H
#include "td2ega_block_request.h"
typedef struct td2ega_block_wrapper_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_calls,services,records,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_block_wrapper_result;
/* Actual13A8:2830 near/noSSargs/inputAXrawsize/DSkey/ESmetadataDS.
 * Actual2852far/fullSS/fiveargs, savedAXpoppedintoDX/actualDS-BXrestores.
 * SP30..FFE0 preserveschild12. Native0actualnearRET/1rawchildfarRET/
 * 2invalid/3budget/4adapterfailure. OnrootRET flags_valid1/zero_flag is
 * actualZF requiredby26BDJNE/2813JE, CF0; diagnosticprefixflags_valid0.
 * ActualchildDXFFFF suppressesORDXDX afterpops; do nottestrestoredDX
 * forchildfailure. No capacity/caller/IRQ/core/realDOS/session admission. */
void td2ega_block_wrapper(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,uint32_t,uint32_t,uint32_t,td2ega_block_wrapper_result *);
#endif
