#ifndef TD2EGA_BIOS_BLOCK_H
#define TD2EGA_BIOS_BLOCK_H
#include "td2ega_state_loop.h"
typedef struct td2ega_bios_block_request {
    uint16_t site, interrupt_number, stack_segment, stack_sp, saved_flags;
    td2ega_state_registers incoming;
} td2ega_bios_block_request;
typedef int (*td2ega_bios_block_service)(void *context,uint8_t *memory,
    const td2ega_bios_block_request *request,td2ega_state_registers *returned);
typedef struct td2ega_bios_block_result {
    uint16_t status,current_sp;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_bios_block_result;
/* ABFA: ES=incomingDS, AX1002, DX=near SS callerargument, INT10, restoreBP,
 * plainRETF. Exact raw BIOS request; block extent/meaning/device separate.
 * Service incomingIF0, savedCFIFDF explicit; returned initializedpreINT.
 * Serialized1MiBbus, native virtualframes/code/data/control separation. */
void td2ega_bios_block(uint8_t *memory,uint32_t memory_bytes,
    uint16_t stack_segment,uint16_t entry_sp,
    const td2ega_state_registers *incoming,td2ega_bios_block_service service,
    void *context,uint32_t max_calls,td2ega_bios_block_result *result);
#endif
