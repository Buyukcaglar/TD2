#ifndef TD2EGA_SEEK_PARENT_H
#define TD2EGA_SEEK_PARENT_H
#include "td2ega_seek_handle.h"
typedef struct td2ega_seek_parent_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,services,error_calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_seek_parent_result;
/* Actual13A8:2AD8/oneSSword with oneorthree actualfar225E calls.
 * SP48..FFE0 preserves frozenchild24 aftersaves/locals/pool/farframe.
 * LiteralSS pools/locals/returnedBP/rereads/cleanup/savedSI/farRET4.
 * Native0rootRET/1rawchildRET/2invalid/3beforeCALL-or-childINT/4adapterfail.
 * Actualcaller/handlewriters/lifetime/IRQ/core/DOS/resource gates separate. */
void td2ega_seek_parent(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,uint32_t,td2ega_seek_parent_result *);
#endif
