#ifndef TD2EGA_DISCARD_WRAPPERS_H
#define TD2EGA_DISCARD_WRAPPERS_H
#include "td2ega_discard_object.h"
/* entry0=0083 reads currentDS09B2/4, entry1=38D4 reads2F60/2 then2F68/A.
 * Far/noargs; actual782C/7490/SSargs-frames/globalCALL-scanbudgets.
 * Entry1 retainsfirstfourargbytesduringsecondCALL thenADDSP8.
 * Statuscodes match discard_object; native1rawactualchildRETneverfollowed.
 * No caller/writer/lifetime/exclusion/CPU/fatalcleanup/core/session gate. */
void td2ega_discard_wrappers(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,uint32_t,
    td2ega_discard_object_result *);
#endif
