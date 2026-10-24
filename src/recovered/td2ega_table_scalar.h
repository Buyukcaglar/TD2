#ifndef TD2EGA_TABLE_SCALAR_H
#define TD2EGA_TABLE_SCALAR_H
#include "td2ega_state_loop.h"
typedef struct td2ega_table_scalar_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t bus_writes;
    td2ega_state_registers returned;
} td2ega_table_scalar_result;
/*0=13A8:094A raw error-byte mapping/near RET;1=13A8:2D57 six CS bytes,
 *2=13A3:0012 signed AL/table/far RET;3=06C9:5334 threshold update/near RET;
 *4=06C9:535B signed field selection/near RET. External table words/bytes,
 * raw CF/SS saved/return words retained. Native0returnoperation/2invalid.
 * Actual caller/tablebounds/writers/FLAGS/lifetime/core gates separate. */
void td2ega_table_scalar(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_table_scalar_result *);
#endif
