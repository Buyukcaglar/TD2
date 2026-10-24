#ifndef TD2EGA_DELETE_FILE_H
#define TD2EGA_DELETE_FILE_H
#include "td2ega_small_platform.h"
typedef struct td2ega_delete_file_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t services,error_calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_delete_file_result;
/*13A8:2E20, one SSnearfilename/currentDS, syntheticDOS41 service then
 * actualnear094A error mapper and shared0924/0939 tails. SuccessAX0/CF0,
 * failureAXFFFF/DXFFFF/mapperCF. MOVSP,returnedBP/actualSS saved/root words.
 * Native0rootfarreturn/1rawchildnearreturn/2invalid/3beforeINT/4adapterfailure.
 * NoactualDOS/file/session/core acceptance; caller/lifetime/FLAGS separate. */
void td2ega_delete_file(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,td2ega_delete_file_result *);
#endif
