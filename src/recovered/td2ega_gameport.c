#include "td2ega_gameport.h"
#include <stddef.h>

static uint16_t read_word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void write_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static int32_t signed_word(uint16_t word)
{
    return word < UINT16_C(0x8000) ? (int32_t)word : (int32_t)word - INT32_C(65536);
}
static int transfer(td2ega_gameport_service service, void *context,
    uint16_t operation, uint16_t value, uint32_t max_reads,
    td2ega_gameport_result *r, uint8_t *read_value)
{
    td2ega_gameport_request request;
    if (service == NULL || (operation == 0 && r->reads >= max_reads)) return 0;
    request = (td2ega_gameport_request){operation, 0x201, value, r->interrupts_enabled};
    if (!service(context, &request, read_value)) return 0;
    if (operation == 0) ++r->reads;
    return 1;
}

/* Shared shape, retaining the original X signed / Y partly unsigned guards.
 * SUB/JLE uses original signed operands, including overflow, while following
 * DIV/SHR consume the wrapped difference as unsigned16bits.
 */
static void calibrate(uint8_t *g, uint16_t count, uint16_t base, int y,
                      uint16_t *bx)
{
    uint16_t minimum = read_word(g, base), maximum = read_word(g, (uint16_t)(base + 2));
    int new_minimum = y ? count < minimum : signed_word(count) < signed_word(minimum);
    int recalculate = 0, reset = 0;
    if (new_minimum) {
        minimum = count; write_word(g, base, minimum); recalculate = 1;
    } else if (signed_word(count) > signed_word(maximum)) {
        uint16_t remaining = (uint16_t)(read_word(g, (uint16_t)(base + 6)) - UINT16_C(1));
        write_word(g, (uint16_t)(base + 6), remaining);
        if (remaining == 0) {
            maximum = read_word(g, (uint16_t)(base + 4));
            *bx = maximum; write_word(g, (uint16_t)(base + 2), maximum); recalculate = 1;
        } else if (signed_word(count) < signed_word(read_word(g, (uint16_t)(base + 4)))) {
            write_word(g, (uint16_t)(base + 4), count);
        }
    } else reset = 1;
    if (recalculate) {
        uint16_t difference = (uint16_t)(maximum - minimum);
        uint16_t half, quarter, upper, lower;
        if (signed_word(maximum) > signed_word(minimum)) {
            uint16_t scale_at = y ? UINT16_C(0x629c) : UINT16_C(0x629a);
            write_word(g, scale_at, (uint16_t)(UINT16_C(0x4000) / difference));
        }
        half = (uint16_t)(difference >> 1); quarter = (uint16_t)(half >> 1);
        upper = (uint16_t)(half + minimum + quarter);
        lower = (uint16_t)(upper - quarter - quarter);
        write_word(g, (uint16_t)(base + 10), upper); write_word(g, (uint16_t)(base + 8), lower);
        *bx = quarter; reset = 1;
    }
    if (reset) {
        write_word(g, (uint16_t)(base + 6), UINT16_C(8));
        write_word(g, (uint16_t)(base + 4), UINT16_C(0x4e20));
    }
}

void td2ega_gameport_sample(uint8_t *g, uint32_t group_bytes,
    td2ega_gameport_service service, void *context, uint16_t incoming_bx,
    uint16_t incoming_cx, uint16_t incoming_dx, uint16_t initial_if,
    uint32_t max_reads, td2ega_gameport_result *r)
{
    uint8_t value, active;
    uint16_t x, y;
    if (r == NULL) return;
    *r = (td2ega_gameport_result){0}; r->status = 2;
    r->bx = incoming_bx; r->cx = incoming_cx; r->dx = incoming_dx;
    r->interrupts_enabled = initial_if != 0 ? 1 : 0;
    if (g == NULL || group_bytes < UINT32_C(65536)) return;
    if (g[UINT16_C(0x6cfc)] == 0 || (g[UINT16_C(0x6cfe)] & UINT8_C(1)) == 0) {
        r->status = 0; return;
    }
    g[UINT16_C(0x6281)] = 0; r->dx = UINT16_C(0x201);
    if (!transfer(service, context, 0, 0, max_reads, r, &value)) return;
    g[UINT16_C(0x6280)] = value;
    r->bx = (uint16_t)((r->bx & UINT16_C(0xff00)) | UINT16_C(3));
    write_word(g, UINT16_C(0x627c), UINT16_C(0x50));
    write_word(g, UINT16_C(0x627e), UINT16_C(0x50));
    r->cx = 0; r->interrupts_enabled = 0;
    if (!transfer(service, context, 1, value, max_reads, r, &value)) return;
    for (;;) {
        if (!transfer(service, context, 0, 0, max_reads, r, &value)) return;
        active = (uint8_t)((uint8_t)r->bx & (uint8_t)~value);
        if (active == 0) {
            r->cx = (uint16_t)(r->cx + UINT16_C(1));
            if (r->cx < UINT16_C(0xfa0)) continue;
            break;
        }
        if ((active & UINT8_C(1)) != 0) {
            write_word(g, UINT16_C(0x627c), r->cx);
            r->bx = (uint16_t)((r->bx & UINT16_C(0xff00)) | ((uint8_t)r->bx & UINT8_C(2)));
        }
        if ((active & UINT8_C(2)) != 0) {
            write_word(g, UINT16_C(0x627e), r->cx);
            r->bx = (uint16_t)((r->bx & UINT16_C(0xff00)) | ((uint8_t)r->bx & UINT8_C(1)));
        }
        if ((uint8_t)r->bx == 0) break;
    }
    r->interrupts_enabled = 1;
    x = read_word(g, UINT16_C(0x627c)); y = read_word(g, UINT16_C(0x627e));
    calibrate(g, x, UINT16_C(0x6282), 0, &r->bx);
    if (signed_word(x) < signed_word(read_word(g, UINT16_C(0x628a)))) g[UINT16_C(0x6281)] |= UINT8_C(8);
    else if (signed_word(x) >= signed_word(read_word(g, UINT16_C(0x628c)))) g[UINT16_C(0x6281)] |= UINT8_C(4);
    calibrate(g, y, UINT16_C(0x628e), 1, &r->bx);
    if (y < read_word(g, UINT16_C(0x6296))) g[UINT16_C(0x6281)] |= UINT8_C(1);
    else if (y >= read_word(g, UINT16_C(0x6298))) g[UINT16_C(0x6281)] |= UINT8_C(2);
    if (!transfer(service, context, 0, 0, max_reads, r, &value)) return;
    g[UINT16_C(0x6281)] |= (uint8_t)(((value & g[UINT16_C(0x6280)]) & UINT8_C(0x30)) ^ UINT8_C(0x30));
    r->ax = g[UINT16_C(0x6281)]; r->status = 0;
}

void td2ega_gameport_initialize(uint8_t *g)
{
    g[UINT16_C(0x6cfc)] = 1;
    write_word(g, UINT16_C(0x6282), UINT16_C(0x50));
    write_word(g, UINT16_C(0x6284), 0);
    write_word(g, UINT16_C(0x628e), UINT16_C(0x50));
    write_word(g, UINT16_C(0x6290), 0);
}
uint16_t td2ega_gameport_translate(const uint8_t *g, uint16_t input)
{
    return g[UINT16_C(0x629e) + (input & UINT16_C(0xf))];
}
