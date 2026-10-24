#include "td2ega_run_stage.h"
#include "td2ega_paragraph_copy.h"

typedef struct BytePointer {
    uint16_t segment;
    uint16_t offset;
} BytePointer;
typedef struct Pool {
    uint8_t *bytes;
    uint32_t length;
    uint32_t base;
    uint32_t work;
    enum TD2EgaRunStageStatus status;
} Pool;

static int charge(Pool *pool, uint32_t work)
{
    if (pool->status != TD2EGA_RUN_STAGE_OK) {
        return 0;
    }
    if (work > pool->work) {
        pool->status = TD2EGA_RUN_STAGE_WORK_LIMIT;
        return 0;
    }
    pool->work -= work;
    return 1;
}
static int index_of(Pool *pool, BytePointer pointer, uint32_t *index)
{
    uint32_t address = (uint32_t)pointer.segment * UINT32_C(16) + pointer.offset;
    if (address < pool->base || address - pool->base >= pool->length) {
        pool->status = TD2EGA_RUN_STAGE_OUT_OF_POOL;
        return 0;
    }
    *index = address - pool->base;
    return 1;
}
static uint8_t read_byte(Pool *pool, BytePointer *pointer)
{
    uint32_t index;
    uint8_t value = UINT8_C(0);
    if (charge(pool, UINT32_C(1)) && index_of(pool, *pointer, &index)) {
        value = pool->bytes[index];
        pointer->offset = (uint16_t)(pointer->offset + UINT16_C(1));
    }
    return value;
}
static void write_byte(Pool *pool, BytePointer *pointer, uint8_t value,
                       uint32_t *writes)
{
    uint32_t index;
    if (charge(pool, UINT32_C(1)) && index_of(pool, *pointer, &index)) {
        pool->bytes[index] = value;
        pointer->offset = (uint16_t)(pointer->offset + UINT16_C(1));
        ++*writes;
    }
}
static void normalize(BytePointer *pointer)
{
    if (pointer->offset > UINT16_C(0x8000)) {
        pointer->offset = (uint16_t)(pointer->offset - UINT16_C(0x8000));
        pointer->segment = (uint16_t)(pointer->segment + UINT16_C(0x0800));
    }
}
/* Return true when the original literal counter branches to its end. */
static int literal_done(uint16_t *low, uint16_t *high)
{
    *low = (uint16_t)(*low - UINT16_C(1));
    if (*low != UINT16_C(0)) {
        return 0;
    }
    if (*high == UINT16_C(0)) {
        return 1;
    }
    *high = (uint16_t)(*high - UINT16_C(1));
    return 0;
}
static int token_done(uint16_t *low, uint16_t *high, uint16_t bytes)
{
    uint16_t borrow = *low < bytes ? UINT16_C(1) : UINT16_C(0);
    *low = (uint16_t)(*low - bytes);
    *high = (uint16_t)(*high - borrow);
    return (*low | *high) == UINT16_C(0);
}

/* Original6C6E: marker-delimited block repetition before the run stage.
 * Inner-block and repeated-copy offsets wrap without outer normalization.
 * Repeat0/1 deliberately retain the original do/while byte-counter effects.
 */
static uint32_t block_stage(Pool *pool, BytePointer source,
    BytePointer *destination, uint32_t encoded, uint8_t marker, uint32_t *writes)
{
    uint16_t low = (uint16_t)encoded;
    uint16_t high = (uint16_t)(encoded >> 16);
    uint16_t initial_destination = destination->segment;
    while (pool->status == TD2EGA_RUN_STAGE_OK) {
        uint8_t value;
        normalize(&source);
        normalize(destination);
        value = read_byte(pool, &source);
        if (pool->status != TD2EGA_RUN_STAGE_OK) {
            break;
        }
        if (value != marker) {
            write_byte(pool, destination, value, writes);
            if (literal_done(&low, &high)) {
                break;
            }
        } else {
            uint16_t start = destination->offset;
            uint16_t count;
            uint8_t repeat;
            do {
                value = read_byte(pool, &source);
                if (pool->status != TD2EGA_RUN_STAGE_OK) {
                    break;
                }
                if (value != marker) {
                    write_byte(pool, destination, value, writes);
                    low = (uint16_t)(low - UINT16_C(1));
                    if (low == UINT16_C(0)) {
                        high = (uint16_t)(high - UINT16_C(1));
                    }
                }
            } while (value != marker && pool->status == TD2EGA_RUN_STAGE_OK);
            if (pool->status != TD2EGA_RUN_STAGE_OK) {
                break;
            }
            repeat = (uint8_t)(read_byte(pool, &source) - UINT8_C(1));
            count = (uint16_t)(destination->offset - start);
            do {
                BytePointer from;
                uint16_t byte;
                from.segment = destination->segment;
                from.offset = start;
                for (byte = UINT16_C(0); byte < count; ++byte) {
                    value = read_byte(pool, &from);
                    write_byte(pool, destination, value, writes);
                    if (pool->status != TD2EGA_RUN_STAGE_OK) {
                        break;
                    }
                }
                repeat = (uint8_t)(repeat - UINT8_C(1));
            } while (repeat != UINT8_C(0) && pool->status == TD2EGA_RUN_STAGE_OK);
            if (token_done(&low, &high, UINT16_C(3))) {
                break;
            }
        }
    }
    return (uint32_t)(uint16_t)(destination->segment - initial_destination) *
           UINT32_C(16) + destination->offset;
}

/* Provenance: admitted TD2EGA06C9:[6B02,6D18). No original media tables. */
enum TD2EgaRunStageStatus td2ega_run_stage(uint8_t *bytes, uint32_t pool_bytes,
    uint16_t origin, uint16_t source_offset, uint16_t source_segment,
    uint16_t destination_segment, uint16_t allocation_paragraphs,
    uint32_t work_limit, TD2EgaRunStageResult *result)
{
    Pool pool;
    BytePointer source;
    BytePointer destination;
    uint8_t header[16];
    uint8_t ranks[256] = {0};
    uint8_t control;
    uint16_t markers;
    uint16_t index;
    uint32_t encoded;
    uint8_t declared_high;
    uint16_t low;
    uint16_t high;
    result->offset = UINT16_C(0);
    result->segment = destination_segment;
    result->source_argument_offset = source_offset;
    result->source_argument_segment = source_segment;
    result->first_stage_reported_bytes = UINT32_C(0);
    result->first_stage_writes = UINT32_C(0);
    result->final_stage_writes = UINT32_C(0);
    pool.bytes = bytes;
    pool.length = pool_bytes;
    pool.base = (uint32_t)origin * UINT32_C(16);
    pool.work = work_limit;
    pool.status = TD2EGA_RUN_STAGE_OK;
    if (pool_bytes > UINT32_C(0x100000) - pool.base || source_offset > UINT16_C(0xffec)) {
        return TD2EGA_RUN_STAGE_INVALID_PROFILE;
    }
    source.segment = source_segment;
    source.offset = (uint16_t)(source_offset + UINT16_C(3));
    declared_high = read_byte(&pool, &source);
    source.offset = (uint16_t)(source_offset + UINT16_C(4));
    for (index = UINT16_C(0); index < UINT16_C(16); ++index) {
        header[index] = read_byte(&pool, &source);
    }
    if (pool.status != TD2EGA_RUN_STAGE_OK) {
        return pool.status;
    }
    encoded = (uint32_t)header[0] | ((uint32_t)header[1] << 8) |
              ((uint32_t)header[2] << 16) | ((uint32_t)header[3] << 24);
    control = header[4];
    markers = (uint16_t)(control & UINT8_C(0x7f));
    if (markers == UINT16_C(0) || markers > UINT16_C(11)) {
        return TD2EGA_RUN_STAGE_INVALID_PROFILE;
    }
    source.offset = (uint16_t)(source_offset + UINT16_C(9) + markers);
    result->source_argument_offset = source.offset;
    if (control <= UINT8_C(0x80)) {
        uint32_t produced;
        uint16_t paragraphs;
        uint16_t moved_segment;
        destination.segment = destination_segment;
        destination.offset = UINT16_C(0);
        produced = control == UINT8_C(1) ?
            UINT32_C(0x10000) | declared_high :
            block_stage(&pool, source, &destination, encoded, header[6],
                        &result->first_stage_writes);
        result->first_stage_reported_bytes = produced;
        if (pool.status != TD2EGA_RUN_STAGE_OK) {
            return pool.status;
        }
        paragraphs = (uint16_t)((produced >> 4) +
                                ((produced & UINT32_C(15)) != UINT32_C(0) ? UINT32_C(1) : UINT32_C(0)));
        moved_segment = (uint16_t)(destination_segment + allocation_paragraphs - paragraphs);
        if (!charge(&pool, (uint32_t)paragraphs * UINT32_C(32))) {
            return pool.status;
        }
        if (!td2ega_paragraph_copy_backward(bytes, pool_bytes, origin,
                                            destination_segment, moved_segment, paragraphs)) {
            return TD2EGA_RUN_STAGE_OUT_OF_POOL;
        }
        source.segment = moved_segment;
        source.offset = UINT16_C(0);
        result->source_argument_segment = moved_segment;
        result->source_argument_offset = UINT16_C(0);
        encoded = produced;
    }
    for (index = UINT16_C(0); index < markers; ++index) {
        ranks[header[UINT16_C(5) + index]] = (uint8_t)(index + UINT16_C(1));
    }
    destination.segment = destination_segment;
    destination.offset = UINT16_C(0);
    low = (uint16_t)encoded;
    high = (uint16_t)(encoded >> 16);
    while (pool.status == TD2EGA_RUN_STAGE_OK) {
        uint8_t value;
        uint8_t rank;
        uint16_t repeat;
        uint16_t consumed;
        normalize(&source);
        normalize(&destination);
        value = read_byte(&pool, &source);
        if (pool.status != TD2EGA_RUN_STAGE_OK) {
            break;
        }
        rank = ranks[value];
        if (rank == UINT8_C(0)) {
            write_byte(&pool, &destination, value, &result->final_stage_writes);
            if (literal_done(&low, &high)) {
                break;
            }
            continue;
        }
        if (rank == UINT8_C(1)) {
            repeat = read_byte(&pool, &source);
            consumed = UINT16_C(3);
        } else if (rank == UINT8_C(3)) {
            uint16_t first = read_byte(&pool, &source);
            repeat = (uint16_t)(first | ((uint16_t)read_byte(&pool, &source) << 8));
            consumed = UINT16_C(4);
        } else {
            repeat = (uint16_t)(rank - UINT8_C(1));
            consumed = UINT16_C(2);
        }
        value = read_byte(&pool, &source);
        for (index = UINT16_C(0); index < repeat; ++index) {
            write_byte(&pool, &destination, value, &result->final_stage_writes);
            if (pool.status != TD2EGA_RUN_STAGE_OK) {
                break;
            }
        }
        if (token_done(&low, &high, consumed)) {
            break;
        }
    }
    return pool.status;
}
