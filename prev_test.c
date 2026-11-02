/* chunk_inspect.c */
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>

/* ============================================================
 *  CONFIG  — edit these freely
 * ============================================================ */

static unsigned char  FILL_BYTE              = 0xAA;
static size_t         DISPLAY_MAX_BYTES      = 64;   /* 0 = show all */
static int            FREE_AT_END            = 1;
static int            DUMP_AFTER_FREE        = 0;

static size_t REQUESTED_BYTES[] = {
    1, 8, 16, 17, 24, 25, 32, 33, 64, 100, 1000
};

/* ============================================================
 *  RUNTIME STATE
 * ============================================================ */

#define MAX_NUMBER_OF_ALLOCATIONS 64

static int     NUMBER_OF_ALLOCATIONS;
static void   *USER_POINTERS   [MAX_NUMBER_OF_ALLOCATIONS];
static size_t  REQUESTED_SIZES [MAX_NUMBER_OF_ALLOCATIONS];

/* ============================================================
 *  CHUNK ACCESSORS  (matches glibc names)
 * ============================================================ */

static uint64_t raw_size_field(void *user_ptr) {
    return *(uint64_t*)((char*)user_ptr - 8);
}
static uint64_t prev_size(void *user_ptr) {
    return *(uint64_t*)((char*)user_ptr - 16);
}
static uint64_t chunksize(void *user_ptr) {
    return raw_size_field(user_ptr) & ~0xfULL;
}
static uint64_t prev_inuse(void *user_ptr) {
    return raw_size_field(user_ptr) & 1;
}

/* ============================================================
 *  DISPLAY
 * ============================================================ */

static void print_byte_row(uint64_t address, uint64_t value, const char *label)
{
    printf("  0x%08lx |", address);
    for (int byte_index = 0; byte_index < 8; byte_index++)
        printf(" %02x", (unsigned)((value >> (8 * byte_index)) & 0xff));
    printf(" | 0x%016lx", value);
    if (label && label[0])
        printf("   %s", label);
    printf("\n");
}

static void dump_one_chunk(int index)
{
    void    *user_ptr        = USER_POINTERS[index];
    size_t   requested_bytes = REQUESTED_SIZES[index];
    uint64_t chunk_bytes     = chunksize(user_ptr);
    uint64_t in_chunk_bytes  = chunk_bytes - 16;
    uint64_t spill_bytes     = (requested_bytes > in_chunk_bytes)
                               ? (requested_bytes - in_chunk_bytes)
                               : 0;

    uint64_t chunk_start_address = (uint64_t)user_ptr - 16;
    uint64_t user_start_address  = (uint64_t)user_ptr;

    printf("\n");
    printf("======================================================================\n");
    printf(" Chunk %2d\n", index);
    printf("   requested_bytes  = %5zu\n", requested_bytes);
    printf("   chunk_bytes      = %5lu   (glibc calls this nb)\n", chunk_bytes);
    printf("   in_chunk_bytes   = %5lu\n", in_chunk_bytes);
    printf("   spill_bytes      = %5lu\n", spill_bytes);
    printf("   prev_inuse (P)   = %5lu\n", prev_inuse(user_ptr));
    printf("======================================================================\n");

    char label[96];

    snprintf(label, sizeof(label), "prev_size = 0x%lx", prev_size(user_ptr));
    print_byte_row(chunk_start_address, prev_size(user_ptr), label);

    snprintf(label, sizeof(label),
             "size = 0x%lx  (chunk_bytes=%lu, P=%lu)",
             raw_size_field(user_ptr), chunk_bytes, prev_inuse(user_ptr));
    print_byte_row(chunk_start_address + 8, raw_size_field(user_ptr), label);

    uint64_t show_bytes = in_chunk_bytes;
    int truncated = 0;
    if (DISPLAY_MAX_BYTES > 0 && show_bytes > DISPLAY_MAX_BYTES) {
        show_bytes = (DISPLAY_MAX_BYTES / 8) * 8;
        if (show_bytes == 0) show_bytes = 8;
        truncated = 1;
    }

    for (uint64_t offset = 0; offset < show_bytes; offset += 8) {
        const char *row_label = (offset == 0) ? "<-- user_ptr" : NULL;
        print_byte_row(user_start_address + offset,
                       *(uint64_t*)(user_start_address + offset),
                       row_label);
    }

    if (truncated) {
        printf("  ...\n");
        printf("  ... (%lu more bytes of user data) ...\n",
               in_chunk_bytes - show_bytes);
        printf("  ...\n");
        uint64_t last_row_offset = in_chunk_bytes - 8;
        print_byte_row(user_start_address + last_row_offset,
                       *(uint64_t*)(user_start_address + last_row_offset),
                       "<-- last in-chunk row");
    }

    if (spill_bytes > 0) {
        if (spill_bytes > 8)
            printf("  WARNING: spill_bytes > 8  "
                   "(wrote past prev_size into size field!)\n");
        print_byte_row(user_start_address + in_chunk_bytes,
                       *(uint64_t*)(user_start_address + in_chunk_bytes),
                       "<-- SPILL into next chunk's prev_size");
    }

    printf("  next chunk starts at 0x%lx\n",
           user_start_address + in_chunk_bytes);
}

static void dump_all_chunks(void)
{
    for (int index = 0; index < NUMBER_OF_ALLOCATIONS; index++)
        dump_one_chunk(index);
}

/* ============================================================
 *  MAIN
 * ============================================================ */

int main(void)
{
    NUMBER_OF_ALLOCATIONS =
        (int)(sizeof(REQUESTED_BYTES) / sizeof(REQUESTED_BYTES[0]));
    if (NUMBER_OF_ALLOCATIONS > MAX_NUMBER_OF_ALLOCATIONS) {
        fprintf(stderr,
                "REQUESTED_BYTES has too many entries; truncating to %d\n",
                MAX_NUMBER_OF_ALLOCATIONS);
        NUMBER_OF_ALLOCATIONS = MAX_NUMBER_OF_ALLOCATIONS;
    }

    printf("\n");
    printf("======================================================================\n");
    printf(" CONFIGURATION\n");
    printf("======================================================================\n");
    printf("   FILL_BYTE                = 0x%02x\n", FILL_BYTE);
    printf("   NUMBER_OF_ALLOCATIONS    = %d\n", NUMBER_OF_ALLOCATIONS);
    printf("   DISPLAY_MAX_BYTES        = %zu\n", DISPLAY_MAX_BYTES);
    printf("======================================================================\n");
    printf("\n");

    printf("--- ALLOCATIONS ------------------------------------------------------\n");
    for (int index = 0; index < NUMBER_OF_ALLOCATIONS; index++) {
        USER_POINTERS[index]   = malloc(REQUESTED_BYTES[index]);
        REQUESTED_SIZES[index] = REQUESTED_BYTES[index];
        if (!USER_POINTERS[index]) {
            fprintf(stderr, "malloc(%zu) failed at index=%d\n",
                    REQUESTED_BYTES[index], index);
            NUMBER_OF_ALLOCATIONS = index;
            break;
        }
        memset(USER_POINTERS[index], FILL_BYTE, REQUESTED_BYTES[index]);

        printf("  malloc(%5zu) = %p   usable = %5zu\n",
               REQUESTED_SIZES[index],
               USER_POINTERS[index],
               malloc_usable_size(USER_POINTERS[index]));
    }
    printf("\n");

    printf("--- CHUNK DIAGRAMS ---------------------------------------------------\n");
    dump_all_chunks();

    if (FREE_AT_END) {
        printf("\n--- FREEING ALL CHUNKS -----------------------------------------------\n");
        for (int index = 0; index < NUMBER_OF_ALLOCATIONS; index++)
            free(USER_POINTERS[index]);

        if (DUMP_AFTER_FREE) {
            printf("\n--- CHUNK DIAGRAMS AFTER FREE ----------------------------------------\n");
            dump_all_chunks();
        }
    }

    return 0;
}
